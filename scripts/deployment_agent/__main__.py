"""python -m scripts.deployment_agent — credentials only from protected environment/mounts."""

import hashlib
import os
import signal
import ssl
import threading
import time
from typing import Any

import httpx

from app.domains.deployments.artifacts import write_oci_archive
from app.domains.deployments.contracts import SAFETY, Delivery, RuntimeReport
from app.domains.module_gateway.contracts import read_contract
from app.domains.module_sdk.contracts import SDKContract
from app.domains.packages.archive import verify
from app.domains.packages.codec import PackageError
from app.domains.packages.schema import TrustStore
from scripts.deployment_agent.engine import Engine, EngineFailure
from scripts.deployment_agent.protocol import Config, Protocol, ProtocolFailure, Rejected
from scripts.deployment_agent.state import State
from scripts.module_agent import backoff


class DeploymentAgent:
    def __init__(self, protocol: Protocol, engine: Engine, state: State):
        self.protocol, self.engine, self.state = protocol, engine, state
        self.engine.storage_root = state.root

    def authorize(self, job: Delivery) -> None:
        self.protocol.request("/jobs/" + str(job.id) + "/authorize", {"fence": str(job.fence)})

    def artifact(self, job: Delivery) -> Any:
        try:
            return self.download(job)
        except httpx.HTTPError:
            raise ProtocolFailure("deployment_artifact_transport_failed") from None

    def download(self, job: Delivery) -> Any:
        # Two bounded staging files, one serial worker. Nothing is executable before full verification.
        self.state.clear_staging(job.installation_id)
        cache = self.state.workspace(job.installation_id) / "cache"
        package, archive = cache / "package.xpkg", cache / "image.tar"
        self.authorize(job)
        deadline = time.monotonic() + 90
        with self.protocol.client.stream(
            "GET",
            self.protocol.endpoint("/jobs/" + str(job.id) + "/artifact"),
            params={"fence": str(job.fence)},
            headers={"Authorization": "Bearer " + self.protocol.token()},
        ) as response:
            if response.status_code != 200 or response.headers.get("X-Artifact-SHA256") != job.package_sha256:
                raise PackageError("deployment_artifact_denied")
            digest, total = hashlib.sha256(), 0
            fd = os.open(package, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as stream:
                for chunk in response.iter_bytes(65536):
                    if time.monotonic() > deadline:
                        raise ProtocolFailure("deployment_artifact_deadline")
                    total += len(chunk)
                    if total > job.package_size:
                        raise PackageError("deployment_artifact_size")
                    digest.update(chunk)
                    stream.write(chunk)
                stream.flush()
                os.fsync(stream.fileno())
        if total != job.package_size or digest.hexdigest() != job.package_sha256:
            raise PackageError("deployment_artifact_digest")
        checked = verify(package, TrustStore.model_validate(job.trust))
        if checked.package_sha256 != job.package_sha256 or not checked.core_compatible:
            raise PackageError("deployment_artifact_untrusted")
        contract = write_oci_archive(package, checked.manifest, archive)
        if contract != job.runtime:
            raise PackageError("deployment_runtime_binding_changed")
        api = read_contract(package, checked.manifest)
        if job.profile in {"module-api-private-v1", "module-api-stateful-v1"} and (
            api is None or api != job.api_contract
        ):
            raise PackageError("deployment_api_binding_changed")
        if job.profile == "module-api-stateful-v1":
            sdk = (
                SDKContract.model_validate(checked.sdk_contract) if checked.sdk_contract is not None else None
            )
            if (
                sdk is None
                or sdk.storage is None
                or job.storage is None
                or sdk.digest() != job.storage.sdk_sha256
                or sdk.module_id != job.storage.module_id
                or sdk.package_version != job.storage.package_version
                or sdk.storage.data_schema_version != job.storage.target_schema_version
                or sdk.storage.compatible_minimum != job.storage.compatible_minimum
                or sdk.storage.compatible_maximum != job.storage.compatible_maximum
            ):
                raise PackageError("deployment_storage_binding_changed")
        return archive

    def execute(self, job: Delivery) -> None:
        if job.host_id != self.protocol.config.host_id or job.engine_id != self.protocol.config.engine_id:
            raise ProtocolFailure("deployment_job_identity_conflict")
        old = self.state.accept(job)
        if old is not None:
            old["fence"] = str(job.fence)
            self.protocol.request("/jobs/" + str(job.id) + "/ack", old)
            return
        try:
            artifact = (
                self.artifact(job) if job.operation not in SAFETY and job.operation != "restart" else None
            )
            report = self.engine.apply(job, lambda: self.authorize(job), artifact)
            receipt = {"fence": str(job.fence), "success": True, "report": report.model_dump(mode="json")}
        except (EngineFailure, PackageError) as error:
            code = (
                "artifact_invalid"
                if isinstance(error, PackageError)
                else str(error)
                if str(error) in {"isolation_unavailable", "health_failed", "runtime_missing"}
                else "deployment_failed"
            )
            report = RuntimeReport(
                installation_id=job.installation_id,
                generation=job.generation,
                image_digest=job.runtime.image_digest,
                state="failed",
                health="unknown",
                safe_error_code=code,
            )
            receipt = {"fence": str(job.fence), "success": False, "report": report.model_dump(mode="json")}
        self.state.completed(job, receipt)
        self.state.clear_staging(job.installation_id)
        self.protocol.request("/jobs/" + str(job.id) + "/ack", receipt)

    def cycle(self) -> None:
        reports = []
        for job in self.state.jobs():
            try:
                reports.append(self.engine.report(job).model_dump(mode="json"))
            except EngineFailure:
                reports.append(
                    RuntimeReport(
                        installation_id=job.installation_id,
                        generation=job.generation,
                        image_digest=job.runtime.image_digest,
                        state="unknown",
                        health="unknown",
                        safe_error_code="engine_unavailable",
                    ).model_dump(mode="json")
                )
        value = self.protocol.request("/check-in", {"sequence": self.state.sequence(), "reports": reports})
        jobs = value.get("jobs")
        if not isinstance(jobs, list) or len(jobs) > 1:
            raise ProtocolFailure("deployment_delivery_limit")
        for item in jobs:
            self.execute(Delivery.model_validate(item))


def main() -> None:
    stop = threading.Event()
    for number in (signal.SIGINT, signal.SIGTERM):
        signal.signal(number, lambda *args: stop.set())
    try:
        config = Config()
        state = State(config.storage_root)
        engine = Engine(config.engine_socket, config.engine_id)
        try:
            with httpx.Client(
                verify=ssl.create_default_context(), timeout=30, follow_redirects=False, trust_env=False
            ) as client:
                agent = DeploymentAgent(Protocol(config, client), engine, state)
                failures = 0
                while not stop.is_set():
                    try:
                        agent.cycle()
                        failures = 0
                    except Rejected:
                        # Authentication failure does not authorize deletion or a new deployment.
                        for job in state.jobs():
                            try:
                                for row in engine.owned(job):
                                    engine.stop(row["Id"])
                            except EngineFailure:
                                pass
                        failures += 1
                    except (ProtocolFailure, EngineFailure, OSError, ValueError):
                        failures += 1
                    stop.wait(backoff(failures) if failures else 2)
        finally:
            engine.close()
            state.close()
    except (OSError, ValueError, EngineFailure):
        raise SystemExit("Deployment Agent configuration or local state unavailable") from None


if __name__ == "__main__":
    main()
