"""Narrow Docker API adapter for ONE dedicated, pinned rootless daemon. No shell interface."""

import hashlib
import json
import os
import sqlite3
import stat
import tarfile
import time
from collections.abc import Callable, Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import UUID

import httpx
from xarionix_sdk.storage import StorageError

from app.domains.deployments.contracts import PROFILES, Delivery, RuntimeReport, StorageReport
from app.domains.module_gateway.contracts import Dispatch, json_bytes
from scripts.deployment_agent.ipc import BRIDGE, exchange
from scripts.deployment_agent.storage import (
    CONFIG_ENV,
    CONFIG_LABEL,
    StorageController,
    configuration_text,
    validate_configuration,
    volume_name,
)


class EngineFailure(Exception):
    pass


# Fixed private in-container mount, never a host temporary pathname.
TMP_PATH = "/tmp"  # nosec B108
ISOLATION_PROBE = """import json,os,pathlib
s=dict(line.split(':',1) for line in pathlib.Path('/proc/self/status').read_text().splitlines() if ':' in line)
p=pathlib.Path('/sys/fs/cgroup')
print(json.dumps({'uid':os.getuid(),'caps':s['CapEff'].strip(),'nnp':s['NoNewPrivs'].strip(),'seccomp':s['Seccomp'].strip(),
'memory':(p/'memory.max').read_text().strip(),'swap':(p/'memory.swap.max').read_text().strip(),'pids':(p/'pids.max').read_text().strip(),'cpu':(p/'cpu.max').read_text().strip()}))
"""
HEALTH_PROBE = """import http.client
for path in ('live','ready'):
 c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2)
 c.request('GET','/health/'+path)
 r=c.getresponse()
 assert r.status==200
 r.read(4096)
 c.close()
"""
API_ISOLATION_PROBE = """import pathlib,os,json
interfaces=[line.split(':')[0].strip() for line in pathlib.Path('/proc/net/dev').read_text().splitlines()[2:]]
print(json.dumps({'interfaces':interfaces,'engine':any(os.path.exists(p) for p in ('/var/run/docker.sock','/run/docker.sock'))}))
"""


STORAGE_PROBE = """import http.client,json,os,stat
assert not os.path.islink('/data/storage') and os.path.realpath('/data/storage')=='/data/storage'
s=os.stat('/data/storage')
assert s.st_uid==10001 and stat.S_IMODE(s.st_mode)==0o700
c=http.client.HTTPConnection('127.0.0.1',8080,timeout=2)
c.request('GET','/_xarionix/storage/v1')
r=c.getresponse()
assert r.status==200
raw=r.read(4097)
assert len(raw)<=4096
print(json.dumps(json.loads(raw)))
c.close()
"""


class Engine:
    storage_root: Path | None = None

    def __init__(self, socket: Path, expected_id: str):
        if (
            not socket.is_absolute()
            or socket.is_symlink()
            or socket.resolve() != socket
            or str(socket) in {"/var/run/docker.sock", "/run/docker.sock"}
            or not stat.S_ISSOCK(socket.stat().st_mode)
            or socket.stat().st_uid != os.geteuid()
        ):
            raise EngineFailure("engine_endpoint_denied")
        self.client = httpx.Client(
            transport=httpx.HTTPTransport(uds=str(socket)),
            base_url="http://deployment-engine/v1.52",
            timeout=120,
            trust_env=False,
            follow_redirects=False,
        )
        self.expected_id = expected_id
        self.socket = socket
        self.storage_root: Path | None = None

    def close(self) -> None:
        self.client.close()

    def business(self, job: Delivery, frame: Dispatch) -> dict[str, Any]:
        """Only an independently verified, locally acknowledged signed runtime is callable."""
        contract = job.api_contract
        context = frame.context
        op = (
            next((o for o in contract.operations if o.id == context.operation_id), None) if contract else None
        )
        seconds = (context.deadline - datetime.now(UTC)).total_seconds()
        if (
            job.profile not in {"module-api-private-v1", "module-api-stateful-v1"}
            or not contract
            or not op
            or context.installation_id != job.installation_id
            or context.deployment_generation != job.generation
            or frame.package_sha256 != job.package_sha256
            or frame.contract_sha256 != contract.digest()
            or frame.image_digest != job.runtime.image_digest
            or context.permission != op.permission
            or frame.response_max_bytes > op.response.max_bytes
            or not 0 < seconds <= 15
        ):
            raise EngineFailure("runtime_binding_changed")
        json_bytes(frame.body, limit=min(65536, op.request.max_bytes), depth=frame.json_depth)
        if job.profile == "module-api-stateful-v1" and (
            job.storage is None or context.installation_generation != job.installation_generation
        ):
            raise EngineFailure("runtime_binding_changed")
        matches = [
            r
            for r in self.owned(job)
            if r.get("Labels", {}).get("io.xarionix.deployment.image") == frame.image_digest
        ]
        if job.profile == "module-api-stateful-v1":
            matches = [
                row
                for row in matches
                if (self.inspect(row["Id"]) or {}).get("State", {}).get("Running") is True
            ]
        if len(matches) != 1:
            raise EngineFailure("runtime_binding_changed")
        identifier = matches[0]["Id"]
        info = self.inspect(identifier)
        if not info or not info.get("State", {}).get("Running"):
            raise EngineFailure("module_unavailable")
        self.constraints(info, job)
        if (
            job.profile == "module-api-stateful-v1"
            and validate_configuration(info, self.image(job), job).installation_generation
            != context.installation_generation
        ):
            raise EngineFailure("runtime_binding_changed")
        value = self.call(
            "POST",
            "/containers/" + identifier + "/exec",
            json={
                "AttachStdout": True,
                "AttachStderr": True,
                "AttachStdin": True,
                "Tty": False,
                "User": "10001:10001",
                "Privileged": False,
                "Cmd": ["/usr/local/bin/python", "-I", "-c", BRIDGE],
            },
        )
        if not isinstance(value, dict) or not isinstance(value.get("Id"), str):
            raise EngineFailure("module_unavailable")
        try:
            response = exchange(
                self.socket, value["Id"], frame.model_dump_json().encode(), seconds, frame.response_max_bytes
            )
            status = self.call("GET", "/exec/" + value["Id"] + "/json")
            if not status or status.get("Running") is not False or status.get("ExitCode") != 0:
                raise EngineFailure("module_response_invalid")
            if "body" in response:
                json_bytes(response["body"], limit=frame.response_max_bytes, depth=frame.json_depth)
                if not isinstance(response["body"], dict):
                    raise ValueError("module_json_object_required")
                return {"body": response["body"]}
            raise EngineFailure("module_response_invalid")
        except (OSError, TimeoutError):
            raise EngineFailure("module_timeout") from None
        except (ValueError, TypeError, RecursionError):
            raise EngineFailure("module_response_invalid") from None

    def call(self, method: str, path: str, **kwargs: Any) -> Any:
        try:
            with self.client.stream(method, path, **kwargs) as response:
                data = bytearray()
                for chunk in response.iter_bytes(16384):
                    if len(data) + len(chunk) > 524288:
                        raise EngineFailure("engine_response_limit")
                    data.extend(chunk)
                if response.status_code == 404:
                    return None
                if response.status_code == 304 and path.endswith(("/start", "/stop")):
                    return {}
                if response.status_code == 409 and method == "DELETE" and path.startswith("/images/"):
                    # Bounded cache GC must not remove an image still used by another installation.
                    return {}
                if not 200 <= response.status_code < 300:
                    raise EngineFailure("engine_operation_failed")
                # Exec output is Docker's bounded multiplexed stream, not arbitrary logs.
                if path.endswith("/start") and "/exec/" in path:
                    return bytes(data)
                if not data:
                    return {}
                if path.startswith("/images/load"):
                    for line in data.splitlines():
                        value = json.loads(line)
                        if "error" in value or "errorDetail" in value:
                            raise EngineFailure("engine_image_load_failed")
                    return {}
                return json.loads(data)
        except (httpx.HTTPError, ValueError, TypeError):
            raise EngineFailure("engine_transport_or_protocol") from None

    def identity(self, job: Delivery) -> dict[str, Any]:
        info = self.call("GET", "/info")
        if (
            not isinstance(info, dict)
            or info.get("ID") != self.expected_id
            or job.engine_id != self.expected_id
        ):
            raise EngineFailure("engine_identity_mismatch")
        if "name=rootless" not in info.get("SecurityOptions", []):
            raise EngineFailure("rootless_engine_required")
        return info

    def available(self, job: Delivery) -> None:
        info = self.identity(job)
        rows = self.call("GET", "/containers/json", params={"all": "true"})
        if (
            not isinstance(rows, list)
            or len(rows) > 128
            or any(
                row.get("Labels", {}).get("io.xarionix.deployment.host") != str(job.host_id) for row in rows
            )
        ):
            raise EngineFailure("dedicated_engine_required")
        if (
            not any(s.startswith("name=seccomp") for s in info.get("SecurityOptions", []))
            or str(info.get("CgroupVersion")) != "2"
            or not all(info.get(k) is True for k in ("MemoryLimit", "SwapLimit", "PidsLimit", "CpuCfsQuota"))
        ):
            raise EngineFailure("isolation_unavailable")
        raw_architecture = str(info.get("Architecture", ""))
        architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(raw_architecture, raw_architecture)
        if job.runtime.platform != "linux/" + str(architecture):
            raise EngineFailure("engine_platform_mismatch")

    def owned(self, job: Delivery) -> list[dict[str, Any]]:
        self.identity(job)
        filters = json.dumps(
            {
                "label": [
                    "io.xarionix.deployment.host=" + str(job.host_id),
                    "io.xarionix.deployment.installation=" + str(job.installation_id),
                ]
            },
            separators=(",", ":"),
        )
        rows = self.call("GET", "/containers/json", params={"all": "true", "filters": filters})
        if not isinstance(rows, list) or len(rows) > 4:
            raise EngineFailure("runtime_inventory_invalid")
        return rows

    def inspect(self, identifier: str) -> dict[str, Any] | None:
        value = self.call("GET", "/containers/" + identifier + "/json")
        if value is None:
            return None
        if not isinstance(value, dict):
            raise EngineFailure("runtime_inventory_invalid")
        return value

    def execute(self, identifier: str, source: str) -> bytes:
        value = self.call(
            "POST",
            "/containers/" + identifier + "/exec",
            json={
                "AttachStdout": True,
                "AttachStderr": True,
                "Tty": False,
                "User": "10001:10001",
                "Privileged": False,
                "Cmd": ["/usr/local/bin/python", "-I", "-c", source],
            },
        )
        if not isinstance(value, dict) or not isinstance(value.get("Id"), str):
            raise EngineFailure("health_probe_failed")
        output = self.call(
            "POST", "/exec/" + value["Id"] + "/start", json={"Detach": False, "Tty": False}, timeout=5
        )
        status = self.call("GET", "/exec/" + value["Id"] + "/json")
        if (
            not isinstance(output, bytes)
            or not isinstance(status, dict)
            or status.get("Running") is not False
            or status.get("ExitCode") != 0
        ):
            raise EngineFailure("health_probe_failed")
        result, offset = bytearray(), 0
        while offset < len(output):
            header = output[offset : offset + 8]
            if len(header) != 8 or header[0] not in {1, 2}:
                raise EngineFailure("health_probe_failed")
            size = int.from_bytes(header[4:], "big")
            if offset + 8 + size > len(output):
                raise EngineFailure("health_probe_failed")
            result.extend(output[offset + 8 : offset + 8 + size])
            offset += 8 + size
        return bytes(result)

    def constraints(self, info: dict[str, Any], job: Delivery, *, epoch: UUID | None = None) -> None:
        config, host = info.get("Config", {}), info.get("HostConfig", {})
        limits = PROFILES[job.profile]
        labels = config.get("Labels", {})
        image = self.image(job)
        if (
            labels.get("io.xarionix.deployment.host") != str(job.host_id)
            or labels.get("io.xarionix.deployment.installation") != str(job.installation_id)
            or info.get("Image") != image["Id"]
            or config.get("User") != "10001:10001"
            or (
                job.profile != "module-api-stateful-v1"
                and (config.get("Env") or []) != (image.get("Config", {}).get("Env") or [])
            )
            or host.get("NetworkMode") != "none"
            or host.get("Privileged") is not False
            or host.get("ReadonlyRootfs") is not True
            or set(host.get("CapDrop", [])) != {"ALL"}
            or host.get("CapAdd")
            or set(host.get("SecurityOpt", [])) != {"no-new-privileges"}
            or host.get("CgroupnsMode") != "private"
            or host.get("Binds")
            or (job.profile != "module-api-stateful-v1" and (host.get("Mounts") or info.get("Mounts")))
            or host.get("Devices")
            or host.get("DeviceRequests")
            or host.get("PortBindings")
            or host.get("PidMode")
            or host.get("IpcMode") not in {"private", "none"}
            or host.get("Memory") != limits["memory"]
            or host.get("MemorySwap") != limits["memory"]
            or host.get("PidsLimit") != limits["pids"]
            or host.get("CpuQuota") != limits["cpu_quota"]
            or host.get("CpuPeriod") != 100000
            or host.get("Tmpfs") != {TMP_PATH: f"rw,noexec,nosuid,nodev,size={limits['tmpfs']}"}
        ):
            raise EngineFailure("isolation_unavailable")
        if job.profile == "module-api-stateful-v1":
            if job.storage is None:
                raise EngineFailure("storage_binding_required")
            try:
                validate_configuration(info, image, job)
                if labels.get("io.xarionix.storage.sdk-sha256") != job.storage.sdk_sha256:
                    raise StorageError("storage_sdk_binding_changed")
                StorageController(self, self.storage_root).validate_mounts(
                    info, job, epoch or job.storage.epoch_id
                )
            except (StorageError, ValueError, OSError):
                raise EngineFailure("isolation_unavailable") from None
        if info.get("State", {}).get("Running"):
            measured = json.loads(self.execute(info["Id"], ISOLATION_PROBE))
            if (
                measured.get("uid") != 10001
                or int(measured.get("caps", "1"), 16) != 0
                or measured.get("nnp") != "1"
                or measured.get("seccomp") != "2"
                or measured.get("memory") != str(limits["memory"])
                or measured.get("swap") != "0"
                or measured.get("pids") != str(limits["pids"])
                or measured.get("cpu") != f"{limits['cpu_quota']} 100000"
            ):
                raise EngineFailure("isolation_unavailable")
            if job.profile in {"module-api-private-v1", "module-api-stateful-v1"}:
                network = info.get("NetworkSettings", {})
                measured_api = json.loads(self.execute(info["Id"], API_ISOLATION_PROBE))
                if (
                    set(network.get("Networks", {})) != {"none"}
                    or network.get("Ports")
                    or measured_api != {"interfaces": ["lo"], "engine": False}
                ):
                    raise EngineFailure("isolation_unavailable")

    def load(self, path: Path, job: Delivery) -> None:
        def chunks() -> Iterator[bytes]:
            with path.open("rb") as stream:
                while chunk := stream.read(65536):
                    yield chunk

        self.call(
            "POST", "/images/load?quiet=true", content=chunks(), headers={"Content-Type": "application/x-tar"}
        )
        self.image(job)

    def image(self, job: Delivery) -> dict[str, Any]:
        # Docker's containerd store identifies an imported OCI image by manifest
        # digest; the classic graphdriver uses config digest. Both are bound by
        # the signed OCI inventory. Never resolve by a mutable tag or image name.
        image = self.call("GET", "/images/" + job.runtime.image_digest + "/json")
        if image is None:
            image = self.call("GET", "/images/" + job.runtime.config_digest + "/json")
        if (
            not isinstance(image, dict)
            or image.get("Id") not in {job.runtime.config_digest, job.runtime.image_digest}
            or (
                image.get("Id") == job.runtime.image_digest
                and image.get("Descriptor", {}).get("digest") != job.runtime.image_digest
            )
            or (image.get("Descriptor") and image["Descriptor"].get("digest") != job.runtime.image_digest)
            or str(image.get("Os")) + "/" + str(image.get("Architecture")) != job.runtime.platform
            or image.get("Config", {}).get("Volumes")
            or image.get("Config", {}).get("OnBuild")
        ):
            raise EngineFailure("image_identity_mismatch")
        return image

    def create(self, job: Delivery, *, epoch: UUID | None = None) -> str:
        limits = PROFILES[job.profile]
        storage = StorageController(self, self.storage_root)
        selected = epoch or (job.storage.epoch_id if job.storage else None)
        if job.profile == "module-api-stateful-v1":
            if selected is None:
                raise EngineFailure("storage_binding_required")
            storage.volume(job, selected, create=True)
        text = configuration_text(job) if job.profile == "module-api-stateful-v1" else None
        image = self.image(job)
        name = (
            "xarionix-"
            + job.host_id.hex[:8]
            + "-"
            + job.installation_id.hex
            + "-"
            + job.runtime.config_digest[7:19]
        )
        if text is not None and selected is not None:
            name += "-" + selected.hex[:8] + "-" + str(job.generation)
        value = self.call(
            "POST",
            "/containers/create",
            params={"name": name},
            json={
                "Image": self.image(job)["Id"],
                "User": "10001:10001",
                "Env": [*(image.get("Config", {}).get("Env") or []), CONFIG_ENV + text]
                if text is not None
                else [],
                "WorkingDir": "/app",
                "Labels": {
                    "io.xarionix.deployment.host": str(job.host_id),
                    "io.xarionix.deployment.installation": str(job.installation_id),
                    "io.xarionix.deployment.image": job.runtime.image_digest,
                    **(
                        {
                            CONFIG_LABEL: hashlib.sha256(text.encode()).hexdigest(),
                            "io.xarionix.storage.sdk-sha256": job.storage.sdk_sha256,
                        }
                        if text is not None and job.storage
                        else {}
                    ),
                },
                "HostConfig": {
                    **({"Mounts": [storage.mount(job, selected)]} if text is not None and selected else {}),
                    "NetworkMode": "none",
                    "ReadonlyRootfs": True,
                    "Privileged": False,
                    "CapDrop": ["ALL"],
                    "SecurityOpt": ["no-new-privileges"],
                    "CgroupnsMode": "private",
                    "IpcMode": "none",
                    "Memory": limits["memory"],
                    "MemorySwap": limits["memory"],
                    "PidsLimit": limits["pids"],
                    "CpuPeriod": 100000,
                    "CpuQuota": limits["cpu_quota"],
                    # Fixed private in-container tmpfs, not a host temporary pathname.
                    "Tmpfs": {TMP_PATH: f"rw,noexec,nosuid,nodev,size={limits['tmpfs']}"},
                    "RestartPolicy": {"Name": "on-failure", "MaximumRetryCount": 3},
                    "LogConfig": {"Type": "local", "Config": {"max-size": "1m", "max-file": "2"}},
                },
            },
        )
        if not isinstance(value, dict) or not isinstance(value.get("Id"), str):
            raise EngineFailure("runtime_create_failed")
        identifier = str(value["Id"])
        if text is not None and job.operation != "restore":
            storage.initialize(identifier, job)
        return identifier

    def stop(self, identifier: str) -> None:
        self.call("POST", "/containers/" + identifier + "/stop", params={"t": "10"})

    def stateful_report(self, job: Delivery, *, epoch: UUID | None = None) -> RuntimeReport:
        if job.storage is None:
            raise EngineFailure("storage_binding_required")
        storage = StorageController(self, self.storage_root)
        selected = epoch or storage.current_epoch(job)
        report = RuntimeReport(
            installation_id=job.installation_id,
            generation=job.generation,
            image_digest=job.runtime.image_digest,
            state="not_provisioned",
            health="unknown",
        )
        inspected = [self.inspect(row["Id"]) for row in self.owned(job)]
        running = [info for info in inspected if info and info.get("State", {}).get("Running") is True]
        if len(running) > 1:
            raise EngineFailure("storage_multiple_writers")
        candidates = [
            info
            for info in inspected
            if info
            and info.get("Config", {}).get("Labels", {}).get("io.xarionix.deployment.image")
            == job.runtime.image_digest
            and any(m.get("Name") == volume_name(job, selected) for m in info.get("Mounts", []))
        ]
        if not candidates:
            return report
        info = next(
            (info for info in candidates if info.get("State", {}).get("Running") is True), candidates[0]
        )
        self.constraints(info, job, epoch=selected)
        active = info.get("State", {}).get("Running") is True
        observed = None
        healthy = False
        if active:
            try:
                self.execute(info["Id"], HEALTH_PROBE)
                value = json.loads(self.execute(info["Id"], STORAGE_PROBE))
                config = validate_configuration(info, self.image(job), job)
                if (
                    set(value)
                    != {"schema_version", "installation_id", "installation_generation", "data_schema_version"}
                    or value["schema_version"] != 1
                    or value["installation_id"] != str(job.installation_id)
                    or value["installation_generation"] != config.installation_generation
                    or type(value["data_schema_version"]) is not int
                    or not job.storage.compatible_minimum
                    <= value["data_schema_version"]
                    <= job.storage.compatible_maximum
                ):
                    raise EngineFailure("storage_schema_incompatible")
                observed = StorageReport(epoch_id=selected, data_schema_version=value["data_schema_version"])
                healthy = True
            except (EngineFailure, StorageError, ValueError, OSError):
                pass
        else:
            observed = storage.inspect(info["Id"], job, selected)
        return report.model_copy(
            update={
                "container_id": info["Id"],
                "state": "running" if active else "stopped",
                "health": "healthy" if healthy else "unhealthy" if active else "unknown",
                "live": healthy,
                "ready": healthy,
                "restart_count": info.get("RestartCount", 0),
                "storage": observed,
            }
        )

    def apply_stateful(
        self, job: Delivery, authorize: Callable[[], None], archive: Path | None
    ) -> RuntimeReport:
        if job.storage is None:
            raise EngineFailure("storage_binding_required")
        storage = StorageController(self, self.storage_root)
        rows = self.owned(job)
        if job.operation == "inspect":
            authorize()
            return self.stateful_report(job)
        if job.operation in {"stop", "quarantine", "retire", "deprovision"}:
            authorize()
            for row in rows:
                self.stop(row["Id"])
            try:
                report = self.stateful_report(job)
            except (EngineFailure, StorageError, sqlite3.DatabaseError, OSError, tarfile.TarError):
                report = RuntimeReport(
                    installation_id=job.installation_id,
                    generation=job.generation,
                    image_digest=job.runtime.image_digest,
                    state="stopped",
                    health="unknown",
                )
            if job.operation == "deprovision":
                for row in rows:
                    self.call("DELETE", "/containers/" + row["Id"], params={"v": "false", "force": "false"})
                report = report.model_copy(update={"state": "not_provisioned", "container_id": None})
            return report
        self.available(job)
        if archive:
            self.load(archive, job)
        authorize()
        for row in rows:
            self.stop(row["Id"])
        if rows:
            self.trim_stopped(job, rows[0]["Id"])
        selected = job.storage.next_epoch_id if job.operation == "restore" else job.storage.epoch_id
        if job.operation == "restore":
            storage.backup_metadata(job)
        candidates = []
        desired = configuration_text(job)
        for row in self.owned(job):
            info = self.inspect(row["Id"])
            if (
                info
                and info.get("Config", {}).get("Labels", {}).get("io.xarionix.deployment.image")
                == job.runtime.image_digest
                and CONFIG_ENV + desired in info.get("Config", {}).get("Env", [])
                and any(m.get("Name") == volume_name(job, selected) for m in info.get("Mounts", []))
            ):
                candidates.append(row["Id"])
        if len(candidates) > 1:
            raise EngineFailure("storage_runtime_ambiguous")
        identifier = candidates[0] if candidates else self.create(job, epoch=selected)
        info = self.inspect(identifier)
        if info is None:
            raise EngineFailure("runtime_missing")
        self.constraints(info, job, epoch=selected)
        if job.operation == "backup":
            observed = storage.backup(identifier, job)
        elif job.operation == "restore":
            observed = storage.restore(identifier, job)
        else:
            observed = storage.inspect(identifier, job, selected)
            if observed.data_schema_version != job.storage.expected_schema_version:
                raise StorageError("storage_schema_snapshot_changed")
            if (
                observed.data_schema_version > 0
                and observed.data_schema_version < job.storage.target_schema_version
            ):
                storage.validate_migration_backup(job)
            elif (
                observed.data_schema_version > 0
                and not job.storage.compatible_minimum
                <= observed.data_schema_version
                <= job.storage.compatible_maximum
            ):
                raise StorageError("storage_schema_incompatible")
        authorize()
        if job.operation in {"provision", "backup", "restore"}:
            self.trim_stopped(job, identifier)
            return RuntimeReport(
                installation_id=job.installation_id,
                generation=job.generation,
                image_digest=job.runtime.image_digest,
                container_id=identifier,
                state="stopped",
                health="unknown",
                storage=observed,
            )
        healthy = False
        try:
            self.call("POST", "/containers/" + identifier + "/start")
            deadline = time.monotonic() + 30
            while True:
                report = self.stateful_report(job, epoch=selected)
                if report.health == "healthy":
                    authorize()
                    self.trim_stopped(job, identifier)
                    healthy = True
                    return report
                if time.monotonic() >= deadline:
                    raise EngineFailure("health_failed")
                time.sleep(0.25)
        finally:
            if not healthy:
                self.stop(identifier)

    def trim_stopped(self, job: Delivery, active_id: str) -> None:
        # Retain active + one previous stopped runtime, always preserving volumes.
        # Stateful generations can share one image with different approved config;
        # removing that in-use image is not part of container retirement.
        rows = sorted(
            (r for r in self.owned(job) if r["Id"] != active_id),
            key=lambda r: (r.get("Created", 0), r["Id"]),
            reverse=True,
        )
        for row in rows[1:]:
            info = self.inspect(row["Id"])
            if info is None or info.get("State", {}).get("Running"):
                raise EngineFailure("runtime_inventory_invalid")
            self.call("DELETE", "/containers/" + row["Id"], params={"v": "false", "force": "false"})
            if job.profile != "module-api-stateful-v1":
                self.call("DELETE", "/images/" + info["Image"], params={"force": "false", "noprune": "true"})

    def report(self, job: Delivery) -> RuntimeReport:
        if job.profile == "module-api-stateful-v1":
            try:
                return self.stateful_report(job)
            except (StorageError, sqlite3.DatabaseError, OSError, ValueError, tarfile.TarError):
                raise EngineFailure("storage_observation_failed") from None
        rows = self.owned(job)
        matching = [
            r
            for r in rows
            if r.get("Labels", {}).get("io.xarionix.deployment.image") == job.runtime.image_digest
        ]
        report = RuntimeReport(
            installation_id=job.installation_id,
            generation=job.generation,
            image_digest=job.runtime.image_digest,
            state="not_provisioned",
            health="unknown",
        )
        if not matching:
            return report
        info = self.inspect(matching[0]["Id"])
        if info is None:
            return report
        self.constraints(info, job)
        running = info.get("State", {}).get("Running") is True
        healthy = False
        if running:
            try:
                self.execute(info["Id"], HEALTH_PROBE)
                healthy = True
            except EngineFailure:
                pass
        return report.model_copy(
            update={
                "container_id": info["Id"],
                "state": "running" if running else "stopped",
                "health": "healthy" if healthy else "unhealthy" if running else "unknown",
                "live": healthy,
                "ready": healthy,
                "restart_count": info.get("RestartCount", 0),
            }
        )

    def apply(
        self, job: Delivery, authorize: Callable[[], None], archive: Path | None = None
    ) -> RuntimeReport:
        if job.profile == "module-api-stateful-v1":
            try:
                return self.apply_stateful(job, authorize, archive)
            except (StorageError, sqlite3.DatabaseError, tarfile.TarError, ValueError, OSError):
                raise EngineFailure("storage_operation_failed") from None
        # Stops/quarantine remain possible even after trust, cgroup support or health is lost.
        rows = self.owned(job)
        if job.operation == "inspect":
            authorize()
            return self.report(job)
        if job.operation in {"stop", "quarantine", "retire", "deprovision"}:
            authorize()
            for row in rows:
                self.stop(row["Id"])
                if job.operation == "deprovision":
                    self.call("DELETE", "/containers/" + row["Id"], params={"v": "false", "force": "false"})
            return RuntimeReport(
                installation_id=job.installation_id,
                generation=job.generation,
                image_digest=job.runtime.image_digest,
                state="not_provisioned" if job.operation == "deprovision" else "stopped",
                health="unknown",
            )
        self.available(job)
        if archive:
            self.load(archive, job)
        authorize()
        matches = [
            r
            for r in rows
            if r.get("Labels", {}).get("io.xarionix.deployment.image") == job.runtime.image_digest
        ]
        if job.operation == "restart" and not matches:
            raise EngineFailure("runtime_missing")
        identifier = matches[0]["Id"] if matches else self.create(job)
        info = self.inspect(identifier)
        if info is None:
            raise EngineFailure("runtime_missing")
        self.constraints(info, job)
        if job.operation != "provision":
            if job.operation == "restart":
                self.stop(identifier)
            for row in rows:
                if row["Id"] != identifier:
                    self.stop(row["Id"])
            authorize()
            healthy = False
            try:
                self.call("POST", "/containers/" + identifier + "/start")
                deadline = time.monotonic() + 30
                while True:
                    report = self.report(job)
                    if report.health == "healthy":
                        self.trim_stopped(job, identifier)
                        healthy = True
                        return report
                    if time.monotonic() >= deadline:
                        raise EngineFailure("health_failed")
                    time.sleep(0.25)
            finally:
                # Post-start cgroup/health verification failure must not leave an
                # unacknowledged or insufficiently isolated process running.
                if not healthy:
                    try:
                        self.stop(identifier)
                    except EngineFailure:
                        pass
        return self.report(job)
