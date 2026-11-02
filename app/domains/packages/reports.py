"""Descriptive reports, never a dependency installer or an RBAC catalog mutator."""

from typing import Any

from app.domains.packages.schema import Manifest
from app.domains.packages.semver import Range


def diff(previous: Manifest, current: Manifest) -> dict[str, Any]:
    before = {p.key for p in previous.permissions.definitions}
    after = {p.key for p in current.permissions.definitions}
    names = ("permissions", "dependencies", "compatibility", "artifacts")
    old_artifacts = {a.path: a.model_dump() for a in previous.artifacts}
    new_artifacts = {a.path: a.model_dump() for a in current.artifacts}
    old_permissions = {p.key: p.model_dump() for p in previous.permissions.definitions}
    new_permissions = {p.key: p.model_dump() for p in current.permissions.definitions}
    return {
        "permissions": {
            "added": sorted(after - before),
            "removed": sorted(before - after),
            "unchanged": sorted(
                key for key in before & after if old_permissions[key] == new_permissions[key]
            ),
            "modified": sorted(key for key in before & after if old_permissions[key] != new_permissions[key]),
        },
        "namespaces": {"before": previous.permissions.namespace, "after": current.permissions.namespace},
        "changed_sections": [name for name in names if getattr(previous, name) != getattr(current, name)],
        "protocol": {
            "before": previous.compatibility.module_protocol,
            "after": current.compatibility.module_protocol,
        },
        "runtime_type": {"before": previous.module.type, "after": current.module.type},
        "core_compatibility": {"before": previous.compatibility.core, "after": current.compatibility.core},
        "dependencies": {
            "before": [d.model_dump() for d in previous.dependencies],
            "after": [d.model_dump() for d in current.dependencies],
        },
        "artifacts": {
            "added": sorted(new_artifacts.keys() - old_artifacts.keys()),
            "removed": sorted(old_artifacts.keys() - new_artifacts.keys()),
            "modified": sorted(
                path
                for path in old_artifacts.keys() & new_artifacts.keys()
                if old_artifacts[path] != new_artifacts[path]
            ),
        },
        "activation_performed": False,
    }


def dependencies(manifest: Manifest, known: list[Manifest]) -> dict[str, Any]:
    # Only current-trusted, compatible packages enter 'known'; never pick an arbitrary newest version.
    reports: list[dict[str, Any]] = []
    graph = {(p.publisher.id, p.module.id, p.module.version): p for p in [*known, manifest]}
    visited: set[tuple[str, str, str]] = set()
    cyclic, budget = False, 4096

    def visit(node: Manifest, path: frozenset[tuple[str, str, str]]) -> None:
        nonlocal cyclic, budget
        key = node.publisher.id, node.module.id, node.module.version
        if key in path:
            cyclic = True
            return
        if key in visited:
            return
        visited.add(key)
        for item in node.dependencies:
            budget -= 1
            if budget < 0:
                cyclic = True
                return
            matches = [
                p
                for p in graph.values()
                if p.module.id == item.module_id
                and p.publisher.id == item.publisher_id
                and Range.parse(item.version).contains(p.module.version)
            ]
            reports.append(
                {
                    "required_by": ":".join(key),
                    "module_id": item.module_id,
                    "publisher_id": item.publisher_id,
                    "range": item.version,
                    "candidates": sorted(p.module.version for p in matches),
                    "state": "missing" if not matches else "ambiguous" if len(matches) > 1 else "candidate",
                }
            )
            for child in matches:
                visit(child, path | {key})

    visit(manifest, frozenset())
    return {
        "items": reports,
        "cycle_or_complexity_limit": cyclic,
        "ready": not cyclic and all(p["state"] == "candidate" for p in reports),
        "automatic_selection": False,
    }
