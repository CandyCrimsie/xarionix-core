"""Developer CLI: import reviewed local source, never invoked by Core on uploaded code."""

import argparse
import importlib
from pathlib import Path

from .application import Module
from .validation import decode, json_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description="Проверка и metadata бизнес-модуля Xarionix")
    parser.add_argument("command", choices=("check", "metadata"))
    parser.add_argument("entry", help="Проверенный локальный Python entry: module:attribute")
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        package, attribute = args.entry.split(":")
        value = getattr(importlib.import_module(package), attribute)
        if not isinstance(value, Module):
            raise ValueError()
        manifest = decode(args.manifest.read_bytes(), 65536)
        value.check(manifest)
        if args.command == "metadata":
            if args.output is None:
                raise ValueError()
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / "module-api-v1.json").write_bytes(json_bytes(value.contract()))
            (args.output / "module-sdk-v1.json").write_bytes(json_bytes(value.metadata()))
        print("Контракт модуля проверен; подпись пакета выполняется штатным xpkg pack")
    except (ValueError, KeyError, AttributeError, ImportError, OSError, RecursionError):
        raise SystemExit(
            "Проверка модуля не пройдена; проверьте локальный entry и подписываемый manifest"
        ) from None
