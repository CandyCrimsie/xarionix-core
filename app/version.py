"""Authoritative product version (not the package format or module protocol)."""

from importlib.metadata import version

# pyproject.toml is the single source; wheel metadata and editable installs expose it identically.
VERSION = version("xarionix-core")
