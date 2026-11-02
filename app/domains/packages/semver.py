"""SemVer 2 precedence and deliberately small, unambiguous V1 range grammar."""

import re
from dataclasses import dataclass
from functools import total_ordering

VERSION = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


@total_ordering
@dataclass(frozen=True, eq=False)
class Version:
    major: int
    minor: int
    patch: int
    pre: tuple[str, ...] = ()

    @classmethod
    def parse(cls, value: str) -> "Version":
        match = VERSION.fullmatch(value) if len(value) <= 120 else None
        if match is None:
            raise ValueError("invalid_semver")
        pre = tuple((match[4] or "").split(".")) if match[4] else ()
        if any(part.isdigit() and len(part) > 1 and part.startswith("0") for part in pre):
            raise ValueError("invalid_semver")
        return cls(int(match[1]), int(match[2]), int(match[3]), pre)

    def base(self) -> tuple[int, int, int]:
        return self.major, self.minor, self.patch

    def __eq__(self, other: object) -> bool:
        return isinstance(other, Version) and self.base() == other.base() and self.pre == other.pre

    def __hash__(self) -> int:
        return hash((self.base(), self.pre))

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Version):
            return NotImplemented
        if self.base() != other.base():
            return self.base() < other.base()
        if not self.pre or not other.pre:
            return bool(self.pre) and not other.pre
        for a, b in zip(self.pre, other.pre, strict=False):
            if a == b:
                continue
            if a.isdigit() and b.isdigit():
                return int(a) < int(b)
            if a.isdigit() != b.isdigit():
                return a.isdigit()
            return a < b
        return len(self.pre) < len(other.pre)


@dataclass(frozen=True)
class Range:
    clauses: tuple[tuple[str, Version], ...]

    @classmethod
    def parse(cls, value: str) -> "Range":
        if not value or len(value) > 256 or value != value.strip() or "  " in value:
            raise ValueError("invalid_version_range")
        parts = value.split(" ")
        if len(parts) > 8:
            raise ValueError("invalid_version_range")
        clauses = []
        for part in parts:
            match = re.fullmatch(r"(>=|<=|>|<|=)(.+)", part)
            if not match:
                raise ValueError("invalid_version_range")
            clauses.append((match[1], Version.parse(match[2])))
        result = cls(tuple(clauses))
        # A conjunction has one lower and upper bound; reject contradictory intervals.
        lower, upper = Version(0, 0, 0, ("0",)), None
        lower_closed, upper_closed = True, True
        for operator, version in clauses:
            if operator in {">", ">=", "="}:
                if version > lower:
                    lower, lower_closed = version, operator != ">"
                elif version == lower:
                    lower_closed &= operator != ">"
            if operator in {"<", "<=", "="}:
                if upper is None or version < upper:
                    upper, upper_closed = version, operator != "<"
                elif version == upper:
                    upper_closed &= operator != "<"
        if upper is not None and (lower > upper or (lower == upper and not (lower_closed and upper_closed))):
            raise ValueError("empty_version_range")
        stable = Version(*lower.base())
        if not lower.pre and not lower_closed:
            stable = Version(lower.major, lower.minor, lower.patch + 1)
        candidates = [stable]
        for _, version in clauses:
            if version.pre:
                first = Version(*version.base(), ("0",))
                if first < lower and first.base() == lower.base() and lower.pre:
                    first = lower if lower_closed else Version(*lower.base(), (*lower.pre, "0"))
                candidates.append(first)
        if not any(result.accepts(v) for v in candidates):
            raise ValueError("empty_version_range")
        return result

    def accepts(self, current: Version) -> bool:
        if current.pre and not any(v.pre and v.base() == current.base() for _, v in self.clauses):
            return False
        return all(
            {"=": current == v, ">": current > v, ">=": current >= v, "<": current < v, "<=": current <= v}[
                op
            ]
            for op, v in self.clauses
        )

    def contains(self, version: str) -> bool:
        return self.accepts(Version.parse(version))
