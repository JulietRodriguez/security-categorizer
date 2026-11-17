"""Impact levels and the high-water mark.

FIPS 199 defines three potential impact levels (low, moderate, high) for each
security objective (confidentiality, integrity, availability). An information
type may be "not applicable" for an objective (SP 800-60 uses this for public
information, for example), but a *system* may not: FIPS 199 says
not-applicable can't be assigned to a security objective of an information
system, so a system objective is never lower than low.
"""

from __future__ import annotations

from collections.abc import Iterable
from enum import Enum

OBJECTIVES = ("confidentiality", "integrity", "availability")


class Level(str, Enum):
    NA = "n/a"
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"

    @property
    def rank(self) -> int:
        return _RANK[self]

    @property
    def letter(self) -> str:
        """L / M / H, as used in CNSSI 1253 trigraphs such as M-M-L."""
        return {"n/a": "-", "low": "L", "moderate": "M", "high": "H"}[self.value]

    @property
    def oscal(self) -> str:
        """OSCAL / FedRAMP token, e.g. fips-199-moderate (not-applicable for n/a)."""
        return f"fips-199-{self.value}" if self is not Level.NA else "not-applicable"

    @property
    def label(self) -> str:
        return "N/A" if self is Level.NA else self.value.capitalize()

    @classmethod
    def parse(cls, value: object) -> Level:
        text = str(value).strip().lower().removeprefix("fips-199-")
        aliases = {"na": "n/a", "not applicable": "n/a", "not-applicable": "n/a", "l": "low", "m": "moderate",
                   "medium": "moderate", "h": "high"}  # fmt: skip
        text = aliases.get(text, text)
        try:
            return cls(text)
        except ValueError as exc:
            raise ValueError(f"unknown impact level {value!r} (use low, moderate, high or n/a)") from exc


_RANK = {Level.NA: 0, Level.LOW: 1, Level.MODERATE: 2, Level.HIGH: 3}


def high_water(levels: Iterable[Level], *, floor: Level | None = None) -> Level:
    """Highest level in ``levels`` (n/a is lowest); never below ``floor`` when given."""
    result = max(levels, key=lambda lvl: lvl.rank, default=Level.NA)
    if floor is not None and result.rank < floor.rank:
        return floor
    return result
