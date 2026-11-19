"""Bundled reference data, and the hook for swapping it.

The information-type catalog is a plain JSON file, so it can be replaced: point
``--info-types`` at another file with the same shape (for example a future SP
800-60 Rev. 2 taxonomy, or an agency supplement) and nothing else changes. The
schema is documented in docs/data.md and checked by ``load_info_types``.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from pathlib import Path
from typing import Any

from security_categorizer.levels import OBJECTIVES, Level

DEFAULT_INFO_TYPES = "sp800_60v2r1.json"


class DataError(ValueError):
    """A dataset file is missing or malformed."""


@dataclass(frozen=True)
class InfoType:
    id: str
    title: str
    group_title: str
    confidentiality: Level
    integrity: Level
    availability: Level
    footnoted: tuple[str, ...] = ()

    def provisional(self, objective: str) -> Level:
        return getattr(self, objective)


@dataclass(frozen=True)
class InfoTypeCatalog:
    name: str
    source: dict
    types: dict[str, InfoType]
    not_categorized: dict[str, str]

    def get(self, key: str) -> InfoType:
        """Find a type by ID (``C.3.5.8``) or by exact title, case-insensitive."""
        k = key.strip()
        if k in self.types:
            return self.types[k]
        if k in self.not_categorized:
            raise DataError(f"{k} ({self.not_categorized[k]}) has no provisional impact levels in {self.name}; "
                            "give the levels yourself as a custom information type")  # fmt: skip
        wanted = _norm(k)
        for t in self.types.values():
            if _norm(t.title) in (wanted, _norm(k + " information type")):
                return t
        raise DataError(f"information type {key!r} is not in {self.name}")

    def search(self, text: str) -> list[InfoType]:
        words = _norm(text).split()
        return [t for t in self.types.values() if all(w in _norm(f"{t.id} {t.title} {t.group_title}") for w in words)]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text.lower()).strip()


def _read_json(path: Path | None, packaged: str) -> dict[str, Any]:
    try:
        if path is None:
            return json.loads(resources.files("security_categorizer.data").joinpath(packaged).read_text("utf-8"))
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise DataError(f"dataset not found: {path or packaged}") from exc
    except json.JSONDecodeError as exc:
        raise DataError(f"dataset {path or packaged} is not valid JSON ({exc.msg})") from exc


def load_info_types(path: str | Path | None = None) -> InfoTypeCatalog:
    data = _read_json(Path(path) if path else None, DEFAULT_INFO_TYPES)
    name = str(data.get("dataset") or (Path(path).name if path else DEFAULT_INFO_TYPES))
    raw_types = data.get("information_types")
    if not isinstance(raw_types, list) or not raw_types:
        raise DataError(f"{name}: needs a non-empty 'information_types' list")
    types = {}
    for i, raw in enumerate(raw_types):
        try:
            t = InfoType(
                id=str(raw["id"]),
                title=str(raw["title"]),
                group_title=str(raw.get("group_title", "")),
                footnoted=tuple(raw.get("footnoted", [])),
                **{obj: Level.parse(raw[obj]) for obj in OBJECTIVES},
            )
        except (KeyError, ValueError) as exc:
            raise DataError(f"{name}: information_types[{i}] is invalid ({exc})") from exc
        if t.id in types:
            raise DataError(f"{name}: duplicate information type id {t.id}")
        types[t.id] = t
    not_categorized = {str(x["id"]): str(x.get("title", "")) for x in data.get("not_categorized", [])}
    return InfoTypeCatalog(name=name, source=data.get("source", {}), types=types, not_categorized=not_categorized)


@lru_cache(maxsize=1)
def sp800_53b() -> dict[str, Any]:
    return _read_json(None, "sp800_53b.json")


# The copy of CNSSI 1253 that tools/build_nss_data.py was checked against, and what it extracts
# from it. These are counts, not the tables: the tables stay with the user (no distribution
# statement in the document). load_nss_data refuses data from this PDF whose lists don't
# produce these counts, so a broken extraction (for example a different pdfplumber) is caught.
VERIFIED_CNSSI_1253 = {
    "sha256": "d876741dfb78c54cf21e1f8f966475bddb9df0d3fc8e935e5350862c246d1180",
    "date": "29 July 2022",
    "controls_listed": 1189,
    "baselines": {
        "confidentiality": {"low": 273, "moderate": 319, "high": 397},
        "integrity": {"low": 310, "moderate": 380, "high": 474},
        "availability": {"low": 147, "moderate": 202, "high": 283},
    },
    "privacy_baseline": 93,
}


def nss_data_status(data: dict[str, Any]) -> str:
    """'verified' (extracted from the checked PDF, counts match), 'unverified' (other source)."""
    return "verified" if data.get("source", {}).get("sha256") == VERIFIED_CNSSI_1253["sha256"] else "unverified"


def load_nss_data(path: str | Path) -> dict[str, Any]:
    """Load CNSSI 1253 Appendix D baseline data (format in docs/data.md).

    Build it from your own copy of the PDF with tools/build_nss_data.py. CNSSI 1253 has no
    distribution statement, so the data is not bundled; see docs/design-notes.md.
    """
    data = _read_json(Path(path), "")
    name = str(path)
    try:
        baselines = data["baselines"]
        for obj in OBJECTIVES:
            for level in ("low", "moderate", "high"):
                ids = baselines[obj][level]
                if not isinstance(ids, list) or not all(isinstance(i, str) for i in ids):
                    raise TypeError(f"baselines.{obj}.{level} must be a list of control IDs")
        if not isinstance(data["privacy_baseline"], list):
            raise TypeError("privacy_baseline must be a list of control IDs")
        if not str(data["source"]["date"]).strip():
            raise TypeError("source.date is required")
    except (KeyError, TypeError) as exc:
        raise DataError(f"{name}: not valid CNSSI 1253 baseline data ({exc})") from exc
    if nss_data_status(data) == "verified":
        v = VERIFIED_CNSSI_1253
        got = {o: {lv: len(set(baselines[o][lv])) for lv in ("low", "moderate", "high")} for o in OBJECTIVES}
        if got != v["baselines"] or len(set(data["privacy_baseline"])) != v["privacy_baseline"]:
            raise DataError(
                f"{name}: extracted from the verified CNSSI 1253 PDF, but its baselines don't match the verified "
                f"counts (got {got}, privacy {len(set(data['privacy_baseline']))}). Rebuild it with "
                'tools/build_nss_data.py and the pinned pdfplumber (pip install "security-categorizer[nss]").'
            )
    return data


def control_title(control_id: str) -> str:
    return sp800_53b()["titles"].get(control_id, "")
