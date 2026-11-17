"""Read the system description (YAML or JSON).

Example (see samples/ for complete files)::

    system:
      name: SYNTHETIC Case Management System
      description: Tracks case files for a fictional agency.
    mode: federal            # or nss (CNSSI 1253)
    processes_pii: true
    information_types:
      - id: C.2.8.9          # an SP 800-60 type, by ID or exact title
        adjustments:
          - objective: confidentiality
            level: high
            justification: Records include ...
      - custom:              # a type that isn't in SP 800-60
          id: ORG-01
          title: Case records
          confidentiality: moderate
          integrity: moderate
          availability: low
          source: Agency supplement to SP 800-60, 2026
    system_adjustments:      # optional; may only raise a level
      - objective: availability
        level: moderate
        justification: ...
    overlays: [classified]   # nss mode; privacy is added automatically when processes_pii is true
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from security_categorizer.levels import OBJECTIVES, Level

KNOWN_OVERLAYS = {
    "privacy": "Privacy Overlay",
    "classified": "Classified Information Overlay",
    "space": "Space Platform Overlay",
    "intelligence": "Intelligence Overlays",
    "cds": "Cross Domain Solution Overlay",
}


class SpecError(ValueError):
    """The system description file is malformed."""


@dataclass(frozen=True)
class AdjustmentSpec:
    objective: str
    level: Level
    justification: str


@dataclass(frozen=True)
class CustomTypeSpec:
    id: str
    title: str
    source: str
    levels: tuple[tuple[str, Level], ...]


@dataclass(frozen=True)
class TypeEntry:
    ref: str | CustomTypeSpec
    adjustments: tuple[AdjustmentSpec, ...] = ()


@dataclass(frozen=True)
class SystemSpec:
    name: str
    mode: str
    description: str = ""
    short_name: str = ""
    processes_pii: bool = False
    information_types: tuple[TypeEntry, ...] = ()
    system_adjustments: tuple[AdjustmentSpec, ...] = ()
    overlays: tuple[str, ...] = field(default_factory=tuple)


def _adjustments(raw: Any, where: str) -> tuple[AdjustmentSpec, ...]:
    if raw is None:
        return ()
    if not isinstance(raw, list):
        raise SpecError(f"{where}: adjustments must be a list")
    out = []
    for i, a in enumerate(raw):
        if not isinstance(a, dict):
            raise SpecError(f"{where}: adjustment {i + 1} must be a mapping")
        obj = str(a.get("objective", "")).strip().lower()
        if obj not in OBJECTIVES:
            raise SpecError(f"{where}: adjustment {i + 1} objective must be confidentiality, integrity or availability")
        try:
            level = Level.parse(a.get("level", ""))
        except ValueError as exc:
            raise SpecError(f"{where}: adjustment {i + 1}: {exc}") from exc
        out.append(AdjustmentSpec(obj, level, str(a.get("justification") or "")))
    return tuple(out)


def _custom(raw: Any, where: str) -> CustomTypeSpec:
    if not isinstance(raw, dict):
        raise SpecError(f"{where}: custom must be a mapping")
    missing = [k for k in ("id", "title", *OBJECTIVES) if not raw.get(k)]
    if missing:
        raise SpecError(f"{where}: custom information type is missing {', '.join(missing)}")
    try:
        levels = tuple((o, Level.parse(raw[o])) for o in OBJECTIVES)
    except ValueError as exc:
        raise SpecError(f"{where}: {exc}") from exc
    return CustomTypeSpec(
        id=str(raw["id"]),
        title=str(raw["title"]),
        source=str(raw.get("source") or "custom (organization-defined)"),
        levels=levels,
    )


def parse_spec(data: Any) -> SystemSpec:
    if not isinstance(data, dict):
        raise SpecError("the system description must be a mapping at the top level")
    system = data.get("system") or {}
    if not isinstance(system, dict) or not str(system.get("name", "")).strip():
        raise SpecError("system.name is required")
    entries = []
    raw_types = data.get("information_types") or []
    if not isinstance(raw_types, list):
        raise SpecError("information_types must be a list")
    for i, raw in enumerate(raw_types):
        where = f"information_types[{i + 1}]"
        if isinstance(raw, str):
            entries.append(TypeEntry(ref=raw))
            continue
        if not isinstance(raw, dict):
            raise SpecError(f"{where}: must be an ID string or a mapping")
        if "custom" in raw:
            ref: str | CustomTypeSpec = _custom(raw["custom"], where)
        elif raw.get("id") or raw.get("title"):
            ref = str(raw.get("id") or raw.get("title"))
        else:
            raise SpecError(f"{where}: give an id, a title, or a custom type")
        entries.append(TypeEntry(ref=ref, adjustments=_adjustments(raw.get("adjustments"), where)))

    overlays = data.get("overlays") or []
    if not isinstance(overlays, list):
        raise SpecError("overlays must be a list")
    overlays = [str(o).strip().lower() for o in overlays]
    unknown = [o for o in overlays if o not in KNOWN_OVERLAYS]
    if unknown:
        raise SpecError(f"unknown overlay(s): {', '.join(unknown)} (known: {', '.join(KNOWN_OVERLAYS)})")

    pii = data.get("processes_pii", False)
    if not isinstance(pii, bool):
        raise SpecError("processes_pii must be true or false")
    return SystemSpec(
        name=str(system["name"]).strip(),
        short_name=str(system.get("short_name") or system.get("short-name") or ""),
        description=str(system.get("description") or ""),
        mode=str(data.get("mode", "federal")).strip().lower(),
        processes_pii=pii,
        information_types=tuple(entries),
        system_adjustments=_adjustments(data.get("system_adjustments"), "system_adjustments"),
        overlays=tuple(dict.fromkeys(overlays)),
    )


def load_spec(path: str | Path) -> SystemSpec:
    p = Path(path)
    if not p.is_file():
        raise SpecError(f"{p}: file not found")
    text = p.read_text(encoding="utf-8-sig")
    if p.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            raise SpecError(f"{p}: not valid JSON ({exc.msg})") from exc
    else:
        import yaml

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise SpecError(f"{p}: not valid YAML ({exc})") from exc
    return parse_spec(data)
