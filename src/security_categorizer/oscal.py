"""OSCAL 1.1.2 output.

* ``baseline_profile`` -- the selected baseline as an OSCAL profile that imports
  NIST's SP 800-53 Rev. 5 catalog and includes the selected control IDs. This is
  what the next RMF step (control selection, tailoring, the SSP) starts from,
  and ato-readiness-checker accepts it directly as ``--baseline``.
* ``system_characteristics`` -- the categorization in the shape of an SSP's
  ``system-characteristics``: information types with base / selected impacts and
  adjustment justifications, the C/I/A security impact level and the security
  sensitivity level. It is a fragment, not a whole SSP; a tool that builds the
  SSP merges it in. ``ssp_shell`` wraps it in the smallest SSP that NIST's
  schema accepts, which is how the tests and CI validate it.

UUIDs are UUIDv5 values derived from the system name and the object, so the
same input always produces the same file.
"""

from __future__ import annotations

import uuid

from security_categorizer import OSCAL_VERSION, __version__
from security_categorizer.baseline import BaselineSelection
from security_categorizer.categorize import Categorization
from security_categorizer.levels import OBJECTIVES, Level

NS = "https://github.com/JulietRodriguez/security-categorizer/ns/oscal"
_ROOT = uuid.uuid5(uuid.NAMESPACE_URL, "https://github.com/JulietRodriguez/security-categorizer")
# The identifier OSCAL 1.1.2 lists for the SP 800-60 Vol. 2 Rev. 1 information-type taxonomy.
SP800_60_SYSTEM = "http://doi.org/10.6028/NIST.SP.800-60v2r1"
NIST_CATALOG = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/"
    "NIST_SP-800-53_rev5_catalog.json"
)


def _uuid(*parts: str) -> str:
    return str(uuid.uuid5(_ROOT, "|".join(parts)))


def _prop(name: str, value: str) -> dict:
    return {"name": name, "ns": NS, "value": value}


def baseline_profile(cat: Categorization, selection: BaselineSelection, timestamp: str) -> dict:
    remarks = " ".join(selection.notes)
    return {
        "profile": {
            "uuid": _uuid(cat.system_name, "profile", selection.name),
            "metadata": {
                "title": f"{selection.name} baseline for {cat.system_name}",
                "last-modified": timestamp,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
                "props": [
                    _prop("generator", f"security-categorizer {__version__}"),
                    _prop("baseline-source", selection.source),
                ],
                "remarks": remarks,
            },
            "imports": [{"href": NIST_CATALOG, "include-controls": [{"with-ids": list(selection.controls)}]}],
            "merge": {"as-is": True},
        }
    }


def _impact(base: Level, final: Level, justification: str | None) -> dict:
    out: dict = {"base": base.oscal}
    if final is not base:
        out["selected"] = final.oscal
        if justification:
            out["adjustment-justification"] = justification
    return out


def system_characteristics(cat: Categorization, description: str = "") -> dict:
    info_types = []
    for t in cat.types:
        item: dict = {
            "uuid": _uuid(cat.system_name, "info-type", t.id),
            "title": t.title,
            "description": f"{t.title} ({t.id}), from {t.source}.",
        }
        if t.id[:2] in ("C.", "D."):
            item["categorizations"] = [{"system": SP800_60_SYSTEM, "information-type-ids": [t.id]}]
        for obj in OBJECTIVES:
            why = "; ".join(a.justification for a in t.adjustments if a.objective == obj)
            item[f"{obj}-impact"] = _impact(t.provisional[obj], t.final[obj], why or None)
        info_types.append(item)

    props = [_prop("generator", f"security-categorizer {__version__}"), _prop("categorization-mode", cat.mode)]
    if cat.mode == "nss":
        props.append(_prop("cnssi-1253-categorization", cat.trigraph))
    if cat.system_adjustments:
        props.append(
            _prop(
                "system-level-adjustments",
                "; ".join(
                    f"{a.objective} {a.before.value}->{a.after.value}: {a.justification}"
                    for a in cat.system_adjustments
                ),
            )
        )
    return {
        "system-name": cat.system_name,
        "description": description or f"Security categorization of {cat.system_name}.",
        "props": props,
        "security-sensitivity-level": cat.overall.oscal,
        "system-information": {"information-types": info_types},
        "security-impact-level": {f"security-objective-{o}": cat.final[o].oscal for o in OBJECTIVES},
    }


def ssp_shell(fragment: dict, system_name: str, timestamp: str) -> dict:
    """The smallest schema-valid SSP around a system-characteristics fragment (for validation)."""
    comp = _uuid(system_name, "shell-component")
    return {
        "system-security-plan": {
            "uuid": _uuid(system_name, "shell-ssp"),
            "metadata": {
                "title": f"Validation shell for {system_name}",
                "last-modified": timestamp,
                "version": __version__,
                "oscal-version": OSCAL_VERSION,
            },
            "import-profile": {"href": "baseline-profile.json"},
            "system-characteristics": {
                "system-ids": [{"identifier-type": "https://ietf.org/rfc/rfc4122", "id": _uuid(system_name, "system")}],
                **fragment,
                "status": {"state": "under-development"},
                "authorization-boundary": {"description": "Not part of categorization."},
            },
            "system-implementation": {
                "users": [{"uuid": _uuid(system_name, "shell-user"), "title": "placeholder"}],
                "components": [
                    {
                        "uuid": comp,
                        "type": "this-system",
                        "title": system_name,
                        "description": "placeholder",
                        "status": {"state": "under-development"},
                    }
                ],
            },
            "control-implementation": {
                "description": "placeholder",
                "implemented-requirements": [{"uuid": _uuid(system_name, "shell-req"), "control-id": "ra-2"}],
            },
        }
    }
