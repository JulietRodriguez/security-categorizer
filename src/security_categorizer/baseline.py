"""Pick the control baseline that matches a categorization.

federal: SP 800-53B Low, Moderate or High (chosen by the FIPS 200 high-water
mark), plus the SP 800-53B Privacy baseline when the system processes PII.

nss: CNSSI 1253 (2022) Appendix D marks, for every control, which of the nine
columns (confidentiality, integrity, availability x low, moderate, high) select
it. The system's baseline is the union of the controls selected by its
confidentiality column, its integrity column and its availability column, plus
the NSS Privacy Control Baseline, which CNSSI 1253 applies to every NSS.
Overlays (Privacy, Classified, ...) change that list further; their content is
not bundled, so they are listed as still to be applied.

CNSSI 1253 Appendix D data is not bundled (see docs/design-notes.md). Pass it
with --nss-data; without it, nss mode still categorizes but selects no baseline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from security_categorizer.categorize import Categorization
from security_categorizer.datasets import control_title, sp800_53b
from security_categorizer.levels import OBJECTIVES
from security_categorizer.system import KNOWN_OVERLAYS


@dataclass
class BaselineSelection:
    name: str
    source: str
    controls: list[str]
    parts: dict[str, list[str]] = field(default_factory=dict)  # where the controls came from
    pending_overlays: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def titled(self) -> list[tuple[str, str]]:
        return [(c, control_title(c)) for c in self.controls]


def control_sort_key(control_id: str) -> tuple:
    m = re.match(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$", control_id)
    if not m:
        return (control_id, 0, 0)
    return (m.group(1), int(m.group(2)), int(m.group(3) or 0))


def display_id(control_id: str) -> str:
    m = re.match(r"^([a-z]{2})-(\d+)(?:\.(\d+))?$", control_id)
    if not m:
        return control_id.upper()
    return f"{m.group(1).upper()}-{m.group(2)}" + (f"({m.group(3)})" if m.group(3) else "")


def _federal(cat: Categorization) -> BaselineSelection:
    data = sp800_53b()
    level = cat.overall.value
    security = list(data["baselines"][level])
    parts = {f"SP 800-53B {level.capitalize()} baseline": security}
    controls = set(security)
    notes = [
        f"The {level} baseline is selected by the FIPS 200 high-water mark of "
        f"{', '.join(f'{o} {cat.final[o].value}' for o in OBJECTIVES)}.",
        "This is the starting point: tailor it (SP 800-37 task S-2) before control implementation.",
    ]
    if cat.processes_pii:
        privacy = list(data["baselines"]["privacy"])
        parts["SP 800-53B Privacy baseline (system processes PII)"] = privacy
        controls |= set(privacy)
    return BaselineSelection(
        name=f"SP 800-53B {level.capitalize()}" + (" + Privacy" if cat.processes_pii else ""),
        source=f"NIST SP 800-53 Rev. 5 (catalog {data['source']['catalog_version']}), SP 800-53B",
        controls=sorted(controls, key=control_sort_key),
        parts=parts,
        notes=notes,
    )


def _nss(cat: Categorization, data: dict | None) -> BaselineSelection:
    pending = [KNOWN_OVERLAYS[o] for o in cat.overlays]
    if data is None:
        return BaselineSelection(
            name=f"CNSSI 1253 {cat.trigraph} (not selected)",
            source="none: CNSSI 1253 Appendix D data was not supplied",
            controls=[],
            pending_overlays=pending,
            notes=[
                f"Categorization {cat.trigraph} is complete, but no baseline was selected: CNSSI 1253 Appendix D "
                "baseline data is not bundled with this tool. Supply it with --nss-data (format in docs/data.md).",
                "Overlays to apply: " + (", ".join(pending) if pending else "none declared") + ".",
            ],
        )
    parts = {}
    controls: set[str] = set()
    for obj in OBJECTIVES:
        level = cat.final[obj].value
        selected = list(data["baselines"][obj][level])
        parts[f"CNSSI 1253 {obj} {level}"] = selected
        controls |= set(selected)
    privacy = list(data["privacy_baseline"])
    parts["CNSSI 1253 NSS Privacy Control Baseline (all NSS)"] = privacy
    controls |= set(privacy)
    notes = [
        f"Selected by the CNSSI 1253 categorization {cat.trigraph} (confidentiality-integrity-availability); "
        "CNSSI 1253 does not use a single high-water mark.",
        "This is the starting point: apply overlays, then tailor, before control implementation.",
    ]
    if pending:
        notes.append(
            "Overlays still to apply (their control changes are not bundled with this tool): "
            + ", ".join(pending)
            + "."
        )
    return BaselineSelection(
        name=f"CNSSI 1253 {cat.trigraph}",
        source=f"{data['source'].get('title', 'CNSSI No. 1253')}, {data['source']['date']}, Appendix D",
        controls=sorted(controls, key=control_sort_key),
        parts=parts,
        pending_overlays=pending,
        notes=notes,
    )


def select_baseline(cat: Categorization, nss_data: dict | None = None) -> BaselineSelection:
    return _nss(cat, nss_data) if cat.mode == "nss" else _federal(cat)
