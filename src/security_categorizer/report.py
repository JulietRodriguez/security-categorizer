"""Categorization result as JSON and Markdown, plus a plain baseline list."""

from __future__ import annotations

import json

from security_categorizer import __version__
from security_categorizer.baseline import BaselineSelection, display_id
from security_categorizer.categorize import Categorization
from security_categorizer.datasets import InfoTypeCatalog
from security_categorizer.levels import OBJECTIVES

APPROVAL_NOTE = (
    "This categorization is a draft prepared with security-categorizer. Under NIST SP 800-37 Rev. 2 "
    "(task C-2) the security categorization is reviewed and approved by the Authorizing Official or "
    "the AO's designated representative; for national security systems, CNSSI 1253 applies."
)


def to_dict(cat: Categorization, selection: BaselineSelection, catalog: InfoTypeCatalog) -> dict:
    result: dict = {
        "tool": {"name": "security-categorizer", "version": __version__},
        "system": cat.system_name,
        "mode": cat.mode,
        "processes_pii": cat.processes_pii,
        "security_category": {o: cat.final[o].value for o in OBJECTIVES},
        "fips199_statement": cat.fips199_statement,
        "information_types": [
            {
                "id": t.id,
                "title": t.title,
                "source": t.source,
                "provisional": {o: t.provisional[o].value for o in OBJECTIVES},
                "final": {o: t.final[o].value for o in OBJECTIVES},
                "adjustments": [
                    {
                        "objective": a.objective,
                        "from": a.before.value,
                        "to": a.after.value,
                        "direction": a.direction,
                        "justification": a.justification,
                    }
                    for a in t.adjustments
                ],
                "source_footnotes": list(t.footnoted),
            }
            for t in cat.types
        ],
        "high_water_mark": {o: cat.high_water[o].value for o in OBJECTIVES},
        "system_adjustments": [
            {"objective": a.objective, "from": a.before.value, "to": a.after.value, "justification": a.justification}
            for a in cat.system_adjustments
        ],
        "baseline": {
            "name": selection.name,
            "source": selection.source,
            "control_count": len(selection.controls),
            "parts": {k: len(v) for k, v in selection.parts.items()},
            "pending_overlays": selection.pending_overlays,
            "notes": selection.notes,
            "controls": selection.controls,
        },
        "warnings": cat.warnings,
        "data": {"information_types": catalog.name, "source": catalog.source},
        "approval": APPROVAL_NOTE,
    }
    if cat.mode == "federal":
        result["overall_impact_level"] = cat.overall.value
    else:
        result["cnssi_1253_categorization"] = cat.trigraph
        result["overlays"] = cat.overlays
    return result


def to_json(cat: Categorization, selection: BaselineSelection, catalog: InfoTypeCatalog) -> str:
    return json.dumps(to_dict(cat, selection, catalog), indent=2, ensure_ascii=False) + "\n"


def _esc(text: object) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def _cia(levels: dict) -> str:
    return " / ".join(levels[o].label for o in OBJECTIVES)


def to_markdown(cat: Categorization, selection: BaselineSelection, catalog: InfoTypeCatalog) -> str:
    out: list[str] = []
    w = out.append
    w(f"# Security categorization: {_esc(cat.system_name)}")
    w("")
    w(f"> **DRAFT.** {APPROVAL_NOTE}")
    w("")
    if cat.mode == "federal":
        w(f"## Result: {cat.overall.label} system (FIPS 199 / FIPS 200)")
        w("")
        w(f"`{_esc(cat.fips199_statement)}`")
        w("")
        w(
            f"Overall impact level **{cat.overall.label}** is the FIPS 200 high-water mark of confidentiality "
            f"{cat.final['confidentiality'].label}, integrity {cat.final['integrity'].label} and availability "
            f"{cat.final['availability'].label}."
        )
    else:
        w(f"## Result: {cat.trigraph} (CNSSI 1253)")
        w("")
        w(
            f"Confidentiality **{cat.final['confidentiality'].label}**, integrity **{cat.final['integrity'].label}**, "
            f"availability **{cat.final['availability'].label}**. CNSSI 1253 keeps the three objectives separate; "
            "there is no single overall level."
        )
    w("")
    w(f"Processes PII: {'yes' if cat.processes_pii else 'no'}.")
    w("")

    w("## Information types")
    w("")
    w("| ID | Information type | Provisional C / I / A | Final C / I / A | Adjusted |")
    w("|---|---|---|---|---|")
    for t in cat.types:
        adjusted = "yes" if t.adjustments else ""
        w(f"| {t.id} | {_esc(t.title)} | {_cia(t.provisional)} | {_cia(t.final)} | {adjusted} |")
    w("")
    adjusted = [(t, a) for t in cat.types for a in t.adjustments]
    if adjusted or cat.system_adjustments:
        w("## Adjustments and justifications")
        w("")
        for t, a in adjusted:
            change = f"{a.before.label} → {a.after.label} ({a.direction})"
            w(f"- **{t.id} {a.objective}**: {change}. {_esc(a.justification)}")
        for a in cat.system_adjustments:
            change = f"{a.before.label} → {a.after.label} ({a.direction})"
            w(f"- **System {a.objective}**: {change}. {_esc(a.justification)}")
        w("")

    w("## High-water mark")
    w("")
    w("| Objective | Highest information-type level | Final (after system-level adjustments) |")
    w("|---|---|---|")
    for o in OBJECTIVES:
        w(f"| {o.capitalize()} | {cat.high_water[o].label} | {cat.final[o].label} |")
    w("")
    w("A system objective is never below Low: FIPS 199 does not allow not-applicable for a system.")
    w("")

    count = f"{len(selection.controls)} controls" if selection.controls else "no controls selected"
    w(f"## Control baseline: {selection.name} ({count})")
    w("")
    for label, ids in selection.parts.items():
        w(f"- {label}: {len(ids)} controls")
    for note in selection.notes:
        w(f"- {note}")
    w("")
    if selection.controls:
        w("The full list is in `baseline.txt` and, as an OSCAL profile, in `baseline-profile.json`.")
        w("")
    if cat.warnings:
        w("## Review notes")
        w("")
        for warning in cat.warnings:
            w(f"- {_esc(warning)}")
        w("")
    w("## Data sources")
    w("")
    src = catalog.source
    w(f"- Information types: {_esc(src.get('title', catalog.name))} ({src.get('published', 'date not stated')}).")
    w(f"- Baseline: {_esc(selection.source)}.")
    w("")
    return "\n".join(out)


def baseline_text(selection: BaselineSelection) -> str:
    lines = [f"# {selection.name}: {len(selection.controls)} controls ({selection.source})"]
    for cid, title in selection.titled():
        lines.append(f"{display_id(cid):<12} {title}")
    return "\n".join(lines) + "\n"
