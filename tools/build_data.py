"""Build the datasets in src/security_categorizer/data/ from the source documents in sources/.

    python tools/build_data.py            # regenerate the data files
    python tools/build_data.py --check    # exit 1 if the committed data differs

Sources (listed with SHA-256 in sources/SOURCES.md; CI checks the NIST files
against the official downloads):

* NIST SP 800-60 Vol. 2 Rev. 1 (August 2008) PDF -> information types and their
  provisional confidentiality / integrity / availability impact levels.
* NIST SP 800-53 Rev. 5 OSCAL content (usnistgov/oscal-content) -> the SP 800-53B
  Low, Moderate, High and Privacy baselines, and control titles.

PDF text is extracted with pypdf (pinned in the "data" extra), so the output is
the same on every machine.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / "sources"
DATA = ROOT / "src" / "security_categorizer" / "data"

SP800_60_PDF = SOURCES / "NIST.SP.800-60v2r1.pdf"
CATALOG = SOURCES / "NIST_SP-800-53_rev5_catalog-min.json"
PROFILES = {
    "low": SOURCES / "NIST_SP-800-53_rev5_LOW-baseline_profile-min.json",
    "moderate": SOURCES / "NIST_SP-800-53_rev5_MODERATE-baseline_profile-min.json",
    "high": SOURCES / "NIST_SP-800-53_rev5_HIGH-baseline_profile-min.json",
    "privacy": SOURCES / "NIST_SP-800-53_rev5_PRIVACY-baseline_profile-min.json",
}
OSCAL_CONTENT_COMMIT = "f0de6d8d8c059d374f15e0ae07508d82e370fc1d"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pdf_text(path: Path) -> list[str]:
    from pypdf import PdfReader

    return [page.extract_text() or "" for page in PdfReader(str(path)).pages]


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


# --- NIST SP 800-60 Vol. 2 Rev. 1 -------------------------------------------------------------

_LEVEL = r"(Low|Moderate|High|N/?A|Not\s+Applicable)\s*(\d*)"
_SECURITY_CATEGORY = re.compile(
    r"Security\s+Category\s*=\s*\{\s*\(\s*confidentiality\s*,\s*"
    + _LEVEL
    # NIST's own text for D.16.3 is missing a ')' after the integrity value, so it is optional here.
    + r"\s*\)\s*,\s*\(\s*integrity\s*,\s*"
    + _LEVEL
    + r"\s*\)?\s*,\s*\(\s*availability\s*,\s*"
    + _LEVEL,
    re.IGNORECASE | re.DOTALL,
)
_RECOMMENDED = re.compile(
    r"Recommended\s+(Confidentiality|Integrity|Availability)\s+Impact\s+Level\s*:(.{0,700}?)\.\s*(?:\n|$)",
    re.IGNORECASE | re.DOTALL,
)
_TOC_TYPE = re.compile(r"^\s*((?:C\.\d+\.\d+\.\d+)|(?:D\.\d+\.\d+))\s+(.*)$")
_TOC_GROUP = re.compile(r"^\s*((?:C\.\d+\.\d+)|(?:D\.\d+))\s+(.*?)\s*\.{3,}.*$")


def _level(word: str) -> str:
    w = re.sub(r"\s+", " ", word.strip().lower())
    return "n/a" if w in ("n/a", "na", "not applicable") else w


def _clean_title(t: str) -> str:
    t = re.sub(r"\s*\.{3,}\s*[\dA-Z-]*\s*$", "", t)
    return re.sub(r"\s+", " ", t).strip()


def build_sp800_60() -> dict:
    pages = pdf_text(SP800_60_PDF)
    text = "\n".join(pages)
    lines = text.split("\n")

    # 1. The table of contents is the authoritative list of information types and their groups.
    body_marker = [i for i, line in enumerate(lines) if line.strip().startswith("C.1 Recommended Provisional")]
    toc_end = body_marker[1]
    types: dict[str, dict] = {}
    groups: dict[str, str] = {}
    i = 0
    while i < toc_end:
        line = lines[i]
        g = _TOC_GROUP.match(line)
        m = _TOC_TYPE.match(line)
        if m:
            title = m.group(2)
            if "...." not in title and i + 1 < toc_end:  # title wraps onto the next line
                title = title + " " + lines[i + 1].strip()
            types[m.group(1)] = {"title": _clean_title(title)}
        elif g:
            groups[g.group(1)] = _clean_title(g.group(2))
        i += 1

    # 2. Find each type's section in the body and read its "Security Category = {...}" line.
    body_start = sum(len(line) + 1 for line in lines[:toc_end])
    starts = {}
    for tid in types:
        m = re.compile(r"^\s*" + re.escape(tid) + r"\s+\S", re.M).search(text, body_start)
        if m is None:
            raise SystemExit(f"800-60: no section found for {tid}")
        starts[tid] = m.start()
    ordered = sorted(starts.values())

    records, not_categorized, discrepancies = [], [], []
    for tid, info in types.items():
        start = starts[tid]
        later = [s for s in ordered if s > start]
        section = text[start : later[0] if later else len(text)]
        group_id = tid.rsplit(".", 1)[0]
        base = {
            "id": tid,
            "title": info["title"],
            "appendix": "C" if tid.startswith("C") else "D",
            "group": group_id,
            "group_title": groups.get(group_id, ""),
        }
        m = _SECURITY_CATEGORY.search(section)
        if m is None:
            not_categorized.append(
                {**base, "reason": "SP 800-60 gives no provisional security category for this type."}
            )
            continue
        c, cf, i_, if_, a, af = m.groups()
        record = {
            **base,
            "confidentiality": _level(c),
            "integrity": _level(i_),
            "availability": _level(a),
            # A footnote number next to a level marks a documented exception or special factor.
            "footnoted": [obj for obj, f in (("confidentiality", cf), ("integrity", if_), ("availability", af)) if f],
        }
        # 3. Cross-check against the "Recommended X Impact Level: ... is <level>." sentences.
        for rec in _RECOMMENDED.finditer(section):
            objective = rec.group(1).lower()
            words = re.findall(r"\b(low|moderate|high|not applicable|n/a)\b", rec.group(2), re.IGNORECASE)
            if words and _level(words[-1]) != record[objective]:
                discrepancies.append(
                    {
                        "id": tid,
                        "objective": objective,
                        "security_category": record[objective],
                        "recommended_sentence": _level(words[-1]),
                    }
                )
        records.append(record)

    return {
        "dataset": "nist-sp800-60v2r1",
        "source": {
            "title": "NIST SP 800-60 Vol. 2 Rev. 1, Volume II: Appendices to Guide for Mapping Types of "
            "Information and Information Systems to Security Categories",
            "published": "2008-08",
            "status": "Final. Rev. 2 has been an initial working draft since January 2024 and is not used here.",
            "url": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-60v2r1.pdf",
            "doi": "https://doi.org/10.6028/NIST.SP.800-60v2r1",
            "sha256": sha256(SP800_60_PDF),
        },
        "generated_by": "tools/build_data.py",
        "notes": [
            "Impact levels are the provisional levels NIST recommends. Organizations review and adjust them.",
            "'footnoted' lists objectives whose level carries a footnote in the source "
            "(an exception or special factor).",
            "'source_discrepancies' lists places where the Security Category line and the 'Recommended ... "
            "Impact Level' sentence in the same section disagree; the Security Category line is used.",
        ],
        "counts": dict(Counter(r["appendix"] for r in records)),
        "information_types": records,
        "not_categorized": not_categorized,
        "source_discrepancies": discrepancies,
    }


# --- NIST SP 800-53 Rev. 5 / SP 800-53B ---------------------------------------------------------


def _profile_ids(path: Path) -> list[str]:
    profile = json.loads(path.read_text(encoding="utf-8"))["profile"]
    ids = []
    for imp in profile.get("imports", []):
        for sel in imp.get("include-controls", []):
            ids += sel.get("with-ids", [])
    return ids


def _catalog_titles(catalog: dict) -> dict[str, str]:
    titles = {}

    def walk(node):
        for control in node.get("controls", []):
            withdrawn = any(
                p.get("name") == "status" and p.get("value") == "withdrawn" for p in control.get("props", [])
            )
            titles[control["id"]] = control["title"] + (" (withdrawn)" if withdrawn else "")
            walk(control)
        for group in node.get("groups", []):
            walk(group)

    walk(catalog)
    return titles


def build_sp800_53b() -> dict:
    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))["catalog"]
    titles = _catalog_titles(catalog)
    baselines = {name: _profile_ids(path) for name, path in PROFILES.items()}
    for name, ids in baselines.items():
        unknown = [c for c in ids if c not in titles]
        if unknown:
            raise SystemExit(f"800-53B {name}: IDs not in the catalog: {unknown[:5]}")
    return {
        "dataset": "nist-sp800-53b-rev5",
        "source": {
            "title": "NIST SP 800-53 Rev. 5 catalog and SP 800-53B control baselines (OSCAL)",
            "catalog_version": catalog["metadata"]["version"],
            "repository": "https://github.com/usnistgov/oscal-content",
            "commit": OSCAL_CONTENT_COMMIT,
            "files": {p.name: sha256(p) for p in [CATALOG, *PROFILES.values()]},
        },
        "generated_by": "tools/build_data.py",
        "counts": {name: len(ids) for name, ids in baselines.items()},
        "baselines": baselines,
        "titles": dict(sorted(titles.items())),
    }


# --- main -----------------------------------------------------------------------------------


def build() -> dict[Path, str]:
    files = {
        DATA / "sp800_60v2r1.json": render(build_sp800_60()),
        DATA / "sp800_53b.json": render(build_sp800_53b()),
    }
    return files


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="fail if committed data differs from a fresh build")
    args = ap.parse_args(argv)
    files = build()
    if args.check:
        stale = [p for p, text in files.items() if not p.is_file() or p.read_text(encoding="utf-8") != text]
        for p in stale:
            print(f"out of date: {p.relative_to(ROOT)}", file=sys.stderr)
        return 1 if stale else 0
    DATA.mkdir(parents=True, exist_ok=True)
    for path, text in files.items():
        path.write_text(text, encoding="utf-8")
        print(f"wrote {path.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
