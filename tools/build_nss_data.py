"""Extract the CNSSI 1253 (2022) Appendix D control baselines from your own copy of the PDF.

    python tools/build_nss_data.py CNSSI_1253.pdf -o cnssi-1253-appendix-d.json
    security-categorizer categorize system.yaml --nss-data cnssi-1253-appendix-d.json -o out/

CNSSI 1253 has no distribution statement, so neither the PDF nor data extracted from it is
committed to this repository. Run this script on a copy you obtained from https://www.cnss.gov.

How it reads the tables (Tables D-1 to D-20):

* Each table page has a header row with nine "L M H" cells: low, moderate and high under
  confidentiality, integrity and availability. Their x positions give the nine columns.
* Each control row starts with its ID (for example AC-2(4)) in the left column. A mark
  ("X" = from the SP 800-53B baseline, "+" = added for NSS, "--" = in the NIST baseline but
  not the NSS one) belongs to the row whose ruled borders contain it. Where a page has no
  row borders, the mark must sit on the same text line as the ID.
* The Privacy Control Baseline column is the one marked column to the left of the nine.

The output records the PDF's SHA-256, the counts per column and per family, and every
problem the script could not resolve ("anomalies"). Nothing is guessed: a mark that can't
be placed in exactly one column is reported, not assigned. The tool's tests check the
result against the SP 800-53B baselines (tests/test_nss_data.py).

Needs pdfplumber (pinned in the "nss" extra): pip install "security-categorizer[nss]".
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

OBJECTIVES = ("confidentiality", "integrity", "availability")
LEVELS = ("low", "moderate", "high")
MARKS = {"X", "+", "--"}
EXPECTED_SHA256 = "d876741dfb78c54cf21e1f8f966475bddb9df0d3fc8e935e5350862c246d1180"
EXPECTED_TABLES = 20

_ID = re.compile(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$")
_TABLE = re.compile(r"Table D-(\d+):")
SP800_53B = Path(__file__).resolve().parents[1] / "src" / "security_categorizer" / "data" / "sp800_53b.json"
ID_MAX_X = 90.0  # control IDs sit in the leftmost column
SAME_LINE = 2.5  # points: a mark belongs to the ID on the same text line
COLUMN_TOLERANCE = 7.0  # points from a column's center


def oscal_id(text: str) -> str:
    m = _ID.match(text)
    if not m:
        raise ValueError(text)
    family, number, enhancement = m.groups()
    return f"{family.lower()}-{int(number)}" + (f".{int(enhancement)}" if enhancement else "")


@dataclass
class Row:
    id: str
    page: int
    table: int | None
    withdrawn: bool = False
    marks: dict[str, str] = field(default_factory=dict)  # "confidentiality.low" -> "X" / "+" / "--"
    privacy: str | None = None


def header_columns(words: list[dict]) -> list[float] | None:
    """x centers of the nine L/M/H header cells, left to right, or None if the page has none."""
    by_line: dict[int, list[dict]] = defaultdict(list)
    for w in words:
        if w["text"] in ("L", "M", "H"):
            by_line[round(w["top"])].append(w)
    for line in by_line.values():
        line.sort(key=lambda w: w["x0"])
        if [w["text"] for w in line] == ["L", "M", "H"] * 3:
            return [(w["x0"] + w["x1"]) / 2 for w in line]
    return None


def row_borders(rects: list[dict]) -> list[float]:
    """y positions of the table's horizontal rules that cross the ID column."""
    ys = sorted({round(r["top"], 1) for r in rects if r["height"] < 1.5 and r["x0"] < 40 < r["x1"]})
    merged: list[float] = []
    for y in ys:  # a rule drawn as two thin rectangles counts once
        if not merged or y - merged[-1] > 2.0:
            merged.append(y)
    return merged


def _band(y: float, borders: list[float]) -> int | None:
    for i in range(len(borders) - 1):
        if borders[i] <= y < borders[i + 1]:
            return i
    return None


def parse_page(
    words: list[dict],
    page_no: int,
    table: int | None,
    anomalies: list[dict],
    rects: list[dict] | None = None,
    columns: list[float] | None = None,
) -> list[Row]:
    """Rows on one table page. ``columns`` comes from the page's own header, or (for a page
    that doesn't repeat the header) from the previous page of the same table."""
    if columns is None:
        return []
    keys = [f"{o}.{lv}" for o in OBJECTIVES for lv in LEVELS]
    spacing = columns[1] - columns[0]
    privacy_range = (columns[0] - 4 * spacing, columns[0] - spacing / 2)
    header_words = [w for w in words if w["text"] in ("L", "M", "H")]
    header_bottom = max((w["bottom"] for w in header_words), default=0.0) if header_columns(words) else 0.0

    ids = [w for w in words if w["top"] > header_bottom and w["x0"] < ID_MAX_X and _ID.match(w["text"])]
    rows = [Row(id=oscal_id(w["text"]), page=page_no, table=table) for w in ids]
    tops = [w["top"] for w in ids]
    borders = row_borders(rects or [])
    id_bands = [_band(t, borders) for t in tops] if len(borders) > 1 else None
    if id_bands is not None and (None in id_bands or len(set(id_bands)) != len(id_bands)):
        anomalies.append({"page": page_no, "problem": "row borders don't separate the control IDs; used text lines"})
        id_bands = None

    def owners(top: float) -> list[int]:
        if id_bands is None:
            return [i for i, t in enumerate(tops) if abs(t - top) <= SAME_LINE]
        band = _band(top, borders)
        return [i for i, b in enumerate(id_bands) if b == band and band is not None]

    for w in words:
        if w["top"] <= header_bottom:
            continue
        text = w["text"]
        if text not in MARKS and text != "Withdrawn":
            continue
        near = owners(w["top"])
        if text == "Withdrawn":
            if len(near) == 1:
                rows[near[0]].withdrawn = True
            continue
        center = (w["x0"] + w["x1"]) / 2
        where = {"page": page_no, "text": text, "x": round(center, 1), "top": round(w["top"], 1)}
        if len(near) != 1:
            anomalies.append({**where, "problem": f"mark is in the row of {len(near)} control IDs"})
            continue
        row = rows[near[0]]
        if privacy_range[0] <= center <= privacy_range[1]:
            if row.privacy is not None:
                anomalies.append({**where, "control": row.id, "problem": "two marks in the privacy column"})
            row.privacy = text
            continue
        hits = [k for k, c in zip(keys, columns, strict=True) if abs(c - center) <= COLUMN_TOLERANCE]
        if len(hits) != 1:
            anomalies.append({**where, "control": row.id, "problem": "mark is not under exactly one column"})
            continue
        if hits[0] in row.marks:
            anomalies.append({**where, "control": row.id, "problem": f"two marks in {hits[0]}"})
        row.marks[hits[0]] = text
    return rows


def read_pdf(path: Path) -> tuple[list[Row], list[dict], list[int], list[int]]:
    import pdfplumber

    rows: list[Row] = []
    anomalies: list[dict] = []
    tables_seen: list[int] = []
    carried: list[int] = []  # pages that used the previous page's column positions
    table: int | None = None
    columns: list[float] | None = None
    with pdfplumber.open(str(path)) as pdf:
        for i, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            m = _TABLE.search(text)
            if m and "...." not in text:  # skip the list of tables in the front matter
                table = int(m.group(1))
                tables_seen.append(table)
            words = page.extract_words()
            own = header_columns(words)
            if own is not None:
                columns = own
            elif table is None or not any(_ID.match(w["text"]) and w["x0"] < ID_MAX_X for w in words):
                continue
            else:
                carried.append(i)
            rows.extend(parse_page(words, i, table, anomalies, page.rects, columns))
            if table is not None and "Appendix E" in text and "Overlays" in text and not own:
                break
    return rows, anomalies, tables_seen, carried


def check_rows(rows: list[Row], anomalies: list[dict]) -> dict[str, Row]:
    by_id: dict[str, Row] = {}
    for r in rows:
        if r.id in by_id:
            anomalies.append(
                {"control": r.id, "page": r.page, "problem": f"listed again (first on page {by_id[r.id].page})"}
            )
            continue
        by_id[r.id] = r
        if r.withdrawn and (r.marks or r.privacy):
            anomalies.append({"control": r.id, "page": r.page, "problem": "withdrawn but marked"})
        for obj in OBJECTIVES:
            selected = [lv for lv in LEVELS if r.marks.get(f"{obj}.{lv}") in ("X", "+")]
            # A control selected at a lower level and missing at a higher one is unusual.
            if selected and selected != list(LEVELS[LEVELS.index(selected[0]) :]):
                anomalies.append(
                    {"control": r.id, "page": r.page, "problem": f"{obj}: selected at {', '.join(selected)} only"}
                )
    return by_id


def compare_with_sp800_53b(controls: dict[str, Row], nist: dict) -> list[dict]:
    """Places where Appendix D's marks disagree with its own legend, checked against SP 800-53B.

    The legend says "X" marks a control from the SP 800-53B baseline, "+" one added for NSS, and
    "--" one in the NIST baseline that the NSS baseline leaves out. So, at each impact level, the
    controls marked "X" or "--" in any column should be exactly NIST's baseline for that level.
    Anything else is recorded here, not corrected.
    """
    out: list[dict] = []
    for lv in LEVELS:
        baseline = set(nist["baselines"][lv])
        marked = {cid: {r.marks.get(f"{o}.{lv}") for o in OBJECTIVES} - {None} for cid, r in controls.items()}
        x_or_dash = {cid for cid, m in marked.items() if m & {"X", "--"}}
        for cid in sorted(x_or_dash - baseline):
            out.append({"control": cid, "level": lv, "issue": f"marked X or -- at {lv}, but not in SP 800-53B {lv}"})
        for cid in sorted(baseline - x_or_dash):
            got = "+" if "+" in marked.get(cid, set()) else "not marked"
            out.append(
                {
                    "control": cid,
                    "level": lv,
                    "issue": f"in the SP 800-53B {lv} baseline (catalog {nist['source']['catalog_version']}) "
                    f"but marked {got} at {lv}, not X. Either NIST's baseline changed after July 2022 or the "
                    "mark doesn't follow the legend. The control is selected either way when marked +.",
                }
            )
    privacy = set(nist["baselines"]["privacy"])
    p_marked = {cid for cid, r in controls.items() if r.privacy in ("X", "--")}
    for cid in sorted(p_marked - privacy):
        out.append(
            {"control": cid, "level": "privacy", "issue": "marked X or -- for privacy, not in SP 800-53B Privacy"}
        )
    for cid in sorted(privacy - p_marked):
        out.append(
            {"control": cid, "level": "privacy", "issue": "in SP 800-53B Privacy, not marked X or -- for privacy"}
        )
    for cid in sorted(set(nist["titles"]) - set(controls)):
        out.append(
            {
                "control": cid,
                "level": None,
                "issue": f"in the SP 800-53 catalog {nist['source']['catalog_version']} but not listed in "
                "Appendix D, which is older (29 July 2022); never selected by this data",
            }
        )
    return out


def build(path: Path) -> dict:
    digest = hashlib.sha256(path.read_bytes()).hexdigest()
    rows, anomalies, tables_seen, carried = read_pdf(path)
    by_id = check_rows(rows, anomalies)
    if sorted(set(tables_seen)) != list(range(1, EXPECTED_TABLES + 1)):
        anomalies.append({"problem": f"found tables {sorted(set(tables_seen))}, expected D-1 to D-{EXPECTED_TABLES}"})

    baselines = {o: {lv: [] for lv in LEVELS} for o in OBJECTIVES}
    not_selected = {o: {lv: [] for lv in LEVELS} for o in OBJECTIVES}
    privacy, privacy_not_selected, added_for_nss = [], [], []
    for cid, r in by_id.items():
        for key, mark in r.marks.items():
            obj, lv = key.split(".")
            (not_selected if mark == "--" else baselines)[obj][lv].append(cid)
        if r.privacy in ("X", "+"):
            privacy.append(cid)
        elif r.privacy == "--":
            privacy_not_selected.append(cid)
        if "+" in r.marks.values() or r.privacy == "+":
            added_for_nss.append(cid)

    per_family: dict[str, Counter] = defaultdict(Counter)
    for cid, r in by_id.items():
        fam = cid.split("-")[0]
        per_family[fam]["listed"] += 1
        per_family[fam]["withdrawn"] += r.withdrawn
        per_family[fam]["selected"] += any(m in ("X", "+") for m in r.marks.values()) or r.privacy in ("X", "+")

    return {
        "dataset": "cnssi-1253-2022-appendix-d",
        "source": {
            "title": "CNSSI No. 1253, Categorization and Control Selection for National Security Systems",
            "date": "29 July 2022",
            "issuer": "Committee on National Security Systems",
            "file": path.name,
            "sha256": digest,
            "matches_expected_sha256": digest == EXPECTED_SHA256,
        },
        "generated_by": "tools/build_nss_data.py (security-categorizer)",
        "baselines": baselines,
        "privacy_baseline": privacy,
        "nist_not_selected_for_nss": {"security": not_selected, "privacy": privacy_not_selected},
        "added_for_nss": added_for_nss,
        "controls": {
            cid: {"table": r.table, "page": r.page, "withdrawn": r.withdrawn, "marks": r.marks, "privacy": r.privacy}
            for cid, r in by_id.items()
        },
        "counts": {
            "controls_listed": len(by_id),
            "withdrawn": sum(r.withdrawn for r in by_id.values()),
            "baselines": {o: {lv: len(baselines[o][lv]) for lv in LEVELS} for o in OBJECTIVES},
            "privacy_baseline": len(privacy),
            "per_family": {f: dict(c) for f, c in sorted(per_family.items())},
        },
        "pages_without_table_header": carried,
        "source_discrepancies": compare_with_sp800_53b(by_id, json.loads(SP800_53B.read_text(encoding="utf-8"))),
        "anomalies": anomalies,
    }


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("pdf", type=Path, help="your copy of the CNSSI 1253 (29 July 2022) PDF")
    p.add_argument("-o", "--out", type=Path, default=Path("cnssi-1253-appendix-d.json"))
    args = p.parse_args(argv)
    data = build(args.pdf)
    args.out.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    c = data["counts"]
    print(f"wrote {args.out}: {c['controls_listed']} controls listed ({c['withdrawn']} withdrawn)")
    for obj in OBJECTIVES:
        print(f"  {obj:<16}" + "  ".join(f"{lv} {c['baselines'][obj][lv]}" for lv in LEVELS))
    print(f"  privacy baseline {c['privacy_baseline']}")
    if not data["source"]["matches_expected_sha256"]:
        print(
            f"note: SHA-256 {data['source']['sha256']} is not the copy this script was checked against", file=sys.stderr
        )
    if data["source_discrepancies"]:
        print(f"{len(data['source_discrepancies'])} source discrepancies recorded (see source_discrepancies)")
    if data["anomalies"]:
        print(f"{len(data['anomalies'])} anomalies recorded in the output; review them before use", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
