"""CNSSI 1253 Appendix D data, built from the real PDF, checked against the document and SP 800-53B.

CNSSI 1253 has no distribution statement, so the PDF is not in this repository and these
tests are skipped unless you point them at your copy:

    CNSSI_1253_PDF=/path/to/CNSSI_1253.pdf pytest tests/test_nss_data.py

The numbers pinned here were read from the PDF with SHA-256 d876741d...1180 (CNSSI No. 1253,
29 July 2022) and checked three ways: a second, independent table reader (pdfplumber's
ruled-grid tables) finds the same control rows; every "X" and "--" mark agrees with the
SP 800-53B baselines except the discrepancies listed below; and the spot-checked rows were
compared with the rendered page by eye.
"""

import json
import os
import re
from pathlib import Path

import pytest

from security_categorizer.baseline import select_baseline
from security_categorizer.cli import main
from security_categorizer.datasets import VERIFIED_CNSSI_1253, load_nss_data, sp800_53b

PDF = os.environ.get("CNSSI_1253_PDF")
pytestmark = pytest.mark.skipif(not PDF, reason="set CNSSI_1253_PDF to your copy of CNSSI 1253 (not distributed)")

LEVELS = ("low", "moderate", "high")
OBJECTIVES = ("confidentiality", "integrity", "availability")

# Rows per family in Tables D-1 to D-20 (withdrawn rows included), and how many are withdrawn.
FAMILY_ROWS = {
    "ac": (147, 16), "at": (17, 2), "au": (69, 13), "ca": (32, 7), "cm": (66, 10), "cp": (56, 7), "ia": (70, 15),
    "ir": (42, 2), "ma": (30, 2), "mp": (30, 10), "pe": (59, 8), "pl": (17, 6), "pm": (37, 0), "ps": (18, 1),
    "pt": (21, 0), "ra": (26, 4), "sa": (145, 39), "sc": (162, 23), "si": (118, 17), "sr": (27, 0),
}  # fmt: skip

# Controls selected ("X" or "+") per family, per column: C L/M/H, I L/M/H, A L/M/H, privacy.
FAMILY_COLUMNS = {
    "ac": (45, 55, 60, 41, 49, 54, 3, 4, 5, 2), "at": (10, 10, 12, 10, 10, 12, 10, 10, 12, 6),
    "au": (14, 16, 19, 16, 23, 28, 8, 9, 11, 7), "ca": (11, 14, 18, 11, 14, 18, 9, 11, 15, 6),
    "cm": (8, 10, 11, 26, 38, 43, 0, 2, 2, 2), "cp": (3, 3, 3, 3, 4, 4, 7, 24, 37, 1),
    "ia": (29, 32, 34, 29, 32, 34, 0, 0, 0, 1), "ir": (19, 27, 30, 16, 24, 28, 16, 25, 29, 11),
    "ma": (8, 8, 10, 13, 15, 17, 3, 5, 7, 0), "mp": (7, 7, 10, 3, 3, 3, 0, 0, 0, 1),
    "pe": (9, 13, 15, 7, 10, 12, 11, 18, 24, 4), "pl": (10, 10, 10, 10, 10, 10, 9, 9, 9, 7),
    "pm": (0, 0, 0, 0, 0, 0, 0, 0, 0, 28), "ps": (12, 12, 13, 9, 9, 10, 6, 6, 7, 4),
    "pt": (0, 0, 0, 0, 0, 0, 0, 0, 0, 1), "ra": (13, 14, 15, 13, 14, 15, 13, 14, 15, 4),
    "sa": (17, 23, 58, 21, 27, 65, 15, 21, 56, 4), "sc": (27, 31, 36, 37, 42, 48, 8, 10, 12, 1),
    "si": (17, 19, 21, 31, 41, 51, 15, 19, 20, 2), "sr": (14, 15, 22, 14, 15, 22, 14, 15, 22, 1),
}  # fmt: skip

ALL_X = {f"{o}.{lv}": "X" for o in OBJECTIVES for lv in LEVELS}
ALL_PLUS = {f"{o}.{lv}": "+" for o in OBJECTIVES for lv in LEVELS}
# Rows compared with the rendered page.
SPOT_CHECKS = {
    "ac-1": (ALL_X, "X"),
    "ac-2": ({f"{o}.{lv}": "X" for o in OBJECTIVES[:2] for lv in LEVELS}, None),
    "ac-2.5": ({**ALL_X, **{f"{o}.low": "+" for o in OBJECTIVES}}, None),
    "ac-2.11": ({f"{o}.high": "X" for o in OBJECTIVES}, None),
    "au-12": ({f"{o}.{lv}": "X" for o in OBJECTIVES[:2] for lv in LEVELS}, "+"),
    "ia-12.5": ({f"{o}.{lv}": "--" for o in OBJECTIVES[:2] for lv in ("moderate", "high")}, None),
    "pm-1": ({}, "+"),
    "pt-2": ({}, "--"),
    "sc-16": ({f"{o}.{lv}": "+" for o in OBJECTIVES[:2] for lv in ("moderate", "high")}, None),
    "sc-18.2": ({f"integrity.{lv}": "+" for lv in LEVELS}, None),
    "si-4.22": (ALL_PLUS, None),
}

DISCREPANCIES = {
    ("sa-15", "moderate"), ("sc-7.8", "moderate"), ("si-4.22", "high"),
    ("ia-13", None), ("ia-13.1", None), ("ia-13.2", None), ("ia-13.3", None), ("sa-15.13", None), ("sa-24", None),
    ("si-2.7", None),
}  # fmt: skip


@pytest.fixture(scope="module")
def built(tmp_path_factory):
    from tools import build_nss_data

    out = tmp_path_factory.mktemp("nss") / "cnssi-1253-appendix-d.json"
    assert build_nss_data.main([PDF, "-o", str(out)]) == 0
    return out, json.loads(out.read_text())


def test_source_is_the_verified_copy(built):
    _, d = built
    assert d["source"]["sha256"] == VERIFIED_CNSSI_1253["sha256"]
    assert d["source"]["date"] == "29 July 2022"


def test_nothing_unresolved(built):
    _, d = built
    assert d["anomalies"] == []
    assert d["pages_without_table_header"] == [136]  # SC-18(2) and SC-18(3) continue from page 135


def test_totals_match_the_verified_counts(built):
    _, d = built
    assert d["counts"]["controls_listed"] == VERIFIED_CNSSI_1253["controls_listed"]
    assert d["counts"]["withdrawn"] == 182
    assert d["counts"]["baselines"] == VERIFIED_CNSSI_1253["baselines"]
    assert d["counts"]["privacy_baseline"] == VERIFIED_CNSSI_1253["privacy_baseline"]
    assert sum(v["listed"] for v in d["counts"]["per_family"].values()) == 1189


def test_per_family_counts(built):
    _, d = built
    assert {f: (v["listed"], v["withdrawn"]) for f, v in d["counts"]["per_family"].items()} == FAMILY_ROWS
    keys = [f"{o}.{lv}" for o in OBJECTIVES for lv in LEVELS]
    got = {}
    for cid, row in d["controls"].items():
        fam = cid.split("-")[0]
        counts = got.setdefault(fam, [0] * 10)
        for i, k in enumerate(keys):
            counts[i] += row["marks"].get(k) in ("X", "+")
        counts[9] += row["privacy"] in ("X", "+")
    assert {f: tuple(c) for f, c in got.items()} == FAMILY_COLUMNS


@pytest.mark.parametrize("control", sorted(SPOT_CHECKS))
def test_spot_checks(built, control):
    _, d = built
    marks, privacy = SPOT_CHECKS[control]
    assert d["controls"][control]["marks"] == marks
    assert d["controls"][control]["privacy"] == privacy


def test_x_and_dash_marks_agree_with_sp800_53b(built):
    """The legend: "X" = from the SP 800-53B baseline, "--" = in it but not selected for NSS."""
    _, d = built
    assert {(x["control"], x["level"]) for x in d["source_discrepancies"]} == DISCREPANCIES
    nist = sp800_53b()["baselines"]
    for lv in LEVELS:
        assert set().union(*(d["baselines"][o][lv] for o in OBJECTIVES)) >= set(nist[lv]) - {"ia-12.5"}
    privacy_dash = set(d["nist_not_selected_for_nss"]["privacy"])
    assert set(d["privacy_baseline"]) | privacy_dash >= set(nist["privacy"])
    assert len(privacy_dash) == 27  # left to the Privacy Overlay


def test_columns_are_cumulative(built):
    _, d = built
    for o in OBJECTIVES:
        low, mod, high = (set(d["baselines"][o][lv]) for lv in LEVELS)
        assert low <= mod <= high


def test_an_independent_reader_finds_the_same_rows(built):
    """pdfplumber's ruled-grid table extraction, not the word positions build_nss_data uses."""
    import pdfplumber

    _, d = built
    pat = re.compile(r"^([A-Z]{2})-(\d+)(?:\((\d+)\))?$")
    pages = sorted({r["page"] for r in d["controls"].values()})
    ids = set()
    with pdfplumber.open(PDF) as pdf:
        for n in range(pages[0], pages[-1] + 1):
            for table in pdf.pages[n - 1].extract_tables():
                for row in table:
                    for cell in row[:3]:
                        m = pat.match((cell or "").strip())
                        if m:
                            f, num, enh = m.groups()
                            ids.add(f"{f.lower()}-{int(num)}" + (f".{int(enh)}" if enh else ""))
    assert ids == set(d["controls"])


def test_loader_accepts_it_and_selection_uses_the_three_columns(built, run):
    path, _ = built
    data = load_nss_data(path)
    cat = run([{"custom": {"id": "T", "title": "t", "confidentiality": "high", "integrity": "moderate",
                           "availability": "low"}}], mode="nss")  # fmt: skip
    sel = select_baseline(cat, data)
    assert len(sel.controls) == 543
    assert "its control counts match" in " ".join(sel.notes)
    hhh = select_baseline(run([{"custom": {"id": "T", "title": "t", "confidentiality": "high",
                                           "integrity": "high", "availability": "high"}}], mode="nss"), data)  # fmt: skip
    assert len(hhh.controls) == 607  # what a single high-water mark would select


def test_nss_sample_end_to_end(built, tmp_path):
    from tools.validate_oscal import main as validate

    path, _ = built
    root = Path(__file__).resolve().parents[1]
    out = tmp_path / "nss"
    assert (
        main(["categorize", str(root / "samples" / "nss" / "system.yaml"), "--nss-data", str(path), "-o", str(out)])
        == 0
    )
    profile = json.loads((out / "baseline-profile.json").read_text())["profile"]
    assert len(profile["imports"][0]["include-controls"][0]["with-ids"]) == 543
    assert validate(["--schema-dir", str(root / "schemas"), str(out / "baseline-profile.json")]) == 0
