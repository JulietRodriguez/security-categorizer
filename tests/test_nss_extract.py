"""tools/build_nss_data.py on SYNTHETIC input: word positions built by hand, and a generated PDF.

These run everywhere. The checks against the real CNSSI 1253 PDF are in test_nss_data.py.
"""

import pytest
from tools import build_nss_data as b

COLS = [270.0, 289.0, 309.0, 328.0, 347.0, 367.0, 386.0, 406.0, 425.0]  # C L M H, I L M H, A L M H


def word(text, x, top, width=6.0):
    return {"text": text, "x0": x - width / 2, "x1": x + width / 2, "top": top, "bottom": top + 9}


def header(top=190.0):
    return [word(t, x, top) for t, x in zip("LMH" * 3, COLS, strict=True)]


def rule(y):
    return {"x0": 30.0, "x1": 760.0, "top": y, "height": 0.5}


def test_oscal_id():
    assert b.oscal_id("AC-2") == "ac-2"
    assert b.oscal_id("AC-2(12)") == "ac-2.12"
    assert b.oscal_id("SC-07(08)") == "sc-7.8"
    with pytest.raises(ValueError):
        b.oscal_id("Access")


def test_header_columns():
    assert b.header_columns(header()) == COLS
    assert b.header_columns(header()[:8]) is None
    assert b.header_columns([word("L", 10, 5)]) is None


def test_row_borders_merge_double_rules():
    assert b.row_borders([rule(100), rule(100.8), rule(130), {"x0": 300, "x1": 400, "top": 50, "height": 0.5}]) == [
        100,
        130,
    ]


def test_parse_page_by_row_borders_and_privacy_column():
    words = [
        *header(),
        word("AC-1", 40, 210),
        word("X", 220, 216),  # privacy column, a little below the ID (vertically centered)
        *[word("X", x, 210) for x in COLS],
        word("AC-2(4)", 45, 240),
        word("+", COLS[0], 240),
        word("X", COLS[1], 240),
        word("--", COLS[4], 246),
        word("AC-2(10)", 45, 270),
        word("Withdrawn", 300, 270, width=40),
    ]
    anomalies = []
    rows = b.parse_page(words, 25, 1, anomalies, [rule(200), rule(230), rule(260), rule(290)], b.header_columns(words))
    assert anomalies == []
    r = {x.id: x for x in rows}
    assert r["ac-1"].privacy == "X" and len(r["ac-1"].marks) == 9
    assert r["ac-2.4"].marks == {
        "confidentiality.low": "+",
        "confidentiality.moderate": "X",
        "integrity.moderate": "--",
    }
    assert r["ac-2.10"].withdrawn and not r["ac-2.10"].marks


def test_parse_page_without_borders_uses_text_lines_and_reports_strays():
    words = [
        *header(),
        word("AC-3", 40, 210),
        word("X", COLS[2], 210),
        word("X", COLS[2] + 10, 210),  # between two columns
        word("+", COLS[3], 225),  # on no ID's line
        word("X", 220, 210),
        word("+", 221, 210),  # second privacy mark
        word("X", COLS[2], 210.5),  # second mark in the same column
    ]
    anomalies = []
    rows = b.parse_page(words, 30, 1, anomalies, [], b.header_columns(words))
    assert rows[0].marks == {"confidentiality.high": "X"}
    problems = sorted(a["problem"] for a in anomalies)
    assert problems == [
        "mark is in the row of 0 control IDs",
        "mark is not under exactly one column",
        "two marks in confidentiality.high",
        "two marks in the privacy column",
    ]


def test_parse_page_falls_back_when_borders_do_not_separate_ids():
    words = [*header(), word("AC-5", 40, 210), word("AC-6", 40, 220), word("X", COLS[0], 220)]
    anomalies = []
    rows = b.parse_page(words, 31, 1, anomalies, [rule(200), rule(240)], b.header_columns(words))
    assert {r.id: r.marks for r in rows} == {"ac-5": {}, "ac-6": {"confidentiality.low": "X"}}
    assert anomalies[0]["problem"].startswith("row borders don't separate")


def test_parse_page_needs_columns():
    assert b.parse_page([word("AC-1", 40, 210)], 1, None, [], [], None) == []


def test_check_rows_flags_problems_instead_of_guessing():
    rows = [
        b.Row("ac-1", 1, 1, marks={"confidentiality.low": "X", "confidentiality.high": "X"}),  # gap at moderate
        b.Row("ac-1", 2, 1),
        b.Row("ac-9", 2, 1, withdrawn=True, marks={"integrity.low": "X"}),
        b.Row("ac-11", 2, 1, marks={"availability.moderate": "+", "availability.high": "X"}),
    ]
    anomalies = []
    by_id = b.check_rows(rows, anomalies)
    assert set(by_id) == {"ac-1", "ac-9", "ac-11"}
    problems = sorted(a["problem"] for a in anomalies)
    assert problems == [
        "confidentiality: selected at low, high only",
        "integrity: selected at low only",
        "listed again (first on page 1)",
        "withdrawn but marked",
    ]


def test_compare_with_sp800_53b():
    nist = {
        "source": {"catalog_version": "9.9.9"},
        "baselines": {"low": ["ac-1"], "moderate": ["ac-1", "ac-2"], "high": ["ac-1", "ac-2"], "privacy": ["pt-1"]},
        "titles": {"ac-1": "", "ac-2": "", "ac-3": "", "pt-1": "", "zz-1": ""},
    }
    controls = {
        "ac-1": b.Row("ac-1", 1, 1, marks={f"confidentiality.{lv}": "X" for lv in b.LEVELS}),
        "ac-2": b.Row("ac-2", 1, 1, marks={"integrity.moderate": "+", "integrity.high": "--"}),
        "ac-3": b.Row("ac-3", 1, 1, marks={"availability.low": "X"}, privacy="X"),
        "pt-1": b.Row("pt-1", 1, 1),
    }
    issues = {(i["control"], i["level"]) for i in b.compare_with_sp800_53b(controls, nist)}
    assert issues == {
        ("ac-2", "moderate"),  # NIST moderate, marked + not X
        ("ac-3", "low"),  # X but not in NIST low
        ("ac-3", "privacy"),  # X for privacy, not in NIST privacy
        ("pt-1", "privacy"),  # NIST privacy, not marked
        ("zz-1", None),  # in the catalog, not listed
    }


def _synthetic_pdf(path):
    canvas = pytest.importorskip("reportlab.pdfgen.canvas")
    c = canvas.Canvas(str(path), pagesize=(792, 612))

    def text(s, x, top):
        c.drawString(x, 612 - top - 8, s)

    def hrule(top):
        c.rect(30, 612 - top, 730, 0.5, stroke=0, fill=1)

    def page(title, rows, with_header=True):
        c.setFont("Helvetica", 8)
        if title:
            text(title, 300, 70)
        if with_header:
            for t, x in zip("LMH" * 3, COLS, strict=True):
                text(t, x - 2, 190)
        top = 210.0
        hrule(top - 8)
        for rid, marks in rows:
            text(rid, 35, top)
            for x, m in marks:
                text(m, x - 2, top)
            hrule(top + 18)
            top += 26
        c.showPage()

    page("Front matter. Table D-1: Access Control (AC) Family ........ D-4", [], with_header=False)
    page(
        "Table D-1: Access Control (AC) Family",
        [("AC-1", [(220, "X"), *[(x, "X") for x in COLS]]), ("AC-2", [(x, "+") for x in COLS[:3]])],
    )
    page(None, [("AC-2(1)", [(x, "X") for x in COLS[3:6]])], with_header=False)  # continuation page without a header
    page("Table D-2: Awareness and Training (AT) Family", [("AT-1", [(x, "X") for x in COLS])])
    c.save()


def test_build_on_a_synthetic_pdf(tmp_path, monkeypatch):
    pytest.importorskip("pdfplumber")
    pdf = tmp_path / "SYNTHETIC.pdf"
    _synthetic_pdf(pdf)
    monkeypatch.setattr(b, "EXPECTED_TABLES", 2)
    out = tmp_path / "data.json"
    assert b.main([str(pdf), "-o", str(out)]) == 0
    import json

    data = json.loads(out.read_text())
    assert data["source"]["matches_expected_sha256"] is False
    assert data["pages_without_table_header"] == [3]
    assert data["anomalies"] == []
    assert data["counts"]["controls_listed"] == 4
    assert data["baselines"]["confidentiality"]["low"] == ["ac-1", "ac-2", "at-1"]
    assert data["baselines"]["integrity"]["low"] == ["ac-1", "ac-2.1", "at-1"]
    assert data["privacy_baseline"] == ["ac-1"]
    assert data["added_for_nss"] == ["ac-2"]
    assert data["controls"]["ac-2.1"]["page"] == 3
    # every SP 800-53 control the synthetic tables don't list is reported, none guessed
    assert any(d["control"] == "si-4" for d in data["source_discrepancies"])
