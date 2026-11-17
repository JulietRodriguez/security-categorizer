import json

import pytest

from security_categorizer.baseline import control_sort_key, display_id, select_baseline
from security_categorizer.datasets import DataError, load_info_types, load_nss_data
from security_categorizer.oscal import SP800_60_SYSTEM, baseline_profile, ssp_shell, system_characteristics
from security_categorizer.report import baseline_text, to_dict, to_markdown
from tests.conftest import NSS_DATA, SCHEMAS

TS = "2026-11-17T12:00:00+00:00"


def validate(doc, schema_name):
    from tools.validate_oscal import validator

    return [e.message for e in validator(SCHEMAS / schema_name).iter_errors(doc)]


# --- baseline selection -----------------------------------------------------------------------------


@pytest.mark.parametrize(("types", "name", "count"), [(["C.2.1.1"], "Low", 149), (["C.3.5.8"], "Moderate", 287),
                                                       (["D.4.1"], "High", 370)])  # fmt: skip
def test_federal_baseline_follows_high_water(run, types, name, count):
    sel = select_baseline(run(types))
    assert sel.name == f"SP 800-53B {name}"
    assert len(sel.controls) == count


def test_pii_adds_privacy_baseline(run):
    sel = select_baseline(run(["C.3.5.8"], processes_pii=True))
    assert sel.name == "SP 800-53B Moderate + Privacy"
    assert len(sel.controls) == 340  # 287 security + 96 privacy, with overlap
    assert "pt-2" in sel.controls
    assert sel.controls == sorted(sel.controls, key=control_sort_key)


def test_nss_without_data_selects_nothing_and_says_why(run):
    sel = select_baseline(run(["C.3.5.8"], mode="nss"))
    assert sel.controls == []
    assert "not bundled" in sel.notes[0]


def test_nss_with_data_unions_the_three_columns(run):
    cat = run([{"custom": {"id": "X", "title": "x", "confidentiality": "high", "integrity": "moderate",
                           "availability": "low"}}], mode="nss", processes_pii=True)  # fmt: skip
    sel = select_baseline(cat, load_nss_data(NSS_DATA))
    assert sel.controls == ["ac-1", "ac-2", "ac-3", "ac-4", "cp-1", "pt-1", "si-1", "si-2"]
    assert sel.pending_overlays == ["Privacy Overlay"]
    assert "Privacy Overlay" in sel.notes[-1]


def test_nss_data_validation(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"baselines": {}, "privacy_baseline": [], "source": {"date": "x"}}))
    with pytest.raises(DataError, match="not valid CNSSI 1253 baseline data"):
        load_nss_data(bad)
    with pytest.raises(DataError, match="not found"):
        load_nss_data(tmp_path / "missing.json")


def test_display_and_sort():
    assert display_id("ac-2.1") == "AC-2(1)" and display_id("pm-30") == "PM-30" and display_id("x") == "X"
    assert sorted(["ac-10", "ac-2.1", "ac-2"], key=control_sort_key) == ["ac-2", "ac-2.1", "ac-10"]
    assert control_sort_key("odd") == ("odd", 0, 0)


# --- reports ----------------------------------------------------------------------------------------


def test_json_report(run, catalog):
    cat = run(["C.3.5.8", "D.4.1"])
    d = to_dict(cat, select_baseline(cat), catalog)
    assert d["overall_impact_level"] == "high"
    assert d["security_category"] == {"confidentiality": "moderate", "integrity": "high", "availability": "high"}
    assert d["baseline"]["control_count"] == 370
    assert "task C-2" in d["approval"]
    assert d["data"]["information_types"] == "nist-sp800-60v2r1"


def test_markdown_report_federal(run, catalog):
    cat = run([{"id": "C.3.5.8", "adjustments": [{"objective": "availability", "level": "moderate",
                                                  "justification": "SOC | uptime"}]}],
              system_adjustments=[{"objective": "integrity", "level": "high", "justification": "agg"}])  # fmt: skip
    md = to_markdown(cat, select_baseline(cat), catalog)
    assert "## Result: High system (FIPS 199 / FIPS 200)" in md
    assert "**DRAFT.**" in md
    assert "SOC \\| uptime" in md
    assert "**System integrity**: Moderate → High (raised)" in md
    assert "baseline-profile.json" in md


def test_markdown_report_nss(run, catalog):
    cat = run(["C.3.1.1"], mode="nss")
    md = to_markdown(cat, select_baseline(cat), catalog)
    assert "## Result: L-L-L (CNSSI 1253)" in md
    assert "no controls selected" in md
    assert "## Review notes" in md
    d = to_dict(cat, select_baseline(cat), catalog)
    assert d["cnssi_1253_categorization"] == "L-L-L" and "overall_impact_level" not in d


def test_baseline_text(run):
    text = baseline_text(select_baseline(run(["C.2.1.1"])))
    lines = text.splitlines()
    assert lines[0].startswith("# SP 800-53B Low: 149 controls")
    assert lines[1].split()[0] == "AC-1" and len(lines) == 150


# --- OSCAL ---------------------------------------------------------------------------------------------


def test_profile_is_schema_valid(run):
    cat = run(["C.3.5.8"], processes_pii=True)
    sel = select_baseline(cat)
    prof = baseline_profile(cat, sel, TS)
    assert validate(prof, "oscal_profile_schema.json") == []
    assert prof["profile"]["imports"][0]["include-controls"][0]["with-ids"] == sel.controls
    assert prof == baseline_profile(cat, sel, TS)  # deterministic


def test_system_characteristics_impacts_and_validity(run):
    cat = run(
        [
            {"id": "C.3.5.8", "adjustments": [{"objective": "availability", "level": "moderate", "justification": "j1"}]},
            {"custom": {"id": "ORG", "title": "Org type", "confidentiality": "n/a", "integrity": "low",
                        "availability": "low"}},
        ],
        mode="nss",
    )  # fmt: skip
    frag = system_characteristics(cat, "desc")
    first, second = frag["system-information"]["information-types"]
    assert first["categorizations"] == [{"system": SP800_60_SYSTEM, "information-type-ids": ["C.3.5.8"]}]
    assert first["availability-impact"] == {
        "base": "fips-199-low",
        "selected": "fips-199-moderate",
        "adjustment-justification": "j1",
    }
    assert "categorizations" not in second and second["confidentiality-impact"] == {"base": "not-applicable"}
    assert frag["security-impact-level"]["security-objective-availability"] == "fips-199-moderate"
    props = {p["name"]: p["value"] for p in frag["props"]}
    assert props["cnssi-1253-categorization"] == "M-M-M"
    assert validate(ssp_shell(frag, cat.system_name, TS), "oscal_ssp_schema.json") == []


def test_system_level_adjustment_recorded_in_props(run):
    cat = run(["C.3.5.8"], system_adjustments=[{"objective": "availability", "level": "high", "justification": "j"}])
    props = {p["name"]: p["value"] for p in system_characteristics(cat)["props"]}
    assert props["system-level-adjustments"] == "availability low->high: j"


# --- swappable dataset --------------------------------------------------------------------------------


def test_custom_info_type_dataset(tmp_path):
    f = tmp_path / "rev2.json"
    f.write_text(json.dumps({"dataset": "draft-rev2", "information_types": [
        {"id": "X.1", "title": "New type", "confidentiality": "high", "integrity": "low", "availability": "low"}]}))  # fmt: skip
    cat = load_info_types(f)
    assert cat.name == "draft-rev2" and cat.get("x.1".upper()).confidentiality.value == "high"
    assert [t.id for t in cat.search("new")] == ["X.1"]


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{bad", "not valid JSON"),
        ({"information_types": []}, "non-empty"),
        ({"information_types": [{"id": "a"}]}, "is invalid"),
        (
            {"information_types": [{"id": "a", "title": "t", "confidentiality": "low", "integrity": "low",
                                    "availability": "low"}] * 2},
            "duplicate",
        ),
    ],
)  # fmt: skip
def test_custom_dataset_errors(tmp_path, content, message):
    f = tmp_path / "d.json"
    f.write_text(content if isinstance(content, str) else json.dumps(content))
    with pytest.raises(DataError, match=message):
        load_info_types(f)


def test_missing_dataset(tmp_path):
    with pytest.raises(DataError, match="not found"):
        load_info_types(tmp_path / "none.json")
