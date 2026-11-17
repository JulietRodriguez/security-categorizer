import pytest

from security_categorizer.categorize import CategorizationError
from security_categorizer.levels import Level, high_water
from security_categorizer.system import SpecError
from tests.conftest import spec

M, L, H, NA = Level.MODERATE, Level.LOW, Level.HIGH, Level.NA


def custom(tid, c, i, a, **extra):
    return {
        "custom": {"id": tid, "title": f"Type {tid}", "confidentiality": c, "integrity": i, "availability": a},
        **extra,
    }


# --- levels ----------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "level"),
    [("Low", L), ("fips-199-moderate", M), ("H", H), ("medium", M), ("N/A", NA), ("not applicable", NA)],
)
def test_level_parse(raw, level):
    assert Level.parse(raw) is level


def test_level_parse_rejects_unknown():
    with pytest.raises(ValueError, match="unknown impact level"):
        Level.parse("severe")


def test_level_properties():
    assert (M.letter, M.oscal, M.label) == ("M", "fips-199-moderate", "Moderate")
    assert (NA.letter, NA.oscal, NA.label) == ("-", "not-applicable", "N/A")


def test_high_water():
    assert high_water([L, H, M]) is H
    assert high_water([NA, NA], floor=L) is L
    assert high_water([]) is NA


# --- categorization ------------------------------------------------------------------------------------


def test_high_water_mark_across_types(run):
    cat = run(["C.3.5.8", "D.4.1"])  # M/M/L and L/H/H
    assert cat.final == {"confidentiality": M, "integrity": H, "availability": H}
    assert cat.overall is H
    assert cat.trigraph == "M-H-H"
    assert (
        cat.fips199_statement
        == "SC Test System = {(confidentiality, MODERATE), (integrity, HIGH), (availability, HIGH)}"
    )


def test_lookup_by_title(run):
    cat = run(["System and Network Monitoring"])
    assert cat.types[0].id == "C.3.5.8"


def test_not_applicable_type_never_drops_system_below_low(run):
    cat = run(["C.3.5.9"])  # Information Sharing: n/a for all three
    assert all(level is L for level in cat.final.values())


def test_adjustment_raises_and_is_recorded(run):
    cat = run(
        [{"id": "C.3.5.8", "adjustments": [{"objective": "availability", "level": "high", "justification": "SOC"}]}]
    )
    t = cat.types[0]
    assert t.provisional["availability"] is L and t.final["availability"] is H
    assert t.adjustments[0].direction == "raised"
    assert cat.warnings == []


def test_lowering_is_allowed_but_flagged(run):
    cat = run(
        [{"id": "C.3.5.8", "adjustments": [{"objective": "confidentiality", "level": "low", "justification": "x"}]}]
    )
    assert cat.types[0].adjustments[0].direction == "lowered"
    assert "should be reviewed and approved" in cat.warnings[0]


def test_unchanged_adjustment_is_flagged(run):
    cat = run(
        [{"id": "C.3.5.8", "adjustments": [{"objective": "integrity", "level": "moderate", "justification": "x"}]}]
    )
    assert "matches the current level" in cat.warnings[0]


def test_adjustment_requires_justification(run):
    with pytest.raises(CategorizationError, match="needs a justification"):
        run([{"id": "C.3.5.8", "adjustments": [{"objective": "integrity", "level": "high", "justification": " "}]}])


def test_system_adjustment_can_raise(run):
    cat = run(
        ["C.3.5.8"],
        system_adjustments=[{"objective": "availability", "level": "moderate", "justification": "aggregation"}],
    )
    assert cat.high_water["availability"] is L and cat.final["availability"] is M
    assert cat.system_adjustments[0].direction == "raised"


@pytest.mark.parametrize(("level", "message"), [("low", "can't be lowered"), ("n/a", "can't be lowered")])
def test_system_adjustment_cannot_go_below_high_water(run, level, message):
    with pytest.raises(CategorizationError, match=message):
        run(
            ["C.3.5.8"],
            system_adjustments=[{"objective": "confidentiality", "level": level, "justification": "x"}],
        )


def test_footnoted_type_produces_review_notes(run):
    cat = run(["C.3.1.1"])
    assert len(cat.warnings) == 3 and "footnotes" in cat.warnings[0]
    cat = run(
        [{"id": "C.2.8.4", "adjustments": [{"objective": "confidentiality", "level": "high", "justification": "x"}]}]
    )
    assert len(cat.warnings) == 1 and "availability" in cat.warnings[0]


def test_custom_type(run):
    cat = run([custom("ORG-1", "high", "low", "low")])
    assert cat.types[0].source == "custom (organization-defined)"
    assert cat.overall is H


@pytest.mark.parametrize(
    ("types", "extra", "message"),
    [
        ([], {}, "at least one information type"),
        (["C.3.5.8", "C.3.5.8"], {}, "listed twice"),
        (["Z.9.9"], {}, "not in"),
        (["D.26.1"], {}, "no provisional impact levels"),
        (["C.3.5.8"], {"mode": "fedramp"}, "mode must be one of"),
    ],
)
def test_categorization_errors(run, types, extra, message):
    with pytest.raises(CategorizationError, match=message):
        run(types, **extra)


def test_nss_mode_keeps_objectives_and_adds_privacy_overlay(run):
    cat = run([custom("X", "high", "moderate", "low")], mode="nss", processes_pii=True, overlays=["classified"])
    assert cat.trigraph == "H-M-L"
    assert cat.overlays == ["privacy", "classified"]


def test_overlays_in_federal_mode_are_flagged(run):
    cat = run(["C.3.5.8"], overlays=["space"])
    assert "CNSSI 1253" in cat.warnings[-1]


# --- system description parsing ------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ([], "mapping at the top level"),
        ({"system": {}}, "system.name is required"),
        ({"system": {"name": "x"}, "information_types": "C.3.5.8"}, "must be a list"),
        ({"system": {"name": "x"}, "information_types": [5]}, "ID string or a mapping"),
        ({"system": {"name": "x"}, "information_types": [{}]}, "give an id"),
        ({"system": {"name": "x"}, "information_types": [{"custom": "x"}]}, "custom must be a mapping"),
        ({"system": {"name": "x"}, "information_types": [{"custom": {"id": "a"}}]}, "missing title"),
        (
            {"system": {"name": "x"}, "information_types": [custom("a", "huge", "low", "low")]},
            "unknown impact level",
        ),
        ({"system": {"name": "x"}, "information_types": [{"id": "a", "adjustments": {}}]}, "must be a list"),
        ({"system": {"name": "x"}, "information_types": [{"id": "a", "adjustments": [1]}]}, "must be a mapping"),
        (
            {"system": {"name": "x"}, "information_types": [{"id": "a", "adjustments": [{"objective": "speed"}]}]},
            "objective must be",
        ),
        (
            {
                "system": {"name": "x"},
                "information_types": [{"id": "a", "adjustments": [{"objective": "integrity", "level": "x"}]}],
            },
            "unknown impact level",
        ),
        ({"system": {"name": "x"}, "overlays": "privacy"}, "overlays must be a list"),
        ({"system": {"name": "x"}, "overlays": ["nuclear"]}, "unknown overlay"),
        ({"system": {"name": "x"}, "processes_pii": "yes"}, "true or false"),
    ],
)
def test_spec_errors(data, message):
    from security_categorizer.system import parse_spec

    with pytest.raises(SpecError, match=message):
        parse_spec(data)


def test_spec_defaults_and_aliases():
    s = spec(["C.3.5.8"], overlays=["Privacy", "privacy"])
    assert s.mode == "federal" and s.processes_pii is False
    assert s.overlays == ("privacy",)
