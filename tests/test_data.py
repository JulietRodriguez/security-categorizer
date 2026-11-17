"""The bundled datasets match their sources and contain what the docs say."""

import json
import subprocess
import sys

import pytest

from security_categorizer.datasets import sp800_53b
from tests.conftest import ROOT

DATA = ROOT / "src" / "security_categorizer" / "data"


@pytest.fixture(scope="module")
def sp800_60():
    return json.loads((DATA / "sp800_60v2r1.json").read_text(encoding="utf-8"))


def test_sp800_60_counts(sp800_60):
    assert sp800_60["counts"] == {"C": 77, "D": 90}
    assert len(sp800_60["information_types"]) == 167
    assert [t["id"] for t in sp800_60["not_categorized"]] == ["D.26.1", "D.26.2"]


@pytest.mark.parametrize(
    ("tid", "levels"),
    [
        ("C.3.5.8", ("moderate", "moderate", "low")),
        ("C.2.8.9", ("moderate", "moderate", "moderate")),
        ("C.2.1.1", ("low", "low", "low")),
        ("D.4.1", ("low", "high", "high")),
        ("D.16.3", ("moderate", "moderate", "moderate")),  # NIST's text is missing a ')' here
        ("C.3.5.9", ("n/a", "n/a", "n/a")),
    ],
)
def test_sp800_60_spot_values(sp800_60, tid, levels):
    t = next(x for x in sp800_60["information_types"] if x["id"] == tid)
    assert (t["confidentiality"], t["integrity"], t["availability"]) == levels


def test_sp800_60_records_source_inconsistencies(sp800_60):
    assert {(d["id"], d["objective"]) for d in sp800_60["source_discrepancies"]} == {
        ("D.2.4", "integrity"),
        ("D.23.4", "availability"),
    }


def test_sp800_60_source_hash_matches_vendored_pdf(sp800_60):
    import hashlib

    pdf = ROOT / "sources" / "NIST.SP.800-60v2r1.pdf"
    assert hashlib.sha256(pdf.read_bytes()).hexdigest() == sp800_60["source"]["sha256"]


def test_sp800_53b_baselines_nest():
    data = sp800_53b()
    b = {k: set(v) for k, v in data["baselines"].items()}
    assert data["counts"] == {"low": 149, "moderate": 287, "high": 370, "privacy": 96}
    assert b["low"] <= b["moderate"] <= b["high"]
    assert data["source"]["catalog_version"] == "5.2.0"
    assert data["titles"]["ac-2"] == "Account Management"


def test_data_matches_generator():
    pytest.importorskip("pypdf")
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "build_data.py"), "--check"], capture_output=True, text=True, check=False
    )
    assert proc.returncode == 0, proc.stderr
