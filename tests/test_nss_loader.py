"""load_nss_data's check of data extracted from the verified CNSSI 1253 PDF (no CNSSI content here)."""

import copy
import json

import pytest

from security_categorizer.baseline import select_baseline
from security_categorizer.datasets import VERIFIED_CNSSI_1253, DataError, load_nss_data, nss_data_status

from .conftest import NSS_DATA


def fake_verified():
    """Made-up control IDs in the right numbers, labelled with the verified PDF's SHA-256."""
    v = VERIFIED_CNSSI_1253
    return {
        "dataset": "SYNTHETIC",
        "source": {"title": "SYNTHETIC", "date": "29 July 2022", "sha256": v["sha256"]},
        "baselines": {
            o: {lv: [f"zz-{i}" for i in range(n)] for lv, n in levels.items()} for o, levels in v["baselines"].items()
        },
        "privacy_baseline": [f"zz-{i}" for i in range(v["privacy_baseline"])],
        "source_discrepancies": [{"control": "zz-1", "level": None, "issue": "SYNTHETIC"}],
    }


def write(tmp_path, data):
    path = tmp_path / "nss.json"
    path.write_text(json.dumps(data))
    return path


def test_verified_counts_are_accepted(tmp_path, run):
    data = load_nss_data(write(tmp_path, fake_verified()))
    assert nss_data_status(data) == "verified"
    sel = select_baseline(run(["C.3.5.8"], mode="nss"), data)
    notes = " ".join(sel.notes)
    assert "the copy this tool's extraction was checked against" in notes
    assert "1 places where Appendix D disagrees" in notes


def test_verified_sha_with_wrong_counts_is_refused(tmp_path):
    data = fake_verified()
    data["baselines"]["integrity"]["high"].pop()
    with pytest.raises(DataError, match="don't match the verified counts"):
        load_nss_data(write(tmp_path, data))
    data = fake_verified()
    data["privacy_baseline"].append("zz-0")  # duplicates don't count twice
    load_nss_data(write(tmp_path, data))
    data["privacy_baseline"] = data["privacy_baseline"][:-2]
    with pytest.raises(DataError, match="privacy"):
        load_nss_data(write(tmp_path, data))


def test_other_data_is_unverified(tmp_path, run):
    data = load_nss_data(NSS_DATA)
    assert nss_data_status(data) == "unverified"
    notes = " ".join(select_baseline(run(["C.3.5.8"], mode="nss"), data).notes)
    assert "not from the PDF this tool's extraction was checked against; review it" in notes
    other = copy.deepcopy(json.loads(NSS_DATA.read_text()))
    other["source"]["sha256"] = "0" * 64
    notes = " ".join(select_baseline(run(["C.3.5.8"], mode="nss"), load_nss_data(write(tmp_path, other))).notes)
    assert "(SHA-256 " + "0" * 64 + ")" in notes
