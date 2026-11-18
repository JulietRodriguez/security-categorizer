import json
import subprocess
import sys

import pytest

from security_categorizer import __version__
from security_categorizer.cli import main
from tests.conftest import NSS_DATA, ROOT, SAMPLES


def test_categorize_writes_all_outputs(tmp_path, capsys):
    code = main(["categorize", str(SAMPLES / "federal-moderate" / "system.yaml"), "-o", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert "Moderate" in out and "340 controls" in out and "task C-2" in out
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "baseline-profile.json",
        "baseline.txt",
        "categorization.json",
        "categorization.md",
        "system-characteristics.json",
    ]


def test_categorize_prints_review_notes(capsys):
    assert main(["categorize", str(SAMPLES / "federal-high" / "system.yaml")]) == 0
    out = capsys.readouterr().out
    assert "High" in out and "note: C.3.5.8: confidentiality lowered" in out


def test_nss_without_and_with_data(tmp_path, capsys):
    path = str(SAMPLES / "nss" / "system.yaml")
    assert main(["categorize", path, "-o", str(tmp_path / "a")]) == 0
    assert "Baseline: not selected" in capsys.readouterr().out
    assert not (tmp_path / "a" / "baseline-profile.json").exists()
    assert main(["categorize", path, "--nss-data", str(NSS_DATA), "-o", str(tmp_path / "b")]) == 0
    assert "CNSSI 1253 H-M-L, 8 controls" in capsys.readouterr().out
    assert (tmp_path / "b" / "baseline-profile.json").exists()


def test_mode_override(capsys):
    assert main(["categorize", str(SAMPLES / "federal-moderate" / "system.yaml"), "--mode", "nss"]) == 0
    assert "CNSSI 1253 M-M-L" in capsys.readouterr().out


def test_json_system_file(tmp_path, capsys):
    f = tmp_path / "s.json"
    f.write_text(json.dumps({"system": {"name": "J"}, "information_types": ["C.2.1.1"]}))
    assert main(["categorize", str(f)]) == 0
    assert "J: Low" in capsys.readouterr().out


@pytest.mark.parametrize(
    ("content", "suffix", "message"),
    [("{bad", ".json", "not valid JSON"), ("a: [", ".yaml", "not valid YAML"), ("{}", ".yaml", "system.name")],
)
def test_bad_system_files(tmp_path, capsys, content, suffix, message):
    f = tmp_path / f"s{suffix}"
    f.write_text(content)
    assert main(["categorize", str(f)]) == 2
    assert message in capsys.readouterr().err


def test_missing_system_file(tmp_path, capsys):
    assert main(["categorize", str(tmp_path / "none.yaml")]) == 2
    assert "file not found" in capsys.readouterr().err


def test_types_and_show(capsys):
    assert main(["types", "--search", "emergency"]) == 0
    assert "D.4.4" in capsys.readouterr().out
    assert main(["show", "C.3.1.1"]) == 0
    out = capsys.readouterr().out
    assert "footnoted exception" in out and "Facilities" in out
    assert main(["show", "nope"]) == 2


def test_info_types_override(tmp_path, capsys):
    f = tmp_path / "t.json"
    f.write_text(json.dumps({"dataset": "mine", "information_types": [
        {"id": "M.1", "title": "Mine", "confidentiality": "low", "integrity": "low", "availability": "high"}]}))  # fmt: skip
    assert main(["--info-types", str(f), "types"]) == 0
    assert "M.1" in capsys.readouterr().out


def test_module_entry_point():
    proc = subprocess.run(
        [sys.executable, "-m", "security_categorizer", "--version"],
        capture_output=True,
        text=True,
        check=False,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": ""},
    )
    assert proc.returncode == 0 and f"security-categorizer {__version__}" in proc.stdout


def test_version_matches_pyproject():
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert f'\nversion = "{__version__}"\n' in text


def test_samples_are_up_to_date():
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "make_samples.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_sample_oscal_is_valid():
    pytest.importorskip("jsonschema")
    files = [str(p) for p in SAMPLES.glob("*/output/*.json") if p.name != "categorization.json"]
    proc = subprocess.run(
        [sys.executable, str(ROOT / "tools" / "validate_oscal.py"), "--schema-dir", str(ROOT / "schemas"), *files],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stdout
    assert proc.stdout.count("OK ") == 5
