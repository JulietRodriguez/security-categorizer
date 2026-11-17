from __future__ import annotations

from pathlib import Path

import pytest

from security_categorizer.categorize import categorize
from security_categorizer.datasets import load_info_types
from security_categorizer.system import parse_spec

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ROOT / "samples"
SCHEMAS = ROOT / "schemas"
NSS_DATA = Path(__file__).parent / "fixtures" / "nss-data-SYNTHETIC.json"


@pytest.fixture(scope="session")
def catalog():
    return load_info_types()


def spec(types, **extra):
    return parse_spec({"system": {"name": "Test System"}, "information_types": types, **extra})


@pytest.fixture
def run(catalog):
    def _run(types, **extra):
        return categorize(spec(types, **extra), catalog)

    return _run
