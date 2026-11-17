"""Validate OSCAL output against NIST's OSCAL 1.1.2 JSON schemas.

    python tools/validate_oscal.py --schema-dir schemas FILE [FILE ...]

* ``baseline-profile.json`` files are validated against the profile schema.
* ``system-characteristics.json`` files are fragments, so each one is wrapped in
  the smallest valid SSP (security_categorizer.oscal.ssp_shell) and validated
  against the SSP schema.

NIST's schemas use \\p{L} and \\p{N} in regex patterns, which Python's ``re``
doesn't support; those two classes are translated to [^\\W\\d_] and \\d first.
Every other keyword is used as published. Needs jsonschema.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from jsonschema import Draft7Validator

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from security_categorizer.oscal import ssp_shell

_REWRITES = {r"\p{L}": r"[^\W\d_]", r"\p{N}": r"\d"}


def _rewrite(node):
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            if k == "pattern" and isinstance(v, str):
                for a, b in _REWRITES.items():
                    v = v.replace(a, b)
            out[k] = _rewrite(v)
        return out
    if isinstance(node, list):
        return [_rewrite(v) for v in node]
    return node


def validator(schema_path: Path) -> Draft7Validator:
    return Draft7Validator(_rewrite(json.loads(schema_path.read_text(encoding="utf-8"))))


def errors_for(doc: dict, schema_dir: Path) -> tuple[str, list[str]]:
    if "profile" in doc:
        schema = schema_dir / "oscal_profile_schema.json"
    else:
        doc = ssp_shell(doc, doc.get("system-name", "system"), "2026-01-01T00:00:00+00:00")
        schema = schema_dir / "oscal_ssp_schema.json"
    errs = sorted(validator(schema).iter_errors(doc), key=lambda e: list(map(str, e.absolute_path)))
    return schema.name, [f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}" for e in errs]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--schema-dir", required=True, type=Path)
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)
    failed = 0
    for f in args.files:
        schema, errs = errors_for(json.loads(f.read_text(encoding="utf-8")), args.schema_dir)
        if errs:
            failed += 1
            print(f"FAIL {f}: {len(errs)} error(s) against {schema}")
            for e in errs[:20]:
                print(f"     {e}")
        else:
            print(f"OK   {f}: valid per {schema}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
