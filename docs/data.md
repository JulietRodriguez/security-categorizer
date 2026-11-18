# Data formats

## Information-type catalog (`--info-types`)

The bundled catalog is `src/security_categorizer/data/sp800_60v2r1.json`, built from
NIST SP 800-60 Vol. 2 Rev. 1 by `tools/build_data.py`. Any file with this shape can replace
it: a future SP 800-60 revision, or an agency supplement.

```json
{
  "dataset": "my-catalog-name",
  "source": {"title": "Where the levels come from", "published": "2026-01"},
  "information_types": [
    {
      "id": "C.3.5.8",
      "title": "System and Network Monitoring Information Type",
      "group_title": "Information and Technology Management",
      "confidentiality": "moderate",
      "integrity": "moderate",
      "availability": "low",
      "footnoted": []
    }
  ],
  "not_categorized": [{"id": "D.26.1", "title": "Military Operations Information Type"}]
}
```

- Levels: `low`, `moderate`, `high` or `n/a`.
- `footnoted` (optional): objectives whose level the source marks with an exception. The tool
  adds a review note when one of these is used without an adjustment.
- `not_categorized` (optional): types the source names but gives no levels for. Using one
  is an error that tells you to define it as a custom type.

The bundled file also records `counts` and `source_discrepancies` (places where NIST's own
text disagrees with itself, so a reviewer can check them).

## CNSSI 1253 baseline data (`--nss-data`)

Not bundled (see design notes, section 7). Build it from your copy of CNSSI 1253 (29 July 2022):

```bash
pip install -e ".[nss]"
python tools/build_nss_data.py CNSSI_1253.pdf -o cnssi-1253-appendix-d.json
```

The fields the tool uses:

```json
{
  "dataset": "cnssi-1253-2022-appendix-d",
  "source": {"title": "CNSSI No. 1253, ...", "date": "29 July 2022", "sha256": "..."},
  "baselines": {
    "confidentiality": {"low": ["ac-1", "..."], "moderate": ["..."], "high": ["..."]},
    "integrity":       {"low": ["..."], "moderate": ["..."], "high": ["..."]},
    "availability":    {"low": ["..."], "moderate": ["..."], "high": ["..."]}
  },
  "privacy_baseline": ["..."]
}
```

Each list holds the controls Appendix D selects for that column: entries marked `X` (from the
SP 800-53B baseline) and `+` (added for NSS), but not `--` (in the NIST baseline, not the NSS one).
Control IDs use the OSCAL catalog form (`ac-2.1` for AC-2(1)). `source.sha256` is optional.

The script also writes, for review:

- `controls`: every row, with its table, page, withdrawn flag and the mark in each column.
- `nist_not_selected_for_nss`: the `--` marks.
- `added_for_nss`: controls with at least one `+`.
- `counts`: per column and per family.
- `anomalies`: marks the script couldn't place in exactly one row and column (empty for the
  verified PDF).
- `source_discrepancies`: places where Appendix D disagrees with its legend or with SP 800-53B.
- `pages_without_table_header`: pages that continue a table without repeating its header.

If `source.sha256` is the verified PDF's, the loader checks the counts and refuses data that
doesn't match. `tests/fixtures/nss-data-SYNTHETIC.json` shows the format with made-up values.

## System description

See the docstring of `src/security_categorizer/system.py` and the files in `samples/`.
