# security-categorizer

[![CI](https://github.com/JulietRodriguez/security-categorizer/actions/workflows/ci.yml/badge.svg)](https://github.com/JulietRodriguez/security-categorizer/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)

Security categorization for the **Categorize** step of the NIST SP 800-37 Risk Management Framework.
It takes a system's information types from NIST SP 800-60, applies your adjustments, and works out
the FIPS 199 security category. In national security system (NSS) mode it keeps confidentiality,
integrity and availability separate, as CNSSI 1253 requires. It then picks the matching control
baseline and writes OSCAL the next step can use.

> The result is a **draft**. Under SP 800-37 Rev. 2 (task C-2) the Authorizing Official or the AO's
> designated representative reviews and approves the security categorization.

## The problem

Categorization is usually a spreadsheet: someone copies provisional levels out of a 300-page PDF,
changes a few, and writes "Moderate" at the bottom. Nobody can later tell which levels were NIST's,
which were changed, or why. Because the categorization picks the baseline, a mistake here changes
every control that follows.

## What it does

1. **Information types** come from NIST SP 800-60 Vol. 2 Rev. 1. That's 167 types with provisional
   C/I/A levels, extracted from NIST's PDF by a script. You can also define your own types.
2. **Adjustments** to any level need a written justification. Lowering a level is allowed but always
   flagged for review. Types whose level NIST footnotes with an exception get a review note.
3. **System category.** It takes the high-water mark per objective (never below Low, per FIPS 199).
   System-level adjustments, such as aggregation, can only raise a level.
4. **Mode:**
   - `federal`: the overall level is the highest of C, I and A (FIPS 200). It selects the
     **SP 800-53B Low (149), Moderate (287) or High (370)** baseline, plus the **Privacy baseline
     (96)** when the system processes PII.
   - `nss`: C, I and A stay separate (for example **H-M-L**), as CNSSI 1253 (29 July 2022) requires.
     Each objective selects its own column of CNSSI 1253 Appendix D, and the NSS Privacy Control
     Baseline is added for every NSS. An H-M-L system gets **543** controls; a single high-water mark
     (H-H-H) would give 607. The Privacy Overlay is added when the system processes PII, and you can
     declare other overlays. The Appendix D data is built by a script from your own copy of
     CNSSI 1253 (see [NSS baselines](#nss-baselines-cnssi-1253)).
5. **Outputs:** the reports, the baseline list, an OSCAL baseline profile and an OSCAL
   system-characteristics section.

## Quick start

```bash
pip install -e .

security-categorizer types --search monitoring        # find information types
security-categorizer show C.3.5.8                       # one type's provisional levels
security-categorizer categorize samples/federal-moderate/system.yaml -o out
```

```
SYNTHETIC Case Management System (CMS-DEMO): Moderate (SC SYNTHETIC Case Management System (CMS-DEMO) = {(confidentiality, MODERATE), (integrity, MODERATE), (availability, LOW)})
Baseline: SP 800-53B Moderate + Privacy, 340 controls
```

A system description (YAML or JSON):

```yaml
system:
  name: SYNTHETIC Case Management System (CMS-DEMO)
mode: federal                 # or nss
processes_pii: true
information_types:
  - id: C.3.5.8               # System and Network Monitoring (M/M/L)
  - id: C.2.1.1               # Corrective Action (L/L/L)
    adjustments:
      - objective: integrity
        level: moderate
        justification: Corrective-action records drive case closure decisions ...
  - custom:                   # a type that isn't in SP 800-60
      id: ORG-CMS-01
      title: Case records
      confidentiality: moderate
      integrity: moderate
      availability: low
system_adjustments: []        # optional; may only raise a level
overlays: []                  # nss mode: classified, space, intelligence, cds (privacy is automatic with PII)
```

| Option | What it does |
|---|---|
| `--mode federal\|nss` | Override the mode in the file |
| `--info-types FILE` | Use another information-type catalog (a future SP 800-60 revision, an agency supplement); format in [docs/data.md](docs/data.md) |
| `--nss-data FILE` | CNSSI 1253 Appendix D baseline data for nss mode, built with `tools/build_nss_data.py`; format in [docs/data.md](docs/data.md) |
| `-o DIR` | Write the output files |

## NSS baselines (CNSSI 1253)

CNSSI 1253 has no distribution statement, so this repository doesn't include the PDF or any table
from it. Instead, a script reads Appendix D (Tables D-1 to D-20) from your copy:

```bash
pip install -e ".[nss]"                       # pinned pdfplumber
python tools/build_nss_data.py CNSSI_1253.pdf -o cnssi-1253-appendix-d.json
security-categorizer categorize samples/nss/system.yaml --nss-data cnssi-1253-appendix-d.json -o out/nss
```

The script places each "X", "+" and "--" mark by its position under the nine C/I/A × L/M/H columns
and by the table's ruled row borders. It records the PDF's SHA-256, counts per column and per family,
anything it couldn't place ("anomalies"), and every place where Appendix D disagrees with its own
legend or with SP 800-53B ("source_discrepancies"). It doesn't guess.

It was checked against the CNSSI 1253 PDF dated 29 July 2022 (the CNSS corrected copy of
6 October 2022, SHA-256 `d876741dfb78c54cf21e1f8f966475bddb9df0d3fc8e935e5350862c246d1180`):

| | Low | Moderate | High |
|---|---:|---:|---:|
| Confidentiality column | 273 | 319 | 397 |
| Integrity column | 310 | 380 | 474 |
| Availability column | 147 | 202 | 283 |

Plus 93 controls in the NSS Privacy Control Baseline, out of 1,189 rows (182 withdrawn).
No anomalies. 10 source discrepancies, recorded in the data:

- **SA-15 and SC-7(8) at Moderate, SI-4(22) at High** are in NIST's SP 800-53B baseline (catalog
  5.2.0), but Appendix D marks them "+" (added for NSS) instead of "X". Either NIST's baseline
  changed after July 2022, or the mark doesn't follow the legend. The control is selected either way.
- **7 controls in catalog 5.2.0 aren't in Appendix D** (IA-13 and its three enhancements, SA-15(13),
  SA-24, SI-2(7)). Appendix D is older than that catalog release, so these are never selected.

`load_nss_data` checks data built from that PDF against these counts and refuses it if they don't
match (for example after a pdfplumber change). Data from any other source is used but flagged
"not verified" in the report. With the PDF, `CNSSI_1253_PDF=CNSSI_1253.pdf pytest` runs 20 more
tests that pin the per-family counts and spot-checked rows (see `tests/test_nss_data.py`).

## Outputs

| File | What it is |
|---|---|
| `categorization.md` / `.json` | The result: each information type's provisional and final levels, every adjustment with its justification, the high-water mark, the baseline summary and review notes |
| `baseline.txt` | The selected controls with titles (SP 800-53 Rev. 5, catalog 5.2.0) |
| `baseline-profile.json` | The baseline as an OSCAL 1.1.2 profile. [ato-readiness-checker](https://github.com/JulietRodriguez/ato-readiness-checker) reads it as `--baseline` |
| `system-characteristics.json` | OSCAL 1.1.2 `system-characteristics` content (information types with `base`/`selected` impacts and adjustment justifications, security impact level, sensitivity level) for an SSP |

Both OSCAL outputs are validated against NIST's official OSCAL 1.1.2 schemas in CI. The
system-characteristics file is a fragment, so it's validated inside the smallest SSP the schema accepts.

## Samples (all synthetic)

| Sample | Result | What it shows |
|---|---|---|
| [`federal-moderate`](samples/federal-moderate) | Moderate (M/M/L), 340 controls | PII adds the Privacy baseline; a justified raise; a custom information type |
| [`federal-high`](samples/federal-high) | High (M/H/H), 370 controls | Mission types from SP 800-60 Appendix D; a lowered level (flagged); footnoted exceptions (flagged); a system-level raise for aggregation |
| [`nss`](samples/nss) | H-M-L; 543 controls with your CNSSI 1253 data (the committed output has none, see below) | Per-objective categorization; Privacy Overlay added for PII; a declared Classified overlay |

The committed `nss` output stops before the baseline, because a selected CNSSI 1253 baseline is
derived from Appendix D. Run the commands under [NSS baselines](#nss-baselines-cnssi-1253) to
produce it locally. CI selects an NSS baseline from a SYNTHETIC test file to validate the OSCAL
profile against NIST's schema.

## Data and versions

| Source | Version used | Notes |
|---|---|---|
| NIST SP 800-60 Vol. 1 & 2 | Rev. 1 (August 2008), current final | Rev. 2 has been an initial working draft since January 2024. The catalog is swappable for when it's final |
| NIST SP 800-53 Rev. 5 / SP 800-53B | Catalog release 5.2.0 (NIST OSCAL content) | Baselines and control titles |
| FIPS 199 / FIPS 200 | 2004 / 2006 | The categorization and high-water-mark rules |
| CNSSI No. 1253 | 29 July 2022 | Rules for nss mode; Appendix D read from your copy by `tools/build_nss_data.py` (not redistributed) |

Source documents are kept in [sources/](sources), and CI checks them against the official downloads.
[`tools/build_data.py`](tools/build_data.py) turns them into the bundled JSON, and CI fails if the
data doesn't match a fresh build.

## Design choices (short version)

Plain-language explanations are in [docs/design-notes.md](docs/design-notes.md).

- **Every number traces to a source line or a justification.** The report shows NIST's provisional
  level next to the final one.
- **The data is built by script from NIST's PDF, not typed in.** The script found two places where
  NIST's own text contradicts itself; both are recorded in the dataset.
- **FIPS 199 rules are enforced.** No objective is ever below Low at system level, and a system-level
  change can't go below what the information types require.
- **Two modes, because civilian and national security systems differ.** CNSSI 1253 does not use the
  FIPS 200 high-water mark: each objective selects its own Appendix D column.
- **NSS data is extracted by script and cross-checked, never typed in.** Two table readers agree on
  the rows, and every "X" and "--" mark is checked against SP 800-53B.
- **Outputs are OSCAL,** so the next RMF step reads the result instead of someone retyping it.

## Limits

- **CNSSI 1253 data isn't redistributed.** The document has no distribution statement, so you build
  the Appendix D data from your own copy. Without it, NSS mode categorizes but selects no baseline.
- **CI can't run the real-data tests.** Without the PDF, CI tests the extractor on a generated
  SYNTHETIC PDF and the NSS selection with SYNTHETIC data. The 20 real-data tests run where you have
  the PDF.
- **The extractor is built for the 29 July 2022 layout.** A future edition with a different table
  layout may need changes. Its anomaly report and the count check say when something doesn't fit.
- **Overlays aren't applied.** CNSSI 1253 publishes them separately from the Instruction (Appendix E
  only describes them), so the Privacy, Classified and other overlays are listed as still to apply.
  That includes the 27 SP 800-53B privacy controls that Appendix D leaves to the Privacy Overlay.
- **NSS parameter values aren't included.** Appendix D also sets minimum parameter values; the tool
  selects controls only.
- Baselines are a starting point. Tailoring (SP 800-37 task S-2) and organization-defined parameter
  values are out of scope.
- oscal-ssp-generator doesn't read `system-characteristics.json` itself;
  [rmf-toolchain](https://github.com/JulietRodriguez/rmf-toolchain) joins them.
- Information types are matched by SP 800-60 ID or exact title. The tool doesn't infer which types a
  system processes.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=security_categorizer
ruff check . && ruff format --check .
python tools/build_data.py --check     # bundled data matches sources/
python tools/make_samples.py --check   # sample outputs match the code
CNSSI_1253_PDF=CNSSI_1253.pdf pytest tests/test_nss_data.py   # with your copy of CNSSI 1253
```

CI runs lint, tests on Python 3.10–3.14, a data job (re-downloads the NIST sources, verifies
SHA-256, regenerates the data and the samples), and an OSCAL schema job.

## License

[Apache-2.0](LICENSE). Copyright 2026 Juliet Rodriguez. The documents in `sources/` and `schemas/`
are U.S. Government works.
