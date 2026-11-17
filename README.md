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
     The Privacy Overlay is added when the system processes PII, and you can declare other overlays.
     The baseline is selected from CNSSI 1253 Appendix D data you supply. See [Limits](#limits).
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
| `--nss-data FILE` | CNSSI 1253 Appendix D baseline data for nss mode; format in [docs/data.md](docs/data.md) |
| `-o DIR` | Write the output files |

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
| [`nss`](samples/nss) | H-M-L, baseline not selected | Per-objective categorization; Privacy Overlay added for PII; a declared Classified overlay |

## Data and versions

| Source | Version used | Notes |
|---|---|---|
| NIST SP 800-60 Vol. 1 & 2 | Rev. 1 (August 2008), current final | Rev. 2 has been an initial working draft since January 2024. The catalog is swappable for when it's final |
| NIST SP 800-53 Rev. 5 / SP 800-53B | Catalog release 5.2.0 (NIST OSCAL content) | Baselines and control titles |
| FIPS 199 / FIPS 200 | 2004 / 2006 | The categorization and high-water-mark rules |
| CNSSI No. 1253 | 29 July 2022 | Rules for nss mode; Appendix D tables not bundled |

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
  FIPS 200 high-water mark.
- **Outputs are OSCAL,** so the next RMF step reads the result instead of someone retyping it.

## Limits

- **CNSSI 1253 Appendix D baselines are not bundled.** No official copy was downloadable from a public
  source while this was built, and hand-typed baselines can't be verified. NSS mode still categorizes
  fully; supply the Appendix D data with `--nss-data` to select the baseline.
- Overlay contents (Privacy, Classified, and so on) are not bundled. Overlays are listed as still to apply.
- Baselines are a starting point. Tailoring (SP 800-37 task S-2) and organization-defined parameter
  values are out of scope.
- oscal-ssp-generator doesn't read `system-characteristics.json` yet; joining them is planned for rmf-toolchain.
- Information types are matched by SP 800-60 ID or exact title. The tool doesn't infer which types a
  system processes.

## Development

```bash
pip install -e ".[dev]"
pytest --cov=security_categorizer
ruff check . && ruff format --check .
python tools/build_data.py --check     # bundled data matches sources/
python tools/make_samples.py --check   # sample outputs match the code
```

CI runs lint, tests on Python 3.10–3.14, a data job (re-downloads the NIST sources, verifies
SHA-256, regenerates the data and the samples), and an OSCAL schema job.

## License

[Apache-2.0](LICENSE). Copyright 2026 Juliet Rodriguez. The documents in `sources/` and `schemas/`
are U.S. Government works.
