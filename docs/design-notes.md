# Design notes

Why security-categorizer works the way it does, in plain language.

## 1. Follow the published process, step by step

**Choice:** The code follows SP 800-60 Vol. 1 Section 4 in order: identify information types,
take their provisional levels, adjust with justification, then combine into the system's
security category (FIPS 199).

**Why:** Categorization is the first RMF step, and everything after it depends on it: the
baseline, the cost of the control set, the assessment scope. An assessor or AO should be able to
follow each number back to a source line or a written justification. Each step leaves a record
in the report: provisional level, final level, who changed what and why.

## 2. The data comes from NIST's own PDF, by script, with a drift check

**Choice:** `tools/build_data.py` reads the official SP 800-60 Vol. 2 Rev. 1 PDF and writes the
167 information types to JSON. CI downloads the PDF again from nist.gov, checks its SHA-256, reruns
the script and fails if the output changes. The PDF text is extracted with a pinned version of
pypdf so every machine produces the same result.

**Why:** Typing 167 x 3 impact levels by hand invites mistakes nobody can find later. A script
can be re-run and reviewed. It also caught two places where NIST's own text contradicts itself
(D.2.4 integrity and D.23.4 availability): the "Security Category" line and the "Recommended ...
Impact Level" sentence disagree. The script uses the Security Category line and records both
in `source_discrepancies` so a reviewer can see them. One NIST section (D.16.3) is missing a
closing parenthesis; the parser tolerates that one typo and a test pins it.

**Trade-off:** Parsing a PDF is brittle if NIST ever re-issues the file. That's exactly when the
CI check fails, which is what I want.

## 3. Rev. 1, with the data source swappable

**Choice:** Use SP 800-60 Rev. 1 (2008), the current final. Rev. 2 is an initial working draft
(January 2024). Keep the catalog a plain JSON file that `--info-types` can replace.

**Why:** Agencies categorize against final guidance. When Rev. 2 is final, its taxonomy can be
dropped in without touching the code, and an agency can do the same with its own supplement today.

## 4. Adjustments need a justification; lowering gets a review note

**Choice:** Every adjustment must include a written justification or the run fails. Raising a
level is normal. Lowering one is allowed but always produces a review note. A system-level
adjustment can only raise a level.

**Why:** SP 800-60 expects provisional levels to be adjusted for context, and FIPS 199 makes the
system's category the high-water mark of its information types. Lowering the *system* below what
its own information types require would contradict FIPS 199, so that's an error that tells you
to adjust the information type instead, where the reasoning belongs. A raise at system level
(aggregation, for example) is legitimate and is recorded with its justification.

## 5. A system is never "not applicable"

**Choice:** Information types can be n/a for an objective (SP 800-60 uses that, for example for
Information Sharing), but a system objective is never below Low.

**Why:** FIPS 199 says not-applicable can't be assigned to a security objective of an information
system. Every system has at least some integrity and availability concern.

## 6. Two modes: FIPS 199/200 and CNSSI 1253

**Choice:** In `federal` mode the overall impact level is the highest of C, I and A (FIPS 200
high-water mark), and it selects the SP 800-53B Low, Moderate or High baseline. In `nss` mode C, I
and A stay separate (for example H-M-L), and each one selects its own column of CNSSI 1253
Appendix D.

**Why:** This is the main difference between civilian and national security systems. CNSSI 1253
(2022) states that it does not adopt the FIPS 200 high-water mark. A system with High
confidentiality and Low availability doesn't need High-availability controls, and the per-objective
approach avoids paying for them.

## 7. CNSSI 1253 data is built from your copy, not bundled

**Choice:** `tools/build_nss_data.py` reads Appendix D (Tables D-1 to D-20) from a CNSSI 1253 PDF you
supply and writes the `--nss-data` file. Neither the PDF nor the extracted tables are in this
repository.

**Why not bundle it:** I read the document for a release statement before using it. It has none:
no distribution line, no "approved for public release", no handling marking. The Foreword only says
the Instruction "may be obtained from the CNSS website." That tells you where to get it, not that
you can redistribute it. So the repository ships the extraction method and the checks, and each
user runs them on a copy they got from CNSS. The same reasoning keeps the committed `nss` sample
output short of the baseline.

**How the extraction works:** Each table page has a header with nine L/M/H cells (low, moderate,
high under C, I and A). Their x positions define the nine columns. Each mark ("X", "+", "--") is
placed in the row whose ruled borders contain it, and in the column whose center it sits under.
The NSS Privacy Control Baseline is the marked column left of the nine. A mark that fits no row,
no column, or two of either is reported as an anomaly instead of being placed.

Two layout problems came up on the real PDF, and both are handled in code, not by hand:

- In the PM table, the marks sit a few points below the control ID, so "same text line" missed
  them. The table's ruled row borders fixed it.
- Page 136 continues Table D-18 without repeating the header, so SC-18(2) and SC-18(3) were
  dropped at first. Cross-checking with a second reader (pypdf) caught the gap; the script now reuses the previous page's
  columns and records which pages needed it.

**How it's checked:** Three independent checks, because the extractor shouldn't be the only judge
of its own output:

1. A second reader (pdfplumber's ruled-grid table extraction) finds exactly the same 1,189
   control rows in every family.
2. The legend says "X" means "from the SP 800-53B baseline" and "--" means "in the NIST baseline
   but not the NSS one". So at each level, the "X" and "--" marks should be exactly NIST's
   baseline, which this tool already builds from NIST's own OSCAL. They are, except for 10
   recorded discrepancies.
3. Rows were compared with the rendered page by eye and pinned as spot checks.

**Discrepancies are recorded, not fixed.** SA-15 and SC-7(8) (Moderate) and SI-4(22) (High) are
in NIST's baseline in catalog 5.2.0, but marked "+" in Appendix D. The selection is the same
either way, and I can't tell from the documents alone whether NIST changed its baseline after
July 2022 or the mark breaks the legend, so both readings are written down. Seven controls in
catalog 5.2.0 are not in Appendix D at all and are never selected.

**Guarding against drift:** The tool knows the SHA-256 of the copy it was checked against and the
counts that copy produces. If data built from that PDF doesn't match the counts (a different
pdfplumber, say), `load_nss_data` refuses it. Data from any other source still works, but the
report says it wasn't verified.

**Trade-off:** CI can't run the real-data tests, because CI doesn't have the PDF. CI tests the
extractor on a generated SYNTHETIC PDF, and the NSS selection and its OSCAL profile with SYNTHETIC
data. The 20 tests that pin the real counts run wherever the PDF is available
(`CNSSI_1253_PDF=... pytest`).

## 8. Privacy is handled, not guessed

**Choice:** `processes_pii: true` adds the SP 800-53B Privacy baseline in federal mode. In nss mode
the NSS Privacy Control Baseline is always included (CNSSI 1253 applies it to every NSS), and the
Privacy Overlay is added automatically when the system processes PII.

**Why:** SP 800-53B keeps the privacy baseline separate from the security baselines and selects it
when PII is processed. CNSSI 1253 handles it with a baseline for every NSS plus an overlay for
systems with PII. The tool records the PII decision, but the SAOP or designee approves it.

## 9. Outputs that feed the next step

**Choice:** Besides the Markdown and JSON reports, the tool writes:

- `baseline-profile.json`, an OSCAL 1.1.2 profile that imports NIST's SP 800-53 Rev. 5 catalog
  with the selected control IDs. ato-readiness-checker accepts it directly as `--baseline`.
- `system-characteristics.json`, the categorization in the shape of an SSP's
  `system-characteristics`: information types with `base`, `selected` and
  `adjustment-justification` impacts, the C/I/A impact level and the sensitivity level. Catalog
  types carry the OSCAL 1.1.2 SP 800-60 identifier `http://doi.org/10.6028/NIST.SP.800-60v2r1`.

**Why:** Categorize feeds Select, and Select feeds Implement. Writing OSCAL means the next tool reads
the result instead of someone retyping it. The fragment isn't a whole SSP, so CI validates it by
wrapping it in the smallest SSP NIST's schema accepts.

**Trade-off:** oscal-ssp-generator doesn't read this fragment itself; rmf-toolchain merges it into
the SSP.

## 10. Draft for approval, not a decision

**Choice:** Every report starts with a DRAFT note: under SP 800-37 Rev. 2 task C-2, the AO or the
AO's designated representative reviews and approves the security categorization.

**Why:** The tool does the arithmetic and keeps the record. Deciding that the categorization is
right for the mission belongs to people who know the mission.

## 11. Deterministic and offline

**Choice:** Bundled data, no network calls at run time, UUIDv5 identifiers in OSCAL output, and a
fixed timestamp for the committed samples (checked in CI).

**Why:** The same system description should give the same categorization on any machine, including
one in an enclave with no internet access.
