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

## 7. CNSSI 1253 data is not bundled

**Choice:** `nss` mode categorizes fully (trigraph, overlays), but it selects a baseline only when
you supply CNSSI 1253 Appendix D data with `--nss-data`. Without it, the report says the baseline
was not selected, and why.

**Why:** No official, downloadable copy of CNSSI 1253 (2022) was reachable from a public source
while this was built: cnss.gov and the usual mirrors refused automated and browser downloads.
Typing Appendix D's 20 tables in from memory or from an unofficial copy would produce data nobody
can verify, and a wrong baseline is worse than none. So the tool documents the format
(docs/data.md), tests the logic with a file clearly marked SYNTHETIC, and leaves the official
data to the user.

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

**Trade-off:** oscal-ssp-generator doesn't read this fragment yet; merging it is part of the planned
rmf-toolchain repo.

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
