# Security categorization: SYNTHETIC Case Management System (CMS-DEMO)

> **DRAFT.** This categorization is a draft prepared with security-categorizer. Under NIST SP 800-37 Rev. 2 (task C-2) the security categorization is reviewed and approved by the Authorizing Official or the AO's designated representative; for national security systems, CNSSI 1253 applies.

## Result: Moderate system (FIPS 199 / FIPS 200)

`SC SYNTHETIC Case Management System (CMS-DEMO) = {(confidentiality, MODERATE), (integrity, MODERATE), (availability, LOW)}`

Overall impact level **Moderate** is the FIPS 200 high-water mark of confidentiality Moderate, integrity Moderate and availability Low.

Processes PII: yes.

## Information types

| ID | Information type | Provisional C / I / A | Final C / I / A | Adjusted |
|---|---|---|---|---|
| C.3.5.8 | System and Network Monitoring Information Type | Moderate / Moderate / Low | Moderate / Moderate / Low |  |
| C.2.1.1 | Corrective Action Information Type | Low / Low / Low | Low / Moderate / Low | yes |
| ORG-CMS-01 | Case records | Moderate / Moderate / Low | Moderate / Moderate / Low |  |

## Adjustments and justifications

- **C.2.1.1 integrity**: Low → Moderate (raised). Corrective-action records drive case closure decisions; undetected changes would produce wrong outcomes for the people the cases concern.

## High-water mark

| Objective | Highest information-type level | Final (after system-level adjustments) |
|---|---|---|
| Confidentiality | Moderate | Moderate |
| Integrity | Moderate | Moderate |
| Availability | Low | Low |

A system objective is never below Low: FIPS 199 does not allow not-applicable for a system.

## Control baseline: SP 800-53B Moderate + Privacy (340 controls)

- SP 800-53B Moderate baseline: 287 controls
- SP 800-53B Privacy baseline (system processes PII): 96 controls
- The moderate baseline is selected by the FIPS 200 high-water mark of confidentiality moderate, integrity moderate, availability low.
- This is the starting point: tailor it (SP 800-37 task S-2) before control implementation.

The full list is in `baseline.txt` and, as an OSCAL profile, in `baseline-profile.json`.

## Data sources

- Information types: NIST SP 800-60 Vol. 2 Rev. 1, Volume II: Appendices to Guide for Mapping Types of Information and Information Systems to Security Categories (2008-08).
- Baseline: NIST SP 800-53 Rev. 5 (catalog 5.2.0), SP 800-53B.
