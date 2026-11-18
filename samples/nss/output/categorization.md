# Security categorization: SYNTHETIC Mission Planning System (MPS-DEMO)

> **DRAFT.** This categorization is a draft prepared with security-categorizer. Under NIST SP 800-37 Rev. 2 (task C-2) the security categorization is reviewed and approved by the Authorizing Official or the AO's designated representative; for national security systems, CNSSI 1253 applies.

## Result: H-M-L (CNSSI 1253)

Confidentiality **High**, integrity **Moderate**, availability **Low**. CNSSI 1253 keeps the three objectives separate; there is no single overall level.

Processes PII: yes.

## Information types

| ID | Information type | Provisional C / I / A | Final C / I / A | Adjusted |
|---|---|---|---|---|
| C.3.5.8 | System and Network Monitoring Information Type | Moderate / Moderate / Low | Moderate / Moderate / Low |  |
| ORG-MPS-01 | Exercise plans | High / Moderate / Low | High / Moderate / Low |  |

## High-water mark

| Objective | Highest information-type level | Final (after system-level adjustments) |
|---|---|---|
| Confidentiality | High | High |
| Integrity | Moderate | Moderate |
| Availability | Low | Low |

A system objective is never below Low: FIPS 199 does not allow not-applicable for a system.

## Control baseline: CNSSI 1253 H-M-L (not selected) (no controls selected)

- Categorization H-M-L is complete, but no baseline was selected: CNSSI 1253 Appendix D baseline data is not bundled with this tool. Build it from your copy of CNSSI 1253 with tools/build_nss_data.py and pass it with --nss-data (see docs/data.md).
- Overlays to apply: Privacy Overlay, Classified Information Overlay.

## Data sources

- Information types: NIST SP 800-60 Vol. 2 Rev. 1, Volume II: Appendices to Guide for Mapping Types of Information and Information Systems to Security Categories (2008-08).
- Baseline: none: CNSSI 1253 Appendix D data was not supplied.
