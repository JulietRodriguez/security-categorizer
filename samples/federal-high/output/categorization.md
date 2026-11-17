# Security categorization: SYNTHETIC Flood Warning System (FWS-DEMO)

> **DRAFT.** This categorization is a draft prepared with security-categorizer. Under NIST SP 800-37 Rev. 2 (task C-2) the security categorization is reviewed and approved by the Authorizing Official or the AO's designated representative; for national security systems, CNSSI 1253 applies.

## Result: High system (FIPS 199 / FIPS 200)

`SC SYNTHETIC Flood Warning System (FWS-DEMO) = {(confidentiality, MODERATE), (integrity, HIGH), (availability, HIGH)}`

Overall impact level **High** is the FIPS 200 high-water mark of confidentiality Moderate, integrity High and availability High.

Processes PII: no.

## Information types

| ID | Information type | Provisional C / I / A | Final C / I / A | Adjusted |
|---|---|---|---|---|
| D.4.1 | Disaster Monitoring and Prediction Information Type | Low / High / High | Low / High / High |  |
| D.4.4 | Emergency Response Information Type | Low / High / High | Low / High / High |  |
| C.3.1.1 | Facilities, Fleet, and Equipment Management Information Type | Low / Low / Low | Low / Low / Low |  |
| C.3.5.8 | System and Network Monitoring Information Type | Moderate / Moderate / Low | Low / Moderate / Low | yes |

## Adjustments and justifications

- **C.3.5.8 confidentiality**: Moderate → Low (lowered). The monitoring data in this system is limited to public gauge-station health; no security-sensitive network data is stored. Lowering requires AO review.
- **System confidentiality**: Low → Moderate (raised). Aggregation: combined gauge locations and outage history reveal weak points in the regional warning network.

## High-water mark

| Objective | Highest information-type level | Final (after system-level adjustments) |
|---|---|---|
| Confidentiality | Low | Moderate |
| Integrity | High | High |
| Availability | High | High |

A system objective is never below Low: FIPS 199 does not allow not-applicable for a system.

## Control baseline: SP 800-53B High (370 controls)

- SP 800-53B High baseline: 370 controls
- The high baseline is selected by the FIPS 200 high-water mark of confidentiality moderate, integrity high, availability high.
- This is the starting point: tailor it (SP 800-37 task S-2) before control implementation.

The full list is in `baseline.txt` and, as an OSCAL profile, in `baseline-profile.json`.

## Review notes

- C.3.1.1: SP 800-60 footnotes the provisional confidentiality level with an exception; check whether it applies to this system
- C.3.1.1: SP 800-60 footnotes the provisional integrity level with an exception; check whether it applies to this system
- C.3.1.1: SP 800-60 footnotes the provisional availability level with an exception; check whether it applies to this system
- C.3.5.8: confidentiality lowered from moderate to low; lowering a provisional level should be reviewed and approved

## Data sources

- Information types: NIST SP 800-60 Vol. 2 Rev. 1, Volume II: Appendices to Guide for Mapping Types of Information and Information Systems to Security Categories (2008-08).
- Baseline: NIST SP 800-53 Rev. 5 (catalog 5.2.0), SP 800-53B.
