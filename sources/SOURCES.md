# Source documents

Unmodified copies of the public U.S. Government documents the bundled data is
built from (`tools/build_data.py`). Works of the U.S. Government are not subject
to copyright in the United States. CI downloads each file again from its official
location and checks it against `SHA256SUMS`, so these copies can't drift.

| File | What it is | Official location |
|---|---|---|
| `NIST.SP.800-60v2r1.pdf` | NIST SP 800-60 Vol. 2 Rev. 1 (August 2008): information types and provisional impact levels | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-60v2r1.pdf |
| `NIST_SP-800-53_rev5_catalog-min.json` | NIST SP 800-53 Rev. 5 catalog, release 5.2.0 (OSCAL), for control titles | usnistgov/oscal-content @ `f0de6d8d8c059d374f15e0ae07508d82e370fc1d`, `nist.gov/SP800-53/rev5/json/` |
| `NIST_SP-800-53_rev5_{LOW,MODERATE,HIGH,PRIVACY}-baseline_profile-min.json` | SP 800-53B baselines (OSCAL profiles) | same commit and folder |

## Versions checked (November 2026)

- **NIST SP 800-60 Rev. 1** (Vol. 1 and Vol. 2, August 2008) is the current final.
  **Rev. 2** has been an initial working draft since 31 January 2024 and is not
  used. The information-type data is a plain JSON file, so a later revision can be
  swapped in with `--info-types` (format in `docs/data.md`).
- **NIST SP 800-53 Rev. 5 / SP 800-53B**: NIST's OSCAL content at release 5.2.0.
- **FIPS 199** (2004) and **FIPS 200** (2006): the categorization rules; no data needed.
- **CNSSI No. 1253, 29 July 2022** (supersedes 27 March 2014): the NSS rules used in
  `nss` mode. Its Appendix D baseline tables are **not** bundled; see
  `docs/design-notes.md` (section "CNSSI 1253 data is not bundled").
