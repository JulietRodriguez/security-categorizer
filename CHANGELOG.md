# Changelog

## 0.2.0 (unreleased)

### Added

- NSS baseline selection from CNSSI 1253 (29 July 2022) Appendix D. `tools/build_nss_data.py`
  extracts Tables D-1 to D-20 from your copy of the PDF into the `--nss-data` file, with the PDF's
  SHA-256, counts per column and per family, unplaceable marks ("anomalies") and disagreements with
  the legend or SP 800-53B ("source_discrepancies"). The PDF and the extracted tables are not
  redistributed: the document has no distribution statement.
- `load_nss_data` checks data built from the verified PDF against its known counts and refuses it
  if they don't match. Reports say whether the NSS data was verified.
- Tests: the extractor on a generated SYNTHETIC PDF; 20 tests that pin the real data, run with
  `CNSSI_1253_PDF=...`.
- `nss` extra (pinned pdfplumber).

### Changed

- The CLI version test reads `__version__` instead of a hardcoded number, and a new test checks
  that `pyproject.toml` and `__version__` agree.
