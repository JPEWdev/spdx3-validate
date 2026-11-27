# Changelog

## Unreleased

### Added

- Merged check: report an Element `spdxId` defined in more than one document
  (SPDX wants one definition; others import it via `ExternalMap`). ([#17])
- Merged check: a source given more than once is merged once. ([#17])

### Fixed

- Merged check is now an RDF merge: blank nodes are renamed per document
  (`_:d<i>_<label>`), so a label like `_:CreationInfo0` reused across
  documents no longer collides. IRIs still meet across documents. ([#17])
- `externalSpdxId` is matched as an IRI, not a literal. This enables two checks
  that never fired: type errors on an imported `spdxId` defined in another
  document (merged check), and an `spdxId` both imported and defined in one
  document, which now fails. ([#17])

[#17]: https://github.com/JPEWdev/spdx3-validate/pull/17
