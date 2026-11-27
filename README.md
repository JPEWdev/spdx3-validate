# SPDX 3 Validation Tool

Validates SPDX 3 documents

While standalone tools like `pyshacl` and `check-jsonschema` can be used to
validate SPDX 3 documents, there are a few context-aware checks that can be
useful. This includes:

1. Ignored SHACL errors for missing `spdxId`s if they are defined in an
   `ExternalMap`
2. Validation that any `spdxId` defined in an `ExternalMap` are _not_ present
   in the document
3. SHACL Validation of merged documents (in this way, if you reference an
   `spdxId` from an `ExternalMap` and then pass the document that provides that
   `spdxId`, the type can be validated). Blank nodes are kept apart per
   document; `spdxId`s are shared
4. (Hopefully) More useful JSON schema error output

## Installation

`spdx3-validate` can be installed using `pip`:

```shell
python3 -m pip install spdx3-validate
```

## Using as a library

`spdx3-validate` can also be used programmatically.
`validate()` takes a single source or an iterable of sources
(a path or a URL) and returns a `ValidationResult`:

```python
import spdx3_validate

result = spdx3_validate.validate("doc.spdx3.json")
if not result:
    print(result)  # prints the errors, one per line

# Or inspect the individual findings:
for error in result.errors:
    print(error)
```

- The SPDX version is detected from each document's `@context`;
  pass `version="X.Y"` to force one.
- Set `check_merged=True` to also validate the merged graph of several
  documents together. Blank nodes in its errors are prefixed with the
  document's position: `_:d1_CreationInfo0` is `_:CreationInfo0` in the
  second document. An Element `spdxId` defined in more than one
  document is an error; import it with an `ExternalMap` instead.
- A document that cannot be loaded (missing `@context`, unknown version,
  incompatible versions) raises `spdx3_validate.SpdxValidateError`.

## Developing

Developing on `spdx3-validate` is best done using a virtual environment. You
can configure one and install spdx3-validate in editable mode with all
necessary development dependencies by running:

```shell
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## TODO

- Option to automatically download dependencies based on `locationHint`
- Offline validation?
- Cache downloaded context
