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
   `spdxId`, the type can be validated)
4. (Hopefully) More useful JSON schema error output

## Installation

`spdx3-validate` can be installed using `pip`:

```shell
python3 -m pip install spdx3-validate
```

## Usage

```shell
spdx3-validate -j sbom.json
```

### Options

All available options can be listed by this command:

```shell
spdx3-validate -h
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
  documents together.
- A document that cannot be loaded (missing `@context`, unknown version,
  incompatible versions) raises `spdx3_validate.SpdxValidateError`.

### Validating many documents

`validate()` loads the schema and SHACL model on every call. To validate
repeatedly with the same model, create a `Validator`, which loads them once
(on first use) and keeps them in memory. Nothing is written to disk, and a new
process loads everything again. It takes the same resource options as `validate()`; pass
`check_merged` to its `validate()` method:

```python
v = spdx3_validate.Validator(model_dir="/path/to/spdx_models")
for path in paths:
    print(v.validate(path))
```

A `Validator` binds to one SPDX version (detected from the first document, or
given as `version=`) and can be shared between threads; validations running
during a `reload()` finish on the previous model. It does not re-read its
resources by itself; call `v.reload()` if the model is served from a moving URL
(for example a `-dev` build). If the model is marked pre-release, loading
issues a `spdx3_validate.PreReleaseWarning` (a `FutureWarning`); `v.is_pre_release` reports it and `pre_release=True`
or `False` overrides it (CLI: `--pre-release` / `--no-pre-release`).

## Offline validation

`spdx3-validate` can perform offline validation without fetching schemas or
SHACL models over the network.

### Command-line options

You can explicitly specify local paths or URLs for the JSON Schema,
SHACL shapes, and JSON-LD @context:

```shell
spdx3-validate --json document.json \
  --schema /path/to/spdx-json-schema.json \
  --shapes /path/to/spdx-model.ttl \
  --context /path/to/spdx-context.jsonld
```

### Model directory (`--model-dir` or `SPDX3VALIDATE_MODEL_DIR`)

Alternatively, pass `--model-dir`, or set the `SPDX3VALIDATE_MODEL_DIR`
environment variable (the flag takes precedence), pointing to a directory
structured by SPDX model version:

```text
<SPDX3VALIDATE_MODEL_DIR>/
└── v[VERSION]/
    ├── spdx-context.jsonld
    ├── spdx-json-schema.json
    └── spdx-model.ttl
```

For example:

```shell
export SPDX3VALIDATE_MODEL_DIR=/path/to/spdx_models
spdx3-validate -j document.json

# or
spdx3-validate -j document.json --model-dir /path/to/spdx_models
```

### Offline library validation

The library does not read `SPDX3VALIDATE_MODEL_DIR`; that variable and
`--model-dir` are command-line only. For offline library validation, pass
`model_dir` or explicit resource lists
(`schema_urls`, `shacl_urls`, `context_urls`):

```python
# Using local model directory
result = spdx3_validate.validate(
  "doc.spdx3.json",
  model_dir="/path/to/spdx_models",
)

# Or specifying explicit local file paths / URLs:
result = spdx3_validate.validate(
  "doc.spdx3.json",
  schema_urls=["/path/to/spdx-json-schema.json"],
  shacl_urls=["/path/to/spdx-model.ttl"],
  context_urls=["/path/to/spdx-context.jsonld"],
)
```

Missing local model files, and schema, shapes, or context locations that cannot
be read, raise `spdx3_validate.ResourceNotFoundError`. Malformed JSON, an invalid shapes file,
and a context that does not match the document's SPDX version raise
`spdx3_validate.SpdxValidateError`. On the command line they are reported as
an error message.

Each resource can be a single string or a list. Lists accept more than one entry
for future use, but only the
first entry is used today; passing more issues a `UserWarning` (the command
line prints a warning and uses the first).

### Order of precedence

For each validation resource (JSON schema, SHACL shapes, JSON-LD context),
`spdx3-validate` evaluates resolution independently in strict order:

1. **Explicit parameters / CLI flags**
   (`schema_urls`, `shacl_urls`, `context_urls` /
   `--schema`, `--shapes`, `--context`):
   Used exclusively if provided.
   Raises `ResourceNotFoundError` if the specified local file does not exist.
2. **Model directory (`model_dir` / `--model-dir` / `SPDX3VALIDATE_MODEL_DIR`)**:
   Evaluated if explicit parameters or CLI flags are omitted.
   Looks for `<model_dir>/v[VERSION]/[file]`.
   Raises `ResourceNotFoundError` if the expected model file is missing.
3. **Network default**:
   Used only when neither explicit parameters, CLI flags, nor model directory
   are specified.

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
- Cache downloaded context
