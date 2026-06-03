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

`spdx3-validate` can be installed using either `pip`
or [`pipx`](https://github.com/pypa/pipx):

```shell
python3 -m pip install spdx3-validate
```

or

```shell
pipx install spdx3-validate
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

```text
options:
  -h, --help            show this help message and exit
  --json, -j JSON       Validate SPDX 3 JSON file (URL, path, or '-')
  --spdx-version, -s {3.0.0,3.0.1,auto}
                        SPDX Version to use, or 'auto' to determine version
                        from input files
  --version, -V         show program's version number and exit
  --no-merge            Do not validate merged documents
  --quiet, -q           Run quietly (do not show progress)
```
  
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

* Option to automatically download dependencies based on `locationHint`
* Offline validation?
