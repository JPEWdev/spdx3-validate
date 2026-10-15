# SPDX-FileContributor: Joshua Watt
# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2024-2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

from __future__ import annotations

import argparse
import os
import sys
import warnings
from typing import Any, Dict, Iterator, List, Optional, Sequence, Union

import halo
import jsonschema
import rdflib

from .version import VERSION
from .spdx_versions import SPDX_VERSIONS, SpdxVersion
from .core import (
    Document,
    SpdxValidateError,
    _Locations,
    UnknownVersionError,
    PreReleaseWarning,
    Validator,
    _resolve_version,
)


def _read_stdin() -> str:
    try:
        return sys.stdin.read()
    except UnicodeDecodeError as e:
        raise SpdxValidateError(f"Cannot decode -: {e}") from e


def iter_validation_errors(
    err: jsonschema.exceptions.ValidationError,
) -> Iterator[jsonschema.exceptions.ValidationError]:
    if err.context:
        for e in err.context:
            yield e
            yield from iter_validation_errors(e)


def print_schema_error(
    err: jsonschema.exceptions.ValidationError, filename: str, indent: int = 0
) -> None:
    def print_err(
        e: jsonschema.exceptions.ValidationError,
        indent: int,
        fn: Optional[str] = None,
        message: bool = False,
    ) -> None:
        loc = e.json_path
        if fn:
            loc = f"{fn}::{loc}"

        if isinstance(e.instance, str):
            m = e.message
        else:
            m = "Is not valid"

        print((" " * indent) + f"{loc}: {m}")

    print_err(err, indent, filename)

    if err.context:
        i_str = " " * (indent + 2)
        print(i_str + "This error was caused by other underlying errors:")

        error_map: Dict[Any, jsonschema.exceptions.ValidationError] = {}
        for e in iter_validation_errors(err):
            if isinstance(e, str):
                error_map[(tuple(e.absolute_path), e.message)] = e
            else:
                error_map[(tuple(e.absolute_path), "")] = e

        error_list = [
            error_map[k]
            for k in sorted(
                error_map.keys(),
                key=lambda k: (len(k[0]), k[0], k[1]),
                reverse=True,
            )
        ]
        for e in error_list:
            print_err(e, indent + 4, message=True)

    print()


def main(cmdline_args: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description=f"Validate SPDX 3 files Version {VERSION}"
    )

    parser.add_argument(
        "--json",
        "-j",
        default=[],
        action="append",
        help="Validate SPDX 3 JSON file (URL, path, or '-')",
    )
    parser.add_argument(
        "--spdx-version",
        "-s",
        default="auto",
        choices=[v.pretty for v in SPDX_VERSIONS] + ["auto"],
        help=("SPDX version to use, or 'auto' to determine version from input files"),
    )
    parser.add_argument(
        "--version",
        "-V",
        action="version",
        version=VERSION,
    )
    parser.add_argument(
        "--no-merge",
        action="store_false",
        dest="check_merged",
        help="Do not validate merged documents",
    )
    parser.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Run quietly (do not show progress)",
    )
    parser.add_argument(
        "--model-dir",
        help=(
            "Directory with versioned models (v[VERSION]/spdx-json-schema.json, "
            "spdx-model.ttl, spdx-context.jsonld) "
            "(default: $SPDX3VALIDATE_MODEL_DIR)"
        ),
    )
    parser.add_argument(
        "--pre-release",
        action="store_true",
        default=None,
        help="Treat the model as pre-release, overriding detection",
    )
    parser.add_argument(
        "--no-pre-release",
        action="store_false",
        dest="pre_release",
        help="Treat the model as stable, overriding detection",
    )
    parser.add_argument(
        "--schema",
        action="append",
        help=(
            "Location of JSON Schema for validation " "(only the first is used for now)"
        ),
    )
    parser.add_argument(
        "--shapes",
        action="append",
        help=(
            "Location of RDF model containing SHACL shapes "
            "(only the first is used for now)"
        ),
    )
    parser.add_argument(
        "--context",
        action="append",
        help="Location of JSON-LD @context (only the first is used for now)",
    )
    args = parser.parse_args(cmdline_args)

    if args.schema and len(args.schema) > 1:
        print(
            "WARNING: Multiple --schema options are not supported yet. "
            "Only the first one will be used.",
            file=sys.stderr,
        )
    if args.shapes and len(args.shapes) > 1:
        print(
            "WARNING: Multiple --shapes options are not supported yet. "
            "Only the first one will be used.",
            file=sys.stderr,
        )
    if args.context and len(args.context) > 1:
        print(
            "WARNING: Multiple --context options are not supported yet. "
            "Only the first one will be used.",
            file=sys.stderr,
        )

    current_version = None if args.spdx_version == "auto" else args.spdx_version
    model_dir = args.model_dir or os.environ.get("SPDX3VALIDATE_MODEL_DIR")

    return spdx3validate(
        args.json,
        current_version,
        args.check_merged,
        args.quiet,
        schema_urls=args.schema[:1] if args.schema else None,
        shacl_urls=args.shapes[:1] if args.shapes else None,
        context_urls=args.context[:1] if args.context else None,
        model_dir=model_dir,
        pre_release=args.pre_release,
    )


def spdx3validate(
    json_files: List[str],
    current_version: Union[str, SpdxVersion, None] = None,
    check_merged: bool = False,
    quiet: bool = True,
    schema_urls: _Locations = None,
    shacl_urls: _Locations = None,
    context_urls: _Locations = None,
    model_dir: Optional[str] = None,
    pre_release: Optional[bool] = None,
) -> int:
    try:
        resolved_version = _resolve_version(current_version)
    except UnknownVersionError as e:
        print(str(e))
        return 1
    validator = Validator(
        resolved_version,
        schema_urls=schema_urls,
        shacl_urls=shacl_urls,
        context_urls=context_urls,
        model_dir=model_dir,
        pre_release=pre_release,
    )

    documents: List[Document] = []
    for j in json_files:
        with halo.Halo(f"Loading {j}", enabled=not quiet) as spinner:
            try:
                doc = validator.load_document(j, _read_stdin() if j == "-" else None)
            except SpdxValidateError as e:
                spinner.fail()
                print(str(e))
                return 1

            if resolved_version is None:
                resolved_version = doc.version
            elif resolved_version != doc.version:
                spinner.fail()
                print(
                    f"{j} has incompatible version {doc.version.pretty}. "
                    f"Other documents are {resolved_version.pretty}"
                )
                return 1

            documents.append(doc)
            spinner.succeed()

    if not documents:
        # Nothing to do
        return 0

    if resolved_version is None:
        print("ERROR: Unable to determine SPDX version")
        return 1

    with halo.Halo(
        f"Loading SPDX {resolved_version.pretty}", enabled=not quiet
    ) as spinner:
        try:
            with warnings.catch_warnings(record=True) as caught:
                validator.load(resolved_version)  # user warning filters apply
            spinner.succeed()
        except (SpdxValidateError, Warning) as e:  # Warning: -W error filters
            spinner.fail()
            print(str(e))
            return 1

    for w in caught:
        if issubclass(w.category, PreReleaseWarning):
            print(
                f"WARNING: SPDX {resolved_version.pretty} model is marked "
                "pre-release; it may change between runs",
                file=sys.stderr,
            )
        else:
            warnings.showwarning(w.message, w.category, w.filename, w.lineno)

    errors = 0

    for doc in documents:
        with halo.Halo(
            f"Validating schema for {doc.source}", enabled=not quiet
        ) as spinner:
            try:
                json_errors = validator._schema_errors(doc)
            except SpdxValidateError as e:
                spinner.fail()
                print(str(e))
                return 1
            if json_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if json_errors:
            print(f"ERROR: JSON Schema validation failed for {doc.source}:")
            for json_err in json_errors:
                print_schema_error(json_err, doc.source)
                errors += 1

        with halo.Halo(
            f"Checking SHACL for {doc.source}", enabled=not quiet
        ) as spinner:
            try:
                graph_errors = validator._shacl_errors(doc.graph, True)
            except SpdxValidateError as e:
                spinner.fail()
                print(str(e))
                return 1
            if graph_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if graph_errors:
            print(f"ERROR: SHACL Validation failed for {doc.source}:")
            print("\n".join(graph_errors))
            errors += 1

    if len(documents) > 1 and check_merged:
        if not errors:
            with halo.Halo("Checking merged graph", enabled=not quiet) as spinner:
                merged_g = rdflib.Graph()
                for doc in documents:
                    merged_g += doc.graph

                try:
                    graph_errors = validator._shacl_errors(merged_g, False)
                except SpdxValidateError as e:
                    spinner.fail()
                    print(str(e))
                    return 1
                if graph_errors:
                    spinner.fail()
                else:
                    spinner.succeed()

            if graph_errors:
                print("ERROR: SHACL Validation failed on merged files:")
                print("\n".join(graph_errors))
                errors += 1
        else:
            print(
                "WARNING: Skipping validation of merged documents due to previous errors"
            )

    return 1 if errors else 0
