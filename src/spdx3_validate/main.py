# Copyright (c) 2024 Joshua Watt
#
# SPDX-License-Identifier: MIT

import argparse
import halo
import json
import jsonschema
import pyshacl
import rdflib
import sys
import textwrap
import urllib.request

from rdflib import RDF, RDFS, SH, URIRef

from pathlib import Path
from .version import VERSION
from .spdx_versions import find_version, SPDX_VERSIONS


def read_location(location):
    if "://" in location:
        with urllib.request.urlopen(location) as f:
            return f.read()
    elif location == "-":
        return sys.stdin.read()
    else:
        with Path(location).open("r") as f:
            return f.read()


def derives_from(cls, target, shacl_graph):
    if cls == target:
        return True

    for subclass in shacl_graph.objects(cls, RDFS.subClassOf):
        if derives_from(subclass, target, shacl_graph):
            return True

    return False


def check_graph(graph, shacl_graph, current_version, error_external):
    errors = []

    conforms, results, _ = pyshacl.validate(
        graph,
        shacl_graph=shacl_graph,
        ont_graph=shacl_graph,
    )

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri):
            return nm.normalizeUri(uri)

        def pnode(n):
            if n:
                return n.n3()
            return "-"

        # Collect all external map references
        external_spdxids = set()
        for spdxid in current_version.get_imports(graph):
            # If the SpdxID is in the graph as a subject, than do
            # not mark it as an external SpdxID, since there is a
            # resolved definition for it
            if (spdxid, None, None) in graph:
                if error_external:
                    errors.append(
                        f"ERROR: {str(spdxid)} in an ExternalMap and also defined in the document"
                    )
            else:
                external_spdxids.add(str(spdxid))

        def check_external_ref_error(r):
            if (r, RDF.type, SH.ValidationResult) not in results:
                return False

            if (r, SH.resultSeverity, SH.Violation) not in results:
                return False

            if (
                r,
                SH.sourceConstraintComponent,
                SH.ClassConstraintComponent,
            ) not in results:
                return False

            is_element = False
            for ss in results.objects(r, SH.sourceShape):
                if is_element:
                    break

                for cls in results.objects(ss, SH["class"]):
                    is_element = derives_from(
                        cls,
                        URIRef(current_version.rdf_base + "Core/Element"),
                        shacl_graph,
                    )
                    if is_element:
                        break

            if not is_element:
                return False

            for v in results.objects(r, SH.value):
                if str(v) in external_spdxids:
                    return True

            return False

        for report in results.subjects(RDF.type, SH.ValidationReport):
            for r in results.objects(report, SH.result):
                if check_external_ref_error(r):
                    continue

                e = []
                e.append(
                    f"Violation of type {norm(results.value(r, SH.sourceConstraintComponent))}:"
                )
                e.append(f"\tSeverity: {norm(results.value(r, SH.resultSeverity))}")
                pg = rdflib.Graph()
                pg += results.triples((results.value(r, SH.sourceShape), None, None))
                if pg:
                    e.append("\tSource Shape:")
                    e.append(
                        textwrap.indent(pg.serialize(format="ttl").strip(), "\t\t")
                    )
                e.append(f"\tFocus Node: {pnode(results.value(r, SH.focusNode))}")
                e.append(f"\tValue Node: {pnode(results.value(r, SH.value))}")
                e.append(f"\tResult path: {pnode(results.value(r, SH.resultPath))}")
                e.append(f"\tMessage: {results.value(r, SH.resultMessage) or '-'}")
                e.append("")

                errors.append("\n".join(e))

    return errors


def iter_validation_errors(err):
    if err.context:
        for e in err.context:
            yield e
            yield from iter_validation_errors(e)


def print_schema_error(err, filename, indent=0):
    def print_err(e, indent, fn=None, message=False):
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

        error_map = {}
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


def main(cmdline_args=None):
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
        help="SPDX Version to use, or 'auto' to determine version from input files",
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
    args = parser.parse_args(cmdline_args)

    if args.spdx_version != "auto":
        for v in SPDX_VERSIONS:
            if v.pretty == args.version:
                current_version = v
                break
        else:
            print(f"Unknown SPDX version {args.version}")
            return 1
    else:
        current_version = None

    return spdx3validate(args.json, current_version, args.check_merged, args.quiet)


def spdx3validate(json_files, current_version="3.0.1", check_merged=False, quiet=True):
    files = []
    for j in json_files:
        with halo.Halo(f"Loading {j}", enabled=not quiet) as spinner:
            s = read_location(j)
            d = json.loads(s)
            if "@context" not in d:
                spinner.fail()
                print(f"No @context found in {j}")
                return 1

            version = find_version(d["@context"])
            if version is None:
                spinner.fail()
                print(f"{j} has unknown version @context {d['@context']}")
                return 1

            if current_version is None:
                current_version = version
            elif current_version != version:
                spinner.fail()
                print(
                    f"{j} has incompatible version {version.pretty}. Other documents are {current_version.pretty}"
                )
                return 1

            graph = rdflib.Graph()
            graph.parse(data=s, format="json-ld")

            files.append((j, d, graph))
            spinner.succeed()

    if not files:
        # Nothing to do
        return 0

    with halo.Halo(
        f"Loading SPDX {current_version.pretty}", enabled=not quiet
    ) as spinner:
        with urllib.request.urlopen(current_version.schema_url) as f:
            schema = json.load(f)

        shacl_graph = rdflib.Graph()
        shacl_graph.parse(current_version.shacl_url)
        spinner.succeed()

    errors = 0

    for fn, json_data, g in files:
        with halo.Halo(f"Validating schema for {fn}", enabled=not quiet) as spinner:
            validator_cls = jsonschema.validators.validator_for(schema)

            try:
                validator_cls.check_schema(schema)
            except jsonschema.exceptions.SchemaError as e:
                spinner.fail(f"Invalid schema {current_version.schema_url}: {e}")
                return 1

            validator = validator_cls(schema)
            json_errors = list(validator.iter_errors(json_data))
            if json_errors:
                spinner.fail()
            else:
                spinner.succeed()

        if json_errors:
            print(f"ERROR: JSON Schema validation failed for {fn}:")
            for e in json_errors:
                print_schema_error(e, fn)
                errors += 1

        with halo.Halo(f"Checking SHACL for {fn}", enabled=not quiet) as spinner:
            e = check_graph(g, shacl_graph, current_version, True)
            if e:
                spinner.fail()
            else:
                spinner.succeed()

        if e:
            print(f"ERROR: SHACL Validation failed for {fn}:")
            print("\n".join(e))
            errors += 1

    if len(files) > 1 and check_merged:
        if not errors:
            with halo.Halo("Checking merged graph", enabled=not quiet) as spinner:
                merged_g = rdflib.Graph()
                for _, _, g in files:
                    merged_g += g

                e = check_graph(g, shacl_graph, current_version, False)
                if e:
                    spinner.fail()
                else:
                    spinner.succeed()

            if e:
                print("ERROR: SHACL Validation failed on merged files:")
                print("\n".join(e))
                errors += 1
        else:
            print(
                "WARNING: Skipping validation of merged documents due to previous errors"
            )

    return 1 if errors else 0
