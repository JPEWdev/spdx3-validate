# SPDX-FileContributor: Joshua Watt
# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

"""Core SPDX 3 validation engine.

This module is the library heart of ``spdx3-validate``. It performs no console
output: loading problems are raised as :class:`SpdxValidateError`, and the
validation findings themselves are returned as data. The command-line interface
in :mod:`spdx3_validate.main` builds its progress spinners and error printing on
top of these primitives.
"""

from __future__ import annotations

import json
import os
import textwrap
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import jsonschema
import pyshacl
import rdflib
from rdflib import RDF, RDFS, SH, BNode, URIRef
from rdflib.term import Node

from .spdx_versions import SPDX_VERSIONS, SpdxVersion, find_version


class SpdxValidateError(Exception):
    """Base class for errors raised while loading or validating documents."""


class UnknownVersionError(SpdxValidateError):
    """The requested SPDX version, or a document's ``@context``, is unknown."""


@dataclass
class ValidationError:
    """A single validation finding, attributed to the document it came from.

    Attributes:
        source: The document the error was found in (its :attr:`Document.source`).
            For a merged-graph check this is ``"(merged)"``.
        kind: ``"schema"`` for JSON Schema errors, ``"shacl"`` for SHACL ones.
        message: The human-readable description of the problem.
    """

    source: str
    kind: str
    message: str

    def __str__(self) -> str:
        return f"{self.source} [{self.kind}]: {self.message}"


def _resolve_version(
    version: Union[str, SpdxVersion, None],
) -> Optional[SpdxVersion]:
    """Normalise a version argument to a :class:`SpdxVersion` or ``None``.

    Accepts ``None`` (auto-detect from the documents), a :class:`SpdxVersion`,
    or a version string such as ``"3.0.1"``.
    """
    if version is None or isinstance(version, SpdxVersion):
        return version

    for v in SPDX_VERSIONS:
        if v.pretty == version:
            return v

    raise UnknownVersionError(f"Unknown SPDX version {version}")


def read_location(location: str) -> str:
    """Read the contents of a path or an URL."""
    if "://" in location:
        with urllib.request.urlopen(location) as f:
            content: bytes = f.read()
            return content.decode("utf-8")
    with Path(location).open("r", encoding="utf-8") as f:
        return f.read()


@dataclass
class Document:
    """An SPDX 3 document loaded from a source location.

    Attributes:
        source: Where the document came from. A path or URL for documents
            loaded with :meth:`load`, or any caller-supplied label for
            documents built with :meth:`from_text`.
        data: The parsed JSON content.
        graph: The document parsed as an RDF graph.
        version: The SPDX version detected from the document's ``@context``.
    """

    source: str
    data: Dict[str, Any]
    graph: rdflib.Graph
    version: SpdxVersion

    @classmethod
    def load(cls, source: str) -> Document:
        """Load and parse an SPDX 3 document from a path or URL.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
        """
        return cls.from_text(source, read_location(source))

    @classmethod
    def from_text(cls, source: str, text: str) -> Document:
        """Parse an SPDX 3 document already held in memory.

        Args:
            source: A label identifying the document (e.g. a filename), used
                only to attribute errors to it.
            text: The raw JSON-LD document content.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
        """
        data = json.loads(text)

        if "@context" not in data:
            raise SpdxValidateError(f"No @context found in {source}")

        version = find_version(data["@context"])
        if version is None:
            raise UnknownVersionError(
                f"{source} has unknown version @context {data['@context']}"
            )

        graph = rdflib.Graph()
        graph.parse(data=text, format="json-ld")

        return cls(source, data, graph, version)


def load_validation_data(version: SpdxVersion) -> Tuple[Dict[str, Any], rdflib.Graph]:
    """Download the JSON Schema and SHACL model for an SPDX *version*.

    Returns a ``(schema, shacl_graph)`` tuple.
    """
    with urllib.request.urlopen(version.schema_url) as f:
        schema = json.load(f)

    shacl_graph = rdflib.Graph()
    shacl_graph.parse(version.shacl_url)

    return schema, shacl_graph


def schema_validator(schema: Dict[str, Any]) -> jsonschema.protocols.Validator:
    """Return a ``jsonschema`` validator, checking that *schema* is well formed.

    Raises:
        jsonschema.exceptions.SchemaError: The schema itself is invalid.
    """
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)
    # validator_for()'s return type varies with the jsonschema/types-jsonschema
    # version resolved, so assign through an annotation instead of cast() --
    # cast() is flagged "redundant" in environments where this is already typed.
    validator: jsonschema.protocols.Validator = validator_cls(schema)
    return validator


def _schema_error(
    source: str, err: jsonschema.exceptions.ValidationError
) -> ValidationError:
    """Build a :class:`ValidationError` from a ``jsonschema`` error."""
    if isinstance(err.instance, str):
        message = err.message
    else:
        message = "Is not valid"
    return ValidationError(source, "schema", f"{err.json_path}: {message}")


def derives_from(cls: Node, target: Node, shacl_graph: rdflib.Graph) -> bool:
    """Return True if RDF class *cls* is, or derives from, *target*."""
    if cls == target:
        return True

    for subclass in shacl_graph.objects(cls, RDFS.subClassOf):
        if derives_from(subclass, target, shacl_graph):
            return True

    return False


def merge_graphs(graphs: Iterable[rdflib.Graph]) -> rdflib.Graph:
    """Return the RDF merge of *graphs*, keeping each graph's blank nodes apart.

    A blank-node label is local to its document, so the same label (e.g.
    ``_:CreationInfo0``) in two documents names two different nodes. Each
    graph's blank nodes are renamed ``_:d<i>_<label>``, where *i* is the
    graph's 0-based position, before its triples are added. Names cannot
    collide because ``<i>`` holds no ``_``, and a label written in the
    document (such as ``CreationInfo0``) stays readable in error messages.
    IRIs are left as they are, so elements shared by ``spdxId`` still meet
    across documents.
    """
    merged = rdflib.Graph()
    for i, graph in enumerate(graphs):
        prefix = f"d{i}_"

        def rename(term: Node) -> Node:
            return BNode(prefix + term) if isinstance(term, BNode) else term

        for s, p, o in graph:
            merged.add((rename(s), rename(p), rename(o)))
    return merged


def duplicate_definitions(
    documents: Sequence[Document], shacl_graph: rdflib.Graph, version: SpdxVersion
) -> List[str]:
    """Report each Element ``spdxId`` that more than one document defines.

    An Element is defined where it is a subject typed with a subclass of
    ``Core/Element``. SPDX expects one definition per Element, with other
    documents referring to it through an ``ExternalMap``; two definitions give
    it two ``creationInfo`` values, which the merged SHACL check also rejects.
    IRI-named non-Elements (such as a shared ``CreationInfo``) are not counted.
    """
    element = URIRef(version.rdf_base + "Core/Element")
    defined_in: Dict[URIRef, List[str]] = {}
    for doc in documents:
        for subject in set(doc.graph.subjects(RDF.type, None)):
            if isinstance(subject, URIRef) and any(
                derives_from(cls, element, shacl_graph)
                for cls in doc.graph.objects(subject, RDF.type)
            ):
                defined_in.setdefault(subject, []).append(doc.source)
    return [
        f"ERROR: {spdxid} is defined in more than one document "
        f"({', '.join(sources)}); define it in one and import it in the others "
        "with an ExternalMap"
        for spdxid, sources in defined_in.items()
        if len(sources) > 1
    ]


def _source_key(source: str) -> Tuple[str, ...]:
    """Identify a source so the same document given twice is merged once."""
    if source == "-":
        return ("stdin",)
    path = source
    if source.startswith("file:"):
        path = urllib.request.url2pathname(urllib.parse.urlparse(source).path)
    elif "://" in source:
        return ("url", source)
    try:
        st = os.stat(path)  # also matches hard links and case-insensitive names
        return ("file", str(st.st_dev), str(st.st_ino))
    except OSError:
        return ("path", os.path.realpath(path))


def merged_errors(
    documents: Sequence[Document], shacl_graph: rdflib.Graph, version: SpdxVersion
) -> List[str]:
    """Validate the RDF merge of *documents*, returning error strings.

    A source given more than once is merged once. Elements defined in more
    than one document are reported first, then the SHACL results.
    """
    first: Dict[Tuple[str, ...], Document] = {}
    for d in documents:
        first.setdefault(_source_key(d.source), d)  # keeps input order
    unique = list(first.values())
    if len(unique) < 2:
        return []
    merged = merge_graphs(d.graph for d in unique)
    return duplicate_definitions(unique, shacl_graph, version) + check_graph(
        merged, shacl_graph, version, False
    )


def check_graph(
    graph: rdflib.Graph,
    shacl_graph: rdflib.Graph,
    current_version: SpdxVersion,
    error_external: bool,
) -> List[str]:
    """Validate *graph* against *shacl_graph*, returning a list of error strings.

    External ``spdxId`` references declared in an ``ExternalMap`` are not
    reported as missing. When *error_external* is true, an ``spdxId`` that is
    both imported and defined in the document is reported as an error.
    """
    errors: List[str] = []

    # pyshacl.validate() has no return type annotation, so its result is
    # typed here via annotation to restore type checking for the rest of
    # this function.
    validate_result: Tuple[bool, rdflib.Graph, str] = pyshacl.validate(
        graph,
        shacl_graph=shacl_graph,
        ont_graph=shacl_graph,
    )
    conforms, results, _ = validate_result

    # Collect all external map references
    external_spdxids: set[str] = set()
    # A document may list the same spdxId in several ExternalMaps; report once.
    for spdxid in dict.fromkeys(current_version.get_imports(graph)):
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

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri: Optional[Node]) -> str:
            assert uri is not None
            return nm.normalizeUri(str(uri))

        def pnode(n: Optional[Node]) -> str:
            if n:
                return n.n3()
            return "-"

        def check_external_ref_error(r: Node) -> bool:
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

                e: List[str] = []
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


@dataclass
class ValidationResult:
    """The outcome of validating one or more SPDX 3 documents.

    ``errors`` is a list of :class:`ValidationError`. A result is truthy when
    validation passed, so it reads naturally::

        result = validate("sbom.json")
        if not result:
            print(result)  # prints the errors, one per line
    """

    errors: List[ValidationError] = field(default_factory=list)

    @property
    def valid(self) -> bool:
        """True when no validation errors were found."""
        return not self.errors

    def __bool__(self) -> bool:
        return self.valid

    def __str__(self) -> str:
        return "\n".join(str(e) for e in self.errors)


def validate(
    sources: Union[str, Iterable[str]],
    *,
    version: Union[str, SpdxVersion, None] = None,
    check_merged: bool = False,
) -> ValidationResult:
    """Validate one or more SPDX 3 documents against schema and SHACL rules.

    Args:
        sources: A single path or URL, or an iterable of them.
        version: SPDX version to validate against (e.g. ``"3.0.1"``). When
            ``None`` (the default) the version is detected from each document's
            ``@context``.
        check_merged: Also validate the graph formed by merging every document,
            which catches type errors across ``ExternalMap`` references. Skipped
            if any document already failed.

    Returns:
        ValidationResult: The collected :class:`ValidationError` findings
            (empty when everything is valid).

    Raises:
        SpdxValidateError: A document cannot be loaded, or documents declare
            incompatible versions.
        UnknownVersionError: *version* or a document ``@context`` is unknown.
    """
    if isinstance(sources, str):
        sources = [sources]

    resolved_version = _resolve_version(version)

    documents: List[Document] = []
    for source in sources:
        doc = Document.load(source)
        if resolved_version is None:
            resolved_version = doc.version
        elif doc.version != resolved_version:
            raise SpdxValidateError(
                f"{source} has incompatible version {doc.version.pretty}. "
                f"Other documents are {resolved_version.pretty}"
            )
        documents.append(doc)

    if not documents:
        return ValidationResult()

    # documents is non-empty, so the loop above set resolved_version at least once.
    assert resolved_version is not None

    schema, shacl_graph = load_validation_data(resolved_version)

    try:
        validator = schema_validator(schema)
    except jsonschema.exceptions.SchemaError as e:
        raise SpdxValidateError(
            f"Invalid schema {resolved_version.schema_url}: {e}"
        ) from e

    errors: List[ValidationError] = []
    for doc in documents:
        errors.extend(
            _schema_error(doc.source, e) for e in validator.iter_errors(doc.data)
        )
        errors.extend(
            ValidationError(doc.source, "shacl", msg)
            for msg in check_graph(doc.graph, shacl_graph, resolved_version, True)
        )

    if len(documents) > 1 and check_merged and not errors:
        errors.extend(
            ValidationError("(merged)", "shacl", msg)
            for msg in merged_errors(documents, shacl_graph, resolved_version)
        )

    return ValidationResult(errors)
