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

import http.client
import json
import os
import re
import sys
import textwrap
import threading
import urllib.request
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from types import FrameType
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Type, Union

import jsonschema
import pyshacl
import rdflib
from rdflib import OWL, RDF, RDFS, SH, URIRef
from rdflib.term import Node

from .spdx_versions import SPDX_VERSIONS, SpdxVersion, find_version

# One location, or a list of them (only the first is used so far).
_PathLike = Union[str, "os.PathLike[str]"]
_Locations = Union[_PathLike, Sequence[_PathLike], None]


_TIMEOUT = 60  # seconds, for each network read


class SpdxValidateError(Exception):
    """Base class for errors raised while loading or validating documents."""


class UnknownVersionError(SpdxValidateError):
    """The requested SPDX version, or a document's ``@context``, is unknown."""


class ResourceNotFoundError(SpdxValidateError, FileNotFoundError):
    """A required document, schema, shape, or context could not be found or read."""


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
        try:
            with urllib.request.urlopen(location, timeout=_TIMEOUT) as f:
                content: bytes = f.read()
                return content.decode("utf-8")
        except (OSError, ValueError, http.client.HTTPException) as e:  # bad URL/body
            raise ResourceNotFoundError(f"Failed to read URL {location}: {e}") from e
    try:
        with Path(location).open("r", encoding="utf-8-sig") as f:
            return f.read()
    except FileNotFoundError as e:
        raise ResourceNotFoundError(f"File not found: {location}") from e
    except OSError as e:
        raise ResourceNotFoundError(f"Failed to read {location}: {e}") from e
    except ValueError as e:  # not UTF-8
        raise SpdxValidateError(f"Cannot decode {location}: {e}") from e


def _read_failure(kind: str, location: str, err: Exception) -> ResourceNotFoundError:
    return ResourceNotFoundError(f"Failed to read {kind} {location}: {err}")


def _read_json(location: str, kind: str) -> Any:
    """Read JSON from a path or URL; failures raise ResourceNotFoundError."""
    try:
        if "://" in location:
            with urllib.request.urlopen(location, timeout=_TIMEOUT) as f:
                raw: bytes = f.read()
        else:
            with open(location, "rb") as f:
                raw = f.read()
    except (OSError, ValueError, http.client.HTTPException) as e:  # bad URL/body
        raise _read_failure(kind, location, e) from e
    try:
        return json.loads(raw)
    except (ValueError, RecursionError) as e:  # malformed JSON or not UTF-8
        raise SpdxValidateError(f"Invalid JSON in {kind} {location}: {e}") from e


def _check_context_matches(
    graph: rdflib.Graph,
    data: Dict[str, Any],
    version: SpdxVersion,
    source: str,
    location: str,
) -> None:
    """Fail if an override context leaves a document without SPDX terms.

    A context for another version, or one that maps no SPDX terms, would leave
    SHACL with nothing to check, so the document would pass unvalidated.
    """
    has_content = bool(data.get("@graph")) or any(
        k not in ("@context", "@graph") for k in data
    )
    # Any type or property in the version's namespace shows the context fits.
    iris = {str(t) for t in graph.objects(None, RDF.type)}
    iris.update(str(p) for p in graph.predicates())
    if has_content and not any(i.startswith(version.rdf_base) for i in iris):
        raise SpdxValidateError(
            f"Context {location} does not match SPDX {version.pretty}: "
            f"{source} has nothing in {version.rdf_base}"
        )


class PreReleaseWarning(FutureWarning):
    """The SPDX model in use is pre-release and may change."""


def _warn_unsupported(message: str, category: Type[Warning] = UserWarning) -> None:
    """Warn, attributed to the first caller outside this package."""
    level = 2
    frame: Optional[FrameType] = sys._getframe(1)
    pkg = __package__ or "spdx3_validate"
    while (
        frame is not None and str(frame.f_globals.get("__name__")).split(".")[0] == pkg
    ):
        frame, level = frame.f_back, level + 1
    warnings.warn(message, category, stacklevel=level)


def _first_location(urls: _Locations, name: str) -> Optional[List[str]]:
    """Normalise *urls* to a list of strings, keeping only the first entry."""
    if urls is None:
        return None
    items = [urls] if isinstance(urls, (str, os.PathLike)) else list(urls)
    paths = [os.fspath(u) for u in items]
    if len(paths) > 1:
        _warn_unsupported(
            f"Multiple {name} locations are not supported yet; "
            f"only the first one is used: {paths[0]}"
        )
        return paths[:1]
    return paths


def _parse_json(source: str, text: str) -> Tuple[Dict[str, Any], SpdxVersion]:
    """Parse document JSON and detect its SPDX version from ``@context``."""
    try:
        data = json.loads(text)
    except (ValueError, RecursionError) as e:
        raise SpdxValidateError(f"Invalid JSON in {source}: {e}") from e
    if not isinstance(data, dict):
        raise SpdxValidateError(f"{source} is not a JSON object")

    if "@context" not in data:
        raise SpdxValidateError(f"No @context found in {source}")

    version = find_version(data["@context"])
    if version is None:
        raise UnknownVersionError(
            f"{source} has unknown version @context {data['@context']}"
        )
    return data, version


def _context_location(
    version: SpdxVersion,
    context_urls: Optional[List[str]],
    model_dir: Optional[str],
) -> Optional[str]:
    """Resolve the context override: explicit URL > model_dir > None (default)."""
    if context_urls:
        location = context_urls[0]
        if ("://" not in location) and (not Path(location).is_file()):
            raise ResourceNotFoundError(
                f"Specified context file does not exist: {location}"
            )
        return location
    if model_dir:
        target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-context.jsonld"
        if not target_path.is_file():
            raise ResourceNotFoundError(
                f"JSON-LD context file {target_path.name} not found "
                f"in model directory at {target_path}"
            )
        return str(target_path)
    return None


def _read_context(location: str) -> Dict[str, Any]:
    """Read a JSON-LD context from a path or URL."""
    ctx_obj = _read_json(location, "@context")
    if not isinstance(ctx_obj, dict):
        raise SpdxValidateError(f"Context {location} must be a JSON object")
    return ctx_obj


def _parse_graph(
    source: str,
    data: Dict[str, Any],
    text: str,
    version: SpdxVersion,
    ctx_obj: Optional[Dict[str, Any]],
    override: Optional[str],
) -> rdflib.Graph:
    """Parse a document into RDF, substituting *ctx_obj* for ``@context`` if given.

    *override* is the location of a user-chosen context, which must fit *version*.
    """
    graph = rdflib.Graph()
    if ctx_obj is None:
        parse_text = text
    else:
        ctx_data = dict(data)  # only @context is replaced
        ctx_data["@context"] = ctx_obj["@context"] if "@context" in ctx_obj else ctx_obj
        parse_text = json.dumps(ctx_data)
    try:
        graph.parse(data=parse_text, format="json-ld")
    except OSError as e:  # rdflib fetches remote contexts itself
        raise _read_failure("@context", override or str(data["@context"]), e) from e
    except Exception as e:  # e.g. a malformed @context value
        raise SpdxValidateError(f"Cannot parse {source}: {e}") from e
    if override:
        _check_context_matches(graph, data, version, source, override)
    return graph


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
    def load(
        cls,
        source: _PathLike,
        *,
        context_urls: _Locations = None,
        model_dir: Optional[str] = None,
    ) -> Document:
        """Load and parse an SPDX 3 document from a path or URL.

        Raises:
            SpdxValidateError: The document has no ``@context``.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
            ResourceNotFoundError: The input document file or local context
                file does not exist.
        """
        source = os.fspath(source)
        return cls.from_text(
            source,
            read_location(source),
            context_urls=context_urls,
            model_dir=model_dir,
        )

    @classmethod
    def from_text(  # keep in step with Validator.load_document
        cls,
        source: str,
        text: str,
        *,
        context_urls: _Locations = None,
        model_dir: Optional[str] = None,
    ) -> Document:
        """Parse an SPDX 3 document already held in memory.

        Args:
            source: A label identifying the document (e.g. a filename), used
                only to attribute errors to it.
            text: The raw JSON-LD document content.
            context_urls: Optional list of local file paths or URLs for
                @context.
            model_dir: Optional model directory containing
                v[VERSION]/spdx-context.jsonld.

        Raises:
            SpdxValidateError: The document is not valid JSON or has no
                ``@context``, a context is malformed, or an override context
                does not match the document's SPDX version.
            UnknownVersionError: The ``@context`` is not a known SPDX version.
            ResourceNotFoundError: A specified context file does not exist or
                cannot be read.
        """
        data, version = _parse_json(source, text)
        location = _context_location(
            version, _first_location(context_urls, "context"), model_dir
        )
        ctx_obj = _read_context(location) if location else None
        graph = _parse_graph(source, data, text, version, ctx_obj, location)
        return cls(source, data, graph, version)


def _schema_location(
    version: SpdxVersion, schema_urls: Optional[List[str]], model_dir: Optional[str]
) -> str:
    """Where the schema comes from: explicit > model_dir > network default."""
    if schema_urls:
        location = schema_urls[0]
        if "://" not in location and not Path(location).is_file():
            raise ResourceNotFoundError(
                f"Specified schema file does not exist: {location}"
            )
        return location
    if model_dir:
        target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-json-schema.json"
        if not target_path.is_file():
            raise ResourceNotFoundError(
                f"Schema file {target_path.name} not found in "
                f"model directory at {target_path}"
            )
        return str(target_path)
    return version.schema_url


def _shapes_location(
    version: SpdxVersion, shacl_urls: Optional[List[str]], model_dir: Optional[str]
) -> str:
    """Where the SHACL shapes come from: explicit > model_dir > network default."""
    if shacl_urls:
        location = shacl_urls[0]
        if "://" not in location and not Path(location).is_file():
            raise ResourceNotFoundError(
                f"Specified shapes file does not exist: {location}"
            )
        return location
    if model_dir:
        target_path = Path(model_dir) / f"v{version.pretty}" / "spdx-model.ttl"
        if not target_path.is_file():
            raise ResourceNotFoundError(
                f"SHACL shapes file {target_path.name} not found in "
                f"model directory at {target_path}"
            )
        return str(target_path)
    return version.shacl_url


def load_validation_data(
    version: SpdxVersion,
    *,
    schema_urls: _Locations = None,
    shacl_urls: _Locations = None,
    model_dir: Optional[str] = None,
) -> Tuple[Dict[str, Any], rdflib.Graph]:
    """Load the JSON Schema and SHACL model for an SPDX *version*.

    Resolution precedence for each resource:
    explicit parameter (`schema_urls` / `shacl_urls`) > `model_dir`
    > network default.

    Args:
        version: The SPDX version to load models for.
        schema_urls: Optional list of local file paths or URLs for JSON Schema.
            Takes precedence over `model_dir`.
        shacl_urls: Optional list of local file paths or URLs for SHACL shapes.
            Takes precedence over `model_dir`.
        model_dir: Optional directory containing versioned models (v[VERSION]/).
            Used if explicit resource lists are omitted.

    Returns a ``(schema, shacl_graph)`` tuple.

    Raises:
        ResourceNotFoundError: A specified or expected schema or SHACL file
            does not exist or cannot be read.
        SpdxValidateError: The schema or shapes are malformed.
    """
    schema_urls = _first_location(schema_urls, "schema")
    shacl_urls = _first_location(shacl_urls, "shapes")
    actual_schema_url = _schema_location(version, schema_urls, model_dir)
    actual_shacl_url = _shapes_location(version, shacl_urls, model_dir)

    schema = _read_json(actual_schema_url, "schema")
    if not isinstance(schema, dict):
        raise SpdxValidateError(f"Schema {actual_schema_url} must be a JSON object")
    if not schema:
        _warn_unsupported(f"Schema {actual_schema_url} is empty; it accepts anything")

    shacl_graph = rdflib.Graph()
    try:
        shacl_graph.parse(actual_shacl_url)  # rdflib fetches URLs; no timeout
    except (OSError, http.client.HTTPException) as e:
        raise _read_failure("shapes", actual_shacl_url, e) from e
    except Exception as e:  # rdflib raises many parser-specific errors
        raise SpdxValidateError(f"Invalid shapes {actual_shacl_url}: {e}") from e

    if not len(shacl_graph):
        _warn_unsupported(f"Shapes {actual_shacl_url} are empty; nothing is checked")
    elif not any(
        str(c).startswith(version.rdf_base)
        for c in set(shacl_graph.objects(None, SH.targetClass))
        | set(shacl_graph.subjects(RDF.type, SH.NodeShape))  # implicit targets
    ):
        _warn_unsupported(
            f"Shapes {actual_shacl_url} target no classes in {version.rdf_base}; "
            f"SPDX {version.pretty} documents may not be checked"
        )
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


def schema_errors(
    validator: jsonschema.protocols.Validator, data: Any
) -> List[jsonschema.exceptions.ValidationError]:
    """Run *validator* on *data*; an unresolvable ``$ref`` raises SpdxValidateError."""
    try:
        return list(validator.iter_errors(data))
    except jsonschema.exceptions.ValidationError:
        raise
    except Exception as e:  # e.g. unresolvable $ref
        raise SpdxValidateError(f"Invalid schema: {e}") from e


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
    seen = set()
    todo = [cls]
    while todo:
        c = todo.pop()
        if c == target:
            return True
        if c not in seen:  # user shapes may contain subclass cycles
            seen.add(c)
            todo.extend(shacl_graph.objects(c, RDFS.subClassOf))
    return False


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
    try:
        validate_result: Tuple[bool, rdflib.Graph, str] = pyshacl.validate(
            graph,
            shacl_graph=shacl_graph,
            ont_graph=shacl_graph,
        )
    except pyshacl.errors.ReportableRuntimeError as err:  # malformed shapes
        raise SpdxValidateError(f"Invalid shapes: {err.message}") from err
    except Exception as err:  # e.g. re.error from a bad sh:pattern
        raise SpdxValidateError(f"Invalid shapes: {err}") from err
    conforms, results, _ = validate_result

    if not conforms:
        results.bind("sh", SH)
        nm = rdflib.namespace.NamespaceManager(results)

        def norm(uri: Optional[Node]) -> str:
            if uri is None:
                return "-"
            return nm.normalizeUri(str(uri))

        def pnode(n: Optional[Node]) -> str:
            if n:
                return n.n3()
            return "-"

        # Collect all external map references
        external_spdxids: set[str] = set()
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


# pyshacl re-adds these to the shapes graph on every run; pre-adding makes that a no-op.
_PYSHACL_SYSTEM_TRIPLES: Tuple[Tuple[URIRef, URIRef, URIRef], ...] = (
    (OWL.Class, RDFS.subClassOf, RDFS.Class),
    (OWL.DatatypeProperty, RDFS.subClassOf, RDF.Property),
)

_SH2CODE_PRE = URIRef("https://jpewdev.github.io/shacl2code/schema#isPreRelease")
_ADMS_STATUS = URIRef("http://www.w3.org/ns/adms#status")
_ADMS_NS = "http://purl.org/adms/status/"
_SEMIC_NS = "http://publications.europa.eu/resource/authority/dataset-status/"
_BIBO_STATUS = URIRef("http://purl.org/ontology/bibo/status")
_BIBO_DRAFT = "http://purl.org/ontology/bibo/status/draft"
_SCHEMA_STATUS = (
    URIRef("http://schema.org/creativeWorkStatus"),
    URIRef("https://schema.org/creativeWorkStatus"),
)
_VS_STATUS = URIRef("http://www.w3.org/2003/06/sw-vocab-status/ns#term_status")
# Differs from shacl2code: "+build" and a "v" prefix also count, and a plain
# "false"/"0" isPreRelease string is stable (shacl2code treats any string as true).
_SEMVER_PRE = re.compile(r"^v?\d+\.\d+(?:\.\d+)?[-+][0-9A-Za-z]")
_PRE_WORD = re.compile(r"\b(alpha|beta|dev|pre|rc|snapshot|test)\b", re.IGNORECASE)
_MAJOR_ZERO = re.compile(r"^v?0+(?:\.|$)")


def _ontology_is_pre_release(g: rdflib.Graph, onto: Node) -> bool:
    """Apply shacl2code's precedence to one ``owl:Ontology`` node."""
    flag = g.value(onto, _SH2CODE_PRE)
    if flag is not None:
        return str(flag).strip().lower() not in ("false", "0", "")
    adms = [str(o) for o in g.objects(onto, _ADMS_STATUS)]
    semic = [x for x in adms if x.startswith(_SEMIC_NS)]
    if semic:
        return _SEMIC_NS + "DEVELOP" in semic
    adms_orig = [x for x in adms if x.startswith(_ADMS_NS)]
    if adms_orig:
        return _ADMS_NS + "UnderDevelopment" in adms_orig
    bibo = [str(o) for o in g.objects(onto, _BIBO_STATUS)]
    if bibo:
        return _BIBO_DRAFT in bibo
    for prop in _SCHEMA_STATUS:
        work = [str(o) for o in g.objects(onto, prop)]
        if work:
            return any(x in ("Draft", "Incomplete") for x in work)
    vs = [str(o) for o in g.objects(onto, _VS_STATUS)]
    if vs:
        return any(x in ("unstable", "testing") for x in vs)
    return any(
        _SEMVER_PRE.match(v) or _PRE_WORD.search(v) or _MAJOR_ZERO.match(v)
        for v in (str(o).strip() for o in g.objects(onto, OWL.versionInfo))
    )


def _is_pre_release(g: rdflib.Graph, override: Optional[bool] = None) -> bool:
    """Whether the model is pre-release; any pre-release ontology node counts."""
    if override is not None:
        return override
    return any(
        _ontology_is_pre_release(g, o) for o in g.subjects(RDF.type, OWL.Ontology)
    )


def _warn_pre_release(version: SpdxVersion) -> None:
    _warn_unsupported(
        f"SPDX {version.pretty} model is marked pre-release; it may change. "
        "Call Validator.reload() to pick up changes.",
        PreReleaseWarning,
    )


@dataclass(frozen=True)
class _Model:
    """A loaded schema + SHACL model. Only no-op writes happen after construction."""

    version: SpdxVersion
    schema_validator: jsonschema.protocols.Validator
    shacl_graph: rdflib.Graph
    is_pre_release: bool


class Validator:
    """Validates SPDX 3 documents, loading the schema and SHACL model once.

    The loaded model and parsed contexts are kept in memory by this object only;
    nothing is cached on disk or shared with other validators or processes.

    Options and their precedence match :func:`validate`. The model is read on
    first use (:meth:`load`, :attr:`is_pre_release` or a non-empty
    :meth:`validate`). With ``version=None`` the validator binds to the first
    document's version.
    Resources are not re-read unless :meth:`reload` is called, which is only
    needed for models published at a moving URL. Safe to share between threads.

    Args:
        version: SPDX version, or ``None`` to detect it from the documents.
        schema_urls: Local paths or URLs for the JSON Schema.
        shacl_urls: Local paths or URLs for the SHACL shapes.
        context_urls: Local paths or URLs for the JSON-LD ``@context``.
        model_dir: Directory containing versioned models (``v[VERSION]/``).
        pre_release: Overrides the pre-release status read from the model.

    A :class:`FutureWarning` is issued when the loaded model is pre-release.
    """

    def __init__(
        self,
        version: Union[str, SpdxVersion, None] = None,
        *,
        schema_urls: _Locations = None,
        shacl_urls: _Locations = None,
        context_urls: _Locations = None,
        model_dir: Optional[str] = None,
        pre_release: Optional[bool] = None,
    ) -> None:
        self._version = _resolve_version(version)
        self._schema_urls = _first_location(schema_urls, "schema")
        self._shacl_urls = _first_location(shacl_urls, "shapes")
        self._context_urls = _first_location(context_urls, "context")
        self._model_dir = model_dir
        self._pre_release = pre_release
        self._model: Optional[_Model] = None
        self._contexts: Dict[str, Dict[str, Any]] = {}
        self._generation = 0  # bumped by reload() to drop in-flight context reads
        self._reload_seq = 0  # tickets so the latest reload() always wins
        self._installed_seq = 0
        self._lock = threading.Lock()
        self._loading = threading.local()

    @property
    def version(self) -> Optional[SpdxVersion]:
        """The SPDX version, or ``None`` until one is pinned or detected."""
        return self._version

    @property
    def is_pre_release(self) -> bool:
        """True if the model is pre-release. Loads the model if needed.

        Raises like :meth:`load`; with no version pinned or detected yet it
        raises :class:`SpdxValidateError`.
        """
        return self.load().is_pre_release

    def load(self, version: Union[str, SpdxVersion, None] = None) -> _Model:
        """Load the model now (instead of on first use) and return it.

        Raises:
            SpdxValidateError: No version is known, or it differs from the
                version this validator is bound to.
            UnknownVersionError: *version* is unknown.
            ResourceNotFoundError: A specified or expected model file is missing.

        A pre-release model issues a :class:`PreReleaseWarning` (after the
        model is stored, so an error filter leaves the validator loaded).
        """
        requested = _resolve_version(version)
        model = self._model
        if model is not None and (requested is None or requested == model.version):
            return model  # fast path: no lock while validating
        if requested and self._version and requested != self._version:
            raise SpdxValidateError(
                f"Validator is for SPDX {self._version.pretty}, not {requested.pretty}"
            )
        if getattr(self._loading, "on", False):
            raise SpdxValidateError(
                "Validator used from a warning handler while loading"
            )
        loaded: Optional[_Model] = None
        with self._lock:  # version re-checked below: another thread may have bound one
            if self._model is None:
                wanted = requested or self._version
                if wanted is None:
                    raise SpdxValidateError("Unable to determine SPDX version")
                self._loading.on = True  # a handler re-entering would deadlock
                try:
                    loaded = self._load_model(wanted)
                finally:
                    self._loading.on = False
                self._version = wanted
                self._model = loaded
            elif requested is not None and requested != self._model.version:
                raise SpdxValidateError(
                    f"Validator is for SPDX {self._model.version.pretty}, "
                    f"not {requested.pretty}"
                )
            model = self._model
        if loaded is not None and loaded.is_pre_release:
            _warn_pre_release(loaded.version)  # outside the lock: handlers may re-enter
        return model

    def __reduce__(self) -> Any:
        raise TypeError("Validator cannot be pickled; create one per process")

    def reload(self) -> None:
        """Re-read the model (if loaded) and drop the in-memory contexts.

        A validation running meanwhile keeps the model it started with; documents
        it parses after the swap may use the new contexts.
        """
        if getattr(self._loading, "on", False):
            raise SpdxValidateError(
                "Validator used from a warning handler while loading"
            )
        with self._lock:
            self._reload_seq += 1
            ticket = self._reload_seq
            current = self._model
        new = self._load_model(current.version) if current else None  # slow
        with self._lock:
            if ticket < self._installed_seq:  # a later reload() already finished
                return
            self._installed_seq = ticket
            if new is not None:
                self._model = new
            self._contexts = {}  # swapped with the model, never before
            self._generation += 1
        if new is not None and new.is_pre_release:
            _warn_pre_release(new.version)

    def load_document(self, source: _PathLike, text: Optional[str] = None) -> Document:
        """Load a document like :meth:`Document.load`, reusing the in-memory context.

        Args:
            source: Path or URL, or a label if *text* is given.
            text: The document content; read from *source* when omitted.
        """
        source = os.fspath(source)
        if text is None:
            text = read_location(source)
        data, version = _parse_json(source, text)
        override = _context_location(version, self._context_urls, self._model_dir)
        location = override or version.context_url
        ctx_obj = self._contexts.get(location)
        if ctx_obj is None:
            generation = self._generation
            ctx_obj = _read_context(location)
            if not getattr(self._loading, "on", False):  # lock may be held by us
                with self._lock:
                    if generation == self._generation:  # not invalidated by reload()
                        self._contexts[location] = ctx_obj
        graph = _parse_graph(source, data, text, version, ctx_obj, override)
        return Document(source, data, graph, version)

    def validate(
        self,
        sources: Union[_PathLike, Iterable[_PathLike]],
        *,
        check_merged: bool = False,
    ) -> ValidationResult:
        """Validate one or more documents; see :func:`validate`.

        Also raises :class:`SpdxValidateError` if a document's version differs
        from the version this validator is bound to, even from an earlier call.
        """
        if isinstance(sources, (str, os.PathLike)):
            sources = [sources]

        resolved = self._version
        model = self._model  # pairs documents' contexts with this model
        documents: List[Document] = []
        for source in sources:
            doc = self.load_document(os.fspath(source))
            if resolved is None:
                resolved = doc.version
            elif doc.version != resolved:
                raise SpdxValidateError(
                    f"{source} has incompatible version {doc.version.pretty}. "
                    f"Other documents are {resolved.pretty}"
                )
            documents.append(doc)

        if not documents:
            return ValidationResult()

        if model is None or model.version != resolved:
            model = self.load(resolved)  # raises if bound to another version

        errors: List[ValidationError] = []
        for doc in documents:
            errors.extend(
                _schema_error(doc.source, e) for e in self._schema_errors(doc, model)
            )
            errors.extend(
                ValidationError(doc.source, "shacl", msg)
                for msg in self._shacl_errors(doc.graph, True, model)
            )

        if len(documents) > 1 and check_merged and not errors:
            merged = rdflib.Graph()
            for doc in documents:
                merged += doc.graph
            errors.extend(
                ValidationError("(merged)", "shacl", msg)
                for msg in self._shacl_errors(merged, False, model)
            )

        return ValidationResult(errors)

    def _schema_errors(
        self, doc: Document, model: Optional[_Model] = None
    ) -> List[jsonschema.exceptions.ValidationError]:
        model = model or self.load(doc.version)
        return schema_errors(model.schema_validator, doc.data)

    def _shacl_errors(
        self, graph: rdflib.Graph, error_external: bool, model: Optional[_Model] = None
    ) -> List[str]:
        model = model or self.load()
        return check_graph(graph, model.shacl_graph, model.version, error_external)

    def _load_model(self, version: SpdxVersion) -> _Model:
        schema, shacl_graph = load_validation_data(
            version,
            schema_urls=self._schema_urls,
            shacl_urls=self._shacl_urls,
            model_dir=self._model_dir,
        )
        try:
            validator = schema_validator(schema)
        except jsonschema.exceptions.SchemaError as e:
            location = _schema_location(version, self._schema_urls, self._model_dir)
            raise SpdxValidateError(f"Invalid schema {location}: {e}") from e
        for triple in _PYSHACL_SYSTEM_TRIPLES:
            shacl_graph.add(triple)
        pre_release = _is_pre_release(shacl_graph, self._pre_release)
        return _Model(version, validator, shacl_graph, pre_release)


def validate(
    sources: Union[_PathLike, Iterable[_PathLike]],
    *,
    version: Union[str, SpdxVersion, None] = None,
    check_merged: bool = False,
    schema_urls: _Locations = None,
    shacl_urls: _Locations = None,
    context_urls: _Locations = None,
    model_dir: Optional[str] = None,
    pre_release: Optional[bool] = None,
) -> ValidationResult:
    """Validate one or more SPDX 3 documents against schema and SHACL rules.

    For many calls with the same model, reuse a :class:`Validator`.

    Resolution precedence for each resource (`schema`, `shapes`, `context`):
    explicit list (`schema_urls`, `shacl_urls`, `context_urls`)
    > `model_dir` > network default.

    Args:
        sources: A single path or URL, or an iterable of them.
        version: SPDX version to validate against (e.g. ``"3.0.1"``). When
            ``None`` (the default) the version is detected from each document's
            ``@context``.
        check_merged: Also validate the graph formed by merging every document,
            which catches type errors across ``ExternalMap`` references. Skipped
            if any document already failed.
        schema_urls: Optional list of local file paths or URLs for JSON Schema.
            Takes precedence over `model_dir`.
        shacl_urls: Optional list of local file paths or URLs for SHACL shapes.
            Takes precedence over `model_dir`.
        context_urls: Optional list of local file paths or URLs for JSON-LD
            @context. Takes precedence over `model_dir`.
        model_dir: Optional directory containing versioned models (v[VERSION]/).
            Used for any resources not explicitly overridden above.
        pre_release: Overrides the pre-release status read from the model;
            a pre-release model issues a :class:`PreReleaseWarning`.

    Returns:
        ValidationResult: The collected :class:`ValidationError` findings
            (empty when everything is valid).

    Raises:
        SpdxValidateError: A document cannot be loaded, or documents declare
            incompatible versions.
        UnknownVersionError: *version* or a document ``@context`` is unknown.
        ResourceNotFoundError: A specified or expected model/context file does
            not exist.
    """
    return Validator(
        version,
        schema_urls=schema_urls,
        shacl_urls=shacl_urls,
        context_urls=context_urls,
        model_dir=model_dir,
        pre_release=pre_release,
    ).validate(sources, check_merged=check_merged)
