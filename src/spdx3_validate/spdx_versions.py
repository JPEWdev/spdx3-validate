# SPDX-FileContributor: Joshua Watt
# SPDX-FileCopyrightText: 2024 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT

from __future__ import annotations

from typing import Callable, Iterator, NamedTuple, Optional

from rdflib import RDF, Graph, URIRef
from rdflib.term import Node


class SpdxVersion(NamedTuple):
    context_url: str
    shacl_url: str
    schema_url: str
    pretty: str
    rdf_base: str
    get_imports: Callable[[Graph], Iterator[Node]]


def get_3_0_0_imports(graph: Graph) -> Iterator[Node]:
    RDF_BASE = URIRef("https://spdx.org/rdf/3.0.0/terms/")

    for doc in graph.subjects(RDF.type, RDF_BASE + "Core/SpdxDocument"):
        for i in graph.objects(doc, RDF_BASE + "Core/imports"):
            for spdxid in graph.objects(i, RDF_BASE + "Core/externalSpdxId"):
                # externalSpdxId is an xsd:anyURI literal; return the IRI
                # it names so it can be matched against element subjects.
                yield URIRef(str(spdxid))


def get_3_0_1_imports(graph: Graph) -> Iterator[Node]:
    RDF_BASE = URIRef("https://spdx.org/rdf/3.0.1/terms/")

    for doc in graph.subjects(RDF.type, RDF_BASE + "Core/SpdxDocument"):
        for i in graph.objects(doc, RDF_BASE + "Core/import"):
            for spdxid in graph.objects(i, RDF_BASE + "Core/externalSpdxId"):
                # externalSpdxId is an xsd:anyURI literal; return the IRI
                # it names so it can be matched against element subjects.
                yield URIRef(str(spdxid))


SPDX_VERSIONS = (
    SpdxVersion(
        "https://spdx.org/rdf/3.0.0/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.0/spdx-model.ttl",
        "https://spdx.org/schema/3.0.0/spdx-json-schema.json",
        "3.0.0",
        "https://spdx.org/rdf/3.0.0/terms/",
        get_3_0_0_imports,
    ),
    SpdxVersion(
        "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
        "https://spdx.org/rdf/3.0.1/spdx-model.ttl",
        "https://spdx.org/schema/3.0.1/spdx-json-schema.json",
        "3.0.1",
        "https://spdx.org/rdf/3.0.1/terms/",
        get_3_0_1_imports,
    ),
)


def find_version(context_url: str) -> Optional[SpdxVersion]:
    for s in SPDX_VERSIONS:
        if s.context_url == context_url:
            return s
    return None
