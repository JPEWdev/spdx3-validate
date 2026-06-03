# Copyright (c) 2024 Joshua Watt
#
# SPDX-License-Identifier: MIT

from collections import namedtuple

from rdflib import RDF, URIRef

SpdxVersion = namedtuple(
    "SpdxVersion",
    ["context_url", "shacl_url", "schema_url", "pretty", "rdf_base", "get_imports"],
)


def get_3_0_0_imports(graph):
    RDF_BASE = URIRef("https://spdx.org/rdf/3.0.0/terms/")

    for doc in graph.subjects(RDF.type, RDF_BASE + "Core/SpdxDocument"):
        for i in graph.objects(doc, RDF_BASE + "Core/imports"):
            for spdxid in graph.objects(i, RDF_BASE + "Core/externalSpdxId"):
                yield spdxid


def get_3_0_1_imports(graph):
    RDF_BASE = URIRef("https://spdx.org/rdf/3.0.1/terms/")

    for doc in graph.subjects(RDF.type, RDF_BASE + "Core/SpdxDocument"):
        for i in graph.objects(doc, RDF_BASE + "Core/import"):
            for spdxid in graph.objects(i, RDF_BASE + "Core/externalSpdxId"):
                yield spdxid


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


def find_version(context_url):
    for s in SPDX_VERSIONS:
        if s.context_url == context_url:
            return s
    return None
