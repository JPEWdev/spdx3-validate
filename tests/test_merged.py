# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Merged check (RDF merge, blank nodes per document) and ExternalMap imports."""

import json
from pathlib import Path
from typing import Any, Dict, List, Sequence

import pytest
import rdflib

import spdx3_validate
from spdx3_validate import core
from spdx3_validate.spdx_versions import SPDX_VERSIONS

CTX = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"
LABEL = "_:CreationInfo0"  # the same blank-node label in every document
T1, T2 = "2024-03-06T00:00:00Z", "2025-06-01T00:00:00Z"
X = "http://ex/x"  # the spdxId each case is about
EM = "http://ex/em"  # an IRI-named ExternalMap

Element = Dict[str, Any]


def _doc(
    base: str,
    created: str,
    extra: Sequence[Element] = (),
    imports: Sequence[str] = (),
    em_id: str = "",
) -> Element:
    """A minimal valid SPDX 3.0.1 document whose elements live under *base*."""
    agent = f"{base}/Agent"
    doc: Element = {
        "type": "SpdxDocument",
        "spdxId": f"{base}/Doc",
        "rootElement": [agent],
        "element": [agent, *(e["spdxId"] for e in extra)],
    }
    if imports:
        maps = [{"type": "ExternalMap", "externalSpdxId": i} for i in imports]
        doc["import"] = [{**m, "@id": em_id} for m in maps] if em_id else maps
    info = {
        "type": "CreationInfo",
        "@id": LABEL,
        "createdBy": [agent],
        "specVersion": "3.0.1",
        "created": created,
    }
    elements = [{"type": "Person", "spdxId": agent, "name": "A"}, doc, *extra]
    graph = [info] + [{**e, "creationInfo": LABEL} for e in elements]
    return {"@context": CTX, "@graph": graph}


def _a(*extra: Element, imports: Sequence[str] = (), em_id: str = "") -> Element:
    return _doc("http://ex/a", T1, extra, imports, em_id)


def _b(
    *extra: Element, created: str = T2, imports: Sequence[str] = (), em_id: str = ""
) -> Element:
    return _doc("http://ex/b", created, extra, imports, em_id)


def _person(name: str) -> Element:
    return {"type": "Person", "spdxId": X, "name": name}


PKG = {
    "type": "software_Package",
    "spdxId": "http://ex/a/Pkg",
    "name": "p",
    "originatedBy": [X],  # must be an Agent
}
FILE = {"type": "software_File", "spdxId": X, "name": "f"}  # not an Agent

# id: (documents, expected error sources ("a" = first document),
#      texts that must all appear in one error)
CASES: Dict[str, Any] = {
    # The same blank-node label in two documents names two nodes.
    "bnode_label_different_created": ([_a(), _b()], [], ()),
    # Guards the renaming itself: two equal CreationInfos as two nodes still pass.
    "bnode_label_identical_content": ([_a(), _b(created=T1)], [], ()),
    # IRIs are not renamed: one spdxId with two names fails only when merged.
    "shared_iri_meets": (
        [_a(_person("x")), _b(_person("y"))],
        ["(merged)"],
        ("MaxCount", "Core/name>", X),
    ),
    # One spdxId defined in two documents, even identically, is an error.
    "defined_twice": (
        [_a(_person("x")), _b(_person("x"), created=T1)],
        ["(merged)"],
        ("is defined in more than one document", X, "0.json", "1.json"),
    ),
    # The same file twice is merged once.
    "same_file_twice": ([_a(_person("x")), "0.json"], [], ()),
    # A shared IRI on a non-Element (here an ExternalMap) is not a definition.
    "shared_non_element_iri": (
        [_a(imports=[X], em_id=EM), _b(imports=[X], em_id=EM)],
        [],
        (),
    ),
    # An imported spdxId that another document defines with the wrong type.
    "imported_wrong_type": (
        [_a(PKG, imports=[X]), _b(FILE)],
        ["(merged)"],
        ("Core/originatedBy>", X),
    ),
    # An imported spdxId that no document defines is accepted.
    "imported_unresolved": ([_a(PKG, imports=[X]), _b()], [], ()),
    # Imported and defined in the same (otherwise valid) document.
    "imported_and_defined": (
        [_a(_person("x"), imports=[X])],
        ["a"],
        ("in an ExternalMap and also defined",),
    ),
}


@pytest.mark.parametrize("docs,sources,texts", CASES.values(), ids=CASES.keys())
def test_merged_check(
    tmp_path: Path, docs: List[Any], sources: List[str], texts: Sequence[str]
) -> None:
    """Library and CLI agree; each document alone is checked as well."""
    paths = []
    for i, d in enumerate(docs):
        path = tmp_path / (d if isinstance(d, str) else f"{i}.json")  # str: reuse
        if not isinstance(d, str):
            path.write_text(json.dumps(d))
        paths.append(str(path))
    try:
        errors = spdx3_validate.validate(paths, check_merged=True).errors
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    expected = {paths[0] if s == "a" else s for s in sources}
    assert {e.source for e in errors} == expected
    assert not texts or any(all(t in e.message for t in texts) for e in errors)
    exit_code = spdx3_validate.spdx3validate(paths, check_merged=True)
    assert exit_code == (1 if errors else 0)


def test_merge_graphs_renames_per_graph() -> None:
    """Blank nodes stay linked within a graph and are named ``d<i>_<label>``."""
    ex = rdflib.Namespace("http://ex/")
    x, y = rdflib.BNode("x"), rdflib.BNode("y")
    g = rdflib.Graph()
    for t in [(ex.e, ex.p, x), (x, ex.q, y), (y, ex.r, rdflib.Literal(1))]:
        g.add(t)
    merged = core.merge_graphs([g, g])
    xs = list(merged.objects(ex.e, ex.p))
    ys = {merged.value(n, ex.q) for n in xs}
    assert len(merged) == 6 and len(xs) == 2 and len(ys) == 2
    assert all(merged.value(n, ex.r) == rdflib.Literal(1) for n in ys)
    assert {*xs, *ys} == {rdflib.BNode(f"d{i}_{n}") for i in (0, 1) for n in "xy"}


@pytest.mark.parametrize("v", SPDX_VERSIONS, ids=lambda v: v.pretty)
def test_get_imports_yields_iris(v: Any) -> None:
    """externalSpdxId is an xsd:anyURI literal; it comes back as an IRI."""
    ns = rdflib.Namespace(v.rdf_base + "Core/")
    doc, ext = rdflib.URIRef("http://ex/doc"), rdflib.BNode()
    g = rdflib.Graph()
    g.add((doc, rdflib.RDF.type, ns.SpdxDocument))
    g.add((doc, ns["imports" if v.pretty == "3.0.0" else "import"], ext))
    g.add((ext, ns.externalSpdxId, rdflib.Literal(X, datatype=rdflib.XSD.anyURI)))
    assert list(v.get_imports(g)) == [rdflib.URIRef(X)]


def test_imported_and_defined_reported_once() -> None:
    """Listing one spdxId in two ExternalMaps gives one error, not two."""
    v = SPDX_VERSIONS[1]
    ns = rdflib.Namespace(v.rdf_base + "Core/")
    doc, x = rdflib.URIRef("http://ex/doc"), rdflib.URIRef(X)
    g = rdflib.Graph()
    g.add((doc, rdflib.RDF.type, ns.SpdxDocument))
    g.add((x, ns.name, rdflib.Literal("x")))  # defined here
    for _ in range(2):
        ext = rdflib.BNode()
        g.add((doc, ns["import"], ext))
        g.add((ext, ns.externalSpdxId, rdflib.Literal(X, datatype=rdflib.XSD.anyURI)))
    errors = core.check_graph(g, rdflib.Graph(), v, True)  # no shapes needed
    assert errors == [f"ERROR: {X} in an ExternalMap and also defined in the document"]
    assert core.check_graph(g, rdflib.Graph(), v, False) == []


def test_merged_errors_merges_a_repeated_source_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """[a, b, symlink to a, file:// a, a] merges as [a, b], in input order."""
    a, b = tmp_path / "a.json", tmp_path / "b.json"
    a.write_text(json.dumps(_a()))
    b.write_text(json.dumps(_b()))
    link = tmp_path / "link.json"
    link.symlink_to(a)
    spellings = [str(a), str(b), str(link), a.as_uri(), str(a)]
    try:
        docs = [core.Document.load(p) for p in spellings]
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    merged: List[List[str]] = []

    def spy(documents: Sequence[core.Document], *_: Any) -> List[str]:
        merged.append([d.source for d in documents])
        return []

    monkeypatch.setattr(core, "duplicate_definitions", spy)
    core.merged_errors(docs, rdflib.Graph(), SPDX_VERSIONS[1])
    assert merged == [[str(a), str(b)]]


def test_stdin_is_not_a_file_named_dash(tmp_path: Path) -> None:
    (tmp_path / "-").write_text("{}")
    assert core._source_key("-") != core._source_key(str(tmp_path / "-"))
