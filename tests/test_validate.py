# SPDX-FileContributor: Arthit Suriyawongkul
# SPDX-FileCopyrightText: 2026 Joshua Watt
# SPDX-FileType: SOURCE
# SPDX-License-Identifier: MIT
"""Test the validate() library API and the spdx3validate() CLI entry point."""

import json
import re
import warnings
from pathlib import Path
from typing import Any, Dict, Set

import pytest
import rdflib

import spdx3_validate
from spdx3_validate import Document, core
from spdx3_validate.main import main

DATA_DIR = Path(__file__).parent / "data"
VALID_DOC = DATA_DIR / "3.0.1" / "valid" / "package_sbom.json"
INVALID_DOC = DATA_DIR / "3.0.1" / "invalid" / "package_sbom_missing_creationinfo.json"


# --- Library API: validate() -------------------------------------------------


def test_validate_valid() -> None:
    """A known-valid document validates with no errors."""
    try:
        result = spdx3_validate.validate(str(VALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert result.valid
    assert bool(result) is True
    assert result.errors == []


def test_validate_invalid() -> None:
    """A known-invalid document reports attributed ValidationError objects."""
    try:
        result = spdx3_validate.validate(str(INVALID_DOC))
    except OSError as e:
        pytest.skip(f"network unavailable: {e}")
    assert not result.valid
    assert not result
    assert result.errors
    assert str(result)  # errors render as text
    for err in result.errors:
        assert isinstance(err, spdx3_validate.ValidationError)
        assert err.source == str(INVALID_DOC)
        assert err.kind in {"schema", "shacl"}
        assert err.message


def test_validate_no_sources_is_valid() -> None:
    """Validating nothing succeeds without touching the network."""
    result = spdx3_validate.validate([])
    assert result.valid
    assert result.errors == []


def test_load_nonexistent_file_raises_resource_not_found(
    tmp_path: Path,
) -> None:
    """Loading a non-existent document file raises ResourceNotFoundError."""
    missing_file = tmp_path / "does_not_exist.json"
    with pytest.raises(spdx3_validate.ResourceNotFoundError):
        spdx3_validate.Document.load(str(missing_file))


def test_validate_missing_context_raises(tmp_path: Path) -> None:
    """A document without an @context raises SpdxValidateError (no network)."""
    bad = tmp_path / "no_context.json"
    bad.write_text(json.dumps({"foo": "bar"}), encoding="utf-8")
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate(str(bad))


def test_validate_unknown_version_raises() -> None:
    """An unknown version string raises UnknownVersionError (no network)."""
    with pytest.raises(spdx3_validate.UnknownVersionError):
        spdx3_validate.validate([], version="9.9.9")


def test_error_and_result_rendering() -> None:
    """ValidationError / ValidationResult render as text (no network)."""
    err = spdx3_validate.ValidationError("a.json", "shacl", "boom")
    assert str(err) == "a.json [shacl]: boom"

    result = spdx3_validate.ValidationResult([err])
    assert not result
    assert not result.valid
    assert str(result) == "a.json [shacl]: boom"


def test_empty_result_is_valid_and_blank() -> None:
    """An empty ValidationResult is valid and renders as an empty string."""
    result = spdx3_validate.ValidationResult()
    assert result.valid
    assert bool(result) is True
    assert str(result) == ""


# --- CLI entry point: spdx3validate() (back-compat) --------------------------


def test_spdx3validate_is_callable() -> None:
    """Test that spdx3validate is callable."""
    # No input files -> nothing to validate -> success (exit code 0)
    assert spdx3_validate.spdx3validate([]) == 0


@pytest.mark.parametrize("doc,ok", [(VALID_DOC, True), (INVALID_DOC, False)], ids=["valid", "invalid"])  # fmt: skip
def test_spdx3validate_online(doc: Path, ok: bool, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """Known documents validate (or fail) with the network models."""
    rc = spdx3_validate.spdx3validate([str(doc)])
    if "Failed to read" in capsys.readouterr().out:  # CLI reports it, no exception
        pytest.skip("network unavailable")
    assert (rc == 0) is ok


# --- Offline validation tests ------------------------------------------------


def test_load_validation_data_local_files(tmp_path: Path) -> None:
    """load_validation_data loads schema & shacl from explicit file paths."""
    schema_file = tmp_path / "schema.json"
    schema_file.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    shacl_file = tmp_path / "model.ttl"
    shacl_file.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )

    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]  # 3.0.1
    schema, graph = spdx3_validate.core.load_validation_data(
        version,
        schema_urls=[str(schema_file)],
        shacl_urls=[str(shacl_file)],
    )
    assert schema == {"type": "object"}
    assert len(graph) == 0


def test_document_from_text_local_context(tmp_path: Path) -> None:
    """Document.from_text uses local spdx-context.jsonld (no network)."""
    context_file = tmp_path / "spdx-context.jsonld"
    context_file.write_text(
        json.dumps(
            {
                "@context": {
                    "@vocab": "https://spdx.org/rdf/3.0.1/terms/",
                    "type": "@type",
                }
            }
        ),
        encoding="utf-8",
    )

    doc_text = json.dumps(
        {
            "@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
            "@id": "http://spdx.example.com/test",
            "type": "CreationInfo",
        }
    )

    doc = spdx3_validate.Document.from_text(
        "test.json",
        doc_text,
        context_urls=[str(context_file)],
    )
    assert doc.version.pretty == "3.0.1"
    assert len(doc.graph) > 0


def test_load_validation_data_model_dir(tmp_path: Path) -> None:
    """load_validation_data resolves models from SPDX3VALIDATE_MODEL_DIR."""
    v_dir = tmp_path / "v3.0.1"
    v_dir.mkdir(parents=True)

    schema_file = v_dir / "spdx-json-schema.json"
    schema_file.write_text(json.dumps({"type": "object"}), encoding="utf-8")

    shacl_file = v_dir / "spdx-model.ttl"
    shacl_file.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n", encoding="utf-8"
    )

    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]  # 3.0.1
    schema, graph = spdx3_validate.core.load_validation_data(
        version,
        model_dir=str(tmp_path),
    )
    assert schema == {"type": "object"}
    assert len(graph) == 0


def test_strict_precedence_cli_missing_file_raises(tmp_path: Path) -> None:
    """If CLI specifies a file path that does not exist, fail immediately."""
    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]
    bad_schema = tmp_path / "nonexistent.json"
    with pytest.raises(
        spdx3_validate.ResourceNotFoundError,
        match="Specified schema file does not exist",
    ) as exc_info:
        spdx3_validate.core.load_validation_data(
            version,
            schema_urls=[str(bad_schema)],
        )
    assert isinstance(exc_info.value, spdx3_validate.SpdxValidateError)
    assert isinstance(exc_info.value, FileNotFoundError)


def test_strict_precedence_model_dir_missing_file_raises(
    tmp_path: Path,
) -> None:
    """If model_dir is set but required file is missing, fail immediately."""
    version = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]
    empty_model_dir = tmp_path / "models"
    empty_model_dir.mkdir()
    with pytest.raises(
        spdx3_validate.ResourceNotFoundError,
        match="Schema file spdx-json-schema.json not found in",
    ) as exc_info:
        spdx3_validate.core.load_validation_data(
            version,
            model_dir=str(empty_model_dir),
        )
    assert isinstance(exc_info.value, spdx3_validate.SpdxValidateError)
    assert isinstance(exc_info.value, FileNotFoundError)


def test_cli_multiple_entries_warn_and_use_first(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """Repeated --schema/--shapes/--context warn; only the first is ever read."""
    monkeypatch.delenv("SPDX3VALIDATE_MODEL_DIR", raising=False)
    good = _inputs(tmp_path)
    bad = _inputs(tmp_path / "x", schema='{"type": "array"}', shapes="not turtle", context="{bad")  # fmt: skip
    args = ["-q", "-j", good["doc"]]
    for kind in ("schema", "shapes", "context"):
        flag = "--" + kind
        args += [flag, good[kind], flag, bad[kind]]
    assert main(args) == 0  # a second entry would fail validation or parsing
    err = capsys.readouterr().err
    for kind in ("schema", "shapes", "context"):
        assert f"WARNING: Multiple --{kind} options are not supported yet." in err


# --- Error wrapping, wording and multi-entry lists ---------------------------

V301 = spdx3_validate.spdx_versions.SPDX_VERSIONS[1]
DEAD = "file:///nonexistent/spdx"  # unreachable URL, no network involved
CTX_TEXT = json.dumps({"@context": V301.context_url})


@pytest.fixture(autouse=True)
def _no_model_dir_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SPDX3VALIDATE_MODEL_DIR", raising=False)


@pytest.fixture
def tiny(tmp_path: Path) -> Dict[str, str]:
    """Minimal local schema, shapes and context files, by kind."""
    content = {
        "schema": ("s.json", json.dumps({"type": "object"})),
        "shapes": ("m.ttl", "@prefix sh: <http://www.w3.org/ns/shacl#> .\n"),
        "context": ("c.jsonld", json.dumps({"@context": {"@vocab": V301.rdf_base + "Core/", "type": "@type"}})),  # fmt: skip
        "nested": ("n.jsonld", json.dumps({"@context": DEAD})),
    }
    for name, text in content.values():
        (tmp_path / name).write_text(text, encoding="utf-8")
    return {k: str(tmp_path / name) for k, (name, _) in content.items()}


@pytest.mark.parametrize(
    "call",
    [
        lambda t: core.load_validation_data(V301, schema_urls=[DEAD]),
        lambda t: core.load_validation_data(V301, shacl_urls=[DEAD]),
        lambda t: Document.from_text("d", CTX_TEXT, context_urls=[DEAD]),
        lambda t: Document.from_text("d", CTX_TEXT, context_urls=[t["nested"]]),
    ],
    ids=["schema", "shapes", "context", "nested_context"],
)
def test_fetch_failures_are_resource_not_found(call: Any, tiny: Dict[str, str]) -> None:  # fmt: skip
    """Failed downloads raise ResourceNotFoundError, not a raw URLError."""
    with pytest.raises(spdx3_validate.ResourceNotFoundError, match="Failed to read"):
        call(tiny)


def test_cli_fetch_failure_prints_error(tiny: Dict[str, str], capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """The CLI prints the failure and returns 1, with no traceback."""
    rc = main(["-q", "-j", str(VALID_DOC), "--context", tiny["context"], "--schema", DEAD])  # fmt: skip
    assert rc == 1
    assert "Failed to read schema" in capsys.readouterr().out


@pytest.mark.parametrize("step", ["schema", "shapes", "context"])
def test_model_dir_messages_say_model_directory(step: str, tmp_path: Path) -> None:
    """Missing-file errors name the 'model directory', not the env var."""
    (tmp_path / "v3.0.1").mkdir()
    if step == "shapes":
        (tmp_path / "v3.0.1" / "spdx-json-schema.json").write_text("{}")
    with pytest.raises(spdx3_validate.ResourceNotFoundError) as exc_info:
        if step == "context":
            Document.from_text("d", CTX_TEXT, model_dir=str(tmp_path))
        else:
            core.load_validation_data(V301, model_dir=str(tmp_path))
    msg = str(exc_info.value)
    assert "model directory" in msg and "SPDX3VALIDATE_MODEL_DIR" not in msg


@pytest.mark.parametrize(
    "call,kinds",
    [
        (lambda t: core.load_validation_data(V301, schema_urls=[t["schema"]] * 2, shacl_urls=[t["shapes"]] * 2), {"schema", "shapes"}),  # fmt: skip
        (lambda t: Document.load(str(VALID_DOC), context_urls=[t["context"]] * 2), {"context"}),  # fmt: skip
        (lambda t: spdx3_validate.validate([str(VALID_DOC)] * 2, schema_urls=[t["schema"]] * 2, shacl_urls=[t["shapes"]] * 2, context_urls=[t["context"]] * 2), {"schema", "shapes", "context"}),  # fmt: skip
        (lambda t: spdx3_validate.spdx3validate([str(VALID_DOC)] * 2, schema_urls=[t["schema"]] * 2, shacl_urls=[t["shapes"]] * 2, context_urls=[t["context"]] * 2), {"schema", "shapes", "context"}),  # fmt: skip
    ],
    ids=["load_validation_data", "Document.load", "validate", "spdx3validate"],
)
def test_multiple_entries_warn_once_per_kind(call: Any, kinds: Set[str], tiny: Dict[str, str]) -> None:  # fmt: skip
    """More than one entry warns once per kind, attributed to the caller."""
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        call(tiny)
    ours = [w for w in caught if "Multiple" in str(w.message)]
    assert sorted(re.findall(r"Multiple (\w+)", " ".join(str(w.message) for w in ours))) == sorted(kinds)  # fmt: skip
    assert {w.filename for w in ours} == {__file__}


def test_cli_model_dir_flag_beats_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """--model-dir takes precedence over SPDX3VALIDATE_MODEL_DIR."""
    flag_dir, env_dir = tmp_path / "flag", tmp_path / "env"
    flag_dir.mkdir()
    env_dir.mkdir()
    monkeypatch.setenv("SPDX3VALIDATE_MODEL_DIR", str(env_dir))
    assert main(["-q", "-j", str(VALID_DOC), "--model-dir", str(flag_dir)]) == 1
    out = capsys.readouterr().out
    assert str(flag_dir) in out and str(env_dir) not in out


# --- Override context must match the document's version ----------------------


def _typed_doc(tmp_path: Path, graph: Any) -> str:
    path = tmp_path / "doc.json"
    path.write_text(json.dumps({"@context": V301.context_url, "@graph": graph}))
    return str(path)


def _ctx_for(tmp_path: Path, version: str) -> str:
    ctx = {"@vocab": f"https://spdx.org/rdf/{version}/terms/Core/", "type": "@type"}
    path = tmp_path / f"ctx-{version}.jsonld"
    path.write_text(json.dumps({"@context": ctx}))
    return str(path)


@pytest.mark.parametrize(
    "ctx_version,graph,ok",
    [
        ("3.0.1", [{"type": "Agent", "@id": "http://ex/a"}], True),
        ("3.0.0", [{"type": "Agent", "@id": "http://ex/a"}], False),
        ("3.0.0", [], True),  # no typed nodes: nothing to compare
    ],
    ids=["matching", "mismatched", "no_types"],
)
def test_override_context_must_match_version(ctx_version: str, graph: Any, ok: bool, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """A context for another SPDX version fails loudly, in the library and CLI."""
    doc, ctx = _typed_doc(tmp_path, graph), _ctx_for(tmp_path, ctx_version)
    schema = tmp_path / "s.json"
    shapes = tmp_path / "m.ttl"
    schema.write_text("{}")
    shapes.write_text("@prefix sh: <http://www.w3.org/ns/shacl#> .\n")
    kwargs: Dict[str, Any] = {"context_urls": [ctx], "schema_urls": [str(schema)], "shacl_urls": [str(shapes)]}  # fmt: skip
    cli = ["-q", "-j", doc, "--context", ctx, "--schema", str(schema), "--shapes", str(shapes)]  # fmt: skip
    if ok:
        assert spdx3_validate.validate(doc, **kwargs).valid
        assert main(cli) == 0
    else:
        with pytest.raises(spdx3_validate.SpdxValidateError, match="does not match SPDX 3.0.1"):  # fmt: skip
            spdx3_validate.validate(doc, **kwargs)
        assert main(cli) == 1
        assert "does not match SPDX 3.0.1" in capsys.readouterr().out


# --- Clean errors, explicit-over-model_dir, bare strings ---------------------

SHAPES0 = "@prefix sh: <http://www.w3.org/ns/shacl#> .\n"


def _inputs(base: Path, **override: str) -> Dict[str, str]:
    """A valid document plus local schema, shapes and context; some replaced."""
    base.mkdir(parents=True, exist_ok=True)
    vocab = {"@vocab": V301.rdf_base + "Core/", "type": "@type"}
    graph = [{"type": "Agent", "@id": "http://ex/a"}]
    text = {
        "schema": "{}",
        "shapes": SHAPES0,
        "context": json.dumps({"@context": vocab}),
        "doc": json.dumps({"@context": V301.context_url, "@graph": graph}),
    }
    text.update(override)
    paths = {}
    for kind, content in text.items():
        paths[kind] = str(base / kind)
        (base / kind).write_text(content, encoding="utf-8")
    return paths


@pytest.mark.parametrize(
    "bad,message",
    [
        ({"schema": "{bad"}, "Invalid JSON in schema"),
        ({"context": "{bad"}, "Invalid JSON in @context"),
        ({"context": '"just a string"'}, "must be a JSON object"),
        ({"shapes": "not turtle"}, "Invalid shapes"),
        ({"doc": "{bad"}, "Invalid JSON in"),
        ({"doc": "5"}, "is not a JSON object"),
    ],
    ids=["schema_json", "context_json", "context_not_object", "shapes_syntax", "doc_json", "doc_not_object"],  # fmt: skip
)
def test_malformed_inputs_are_clean_errors(bad: Dict[str, str], message: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """Malformed inputs raise SpdxValidateError and give the CLI a message, rc 1."""
    f = _inputs(tmp_path, **bad)
    opts: Dict[str, Any] = {"schema_urls": [f["schema"]], "shacl_urls": [f["shapes"]], "context_urls": [f["context"]]}  # fmt: skip
    cli = ["-q", "-j", f["doc"], "--schema", f["schema"], "--shapes", f["shapes"], "--context", f["context"]]  # fmt: skip
    with pytest.raises(spdx3_validate.SpdxValidateError, match=message):
        spdx3_validate.validate(f["doc"], **opts)
    assert main(cli) == 1
    assert message in capsys.readouterr().out


def test_directory_as_document_is_clean_error(tmp_path: Path) -> None:
    """A directory given as a document is an error message, not IsADirectoryError."""
    with pytest.raises(spdx3_validate.SpdxValidateError, match="Failed to read"):
        spdx3_validate.Document.load(str(tmp_path))


def test_invalid_schema_names_its_location(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """A malformed user schema is reported with its own path, even with -q."""
    f = _inputs(tmp_path, schema='{"type": 5}')
    opts: Dict[str, Any] = {"schema_urls": [f["schema"]], "shacl_urls": [f["shapes"]], "context_urls": [f["context"]]}  # fmt: skip
    with pytest.raises(spdx3_validate.SpdxValidateError, match="Invalid schema") as exc:
        spdx3_validate.validate(f["doc"], **opts)
    assert f["schema"] in str(exc.value) and "spdx.org" not in str(exc.value)
    cli = ["-q", "-j", f["doc"], "--schema", f["schema"], "--shapes", f["shapes"], "--context", f["context"]]  # fmt: skip
    assert main(cli) == 1
    out = capsys.readouterr().out
    assert f["schema"] in out and "spdx.org" not in out


def test_bare_string_locations_are_accepted(tmp_path: Path) -> None:
    """A single string works where a list of locations is expected."""
    f = _inputs(tmp_path)
    result = spdx3_validate.validate(f["doc"], schema_urls=f["schema"], shacl_urls=f["shapes"], context_urls=f["context"])  # fmt: skip
    assert result.valid


def test_explicit_options_beat_model_dir(tmp_path: Path) -> None:
    """model_dir is used when nothing is explicit, and loses to explicit options."""
    f = _inputs(tmp_path / "files")
    v_dir = tmp_path / "models" / "v3.0.1"
    v_dir.mkdir(parents=True)
    (v_dir / "spdx-json-schema.json").write_text(
        '{"type": "array"}'
    )  # rejects f["doc"]
    (v_dir / "spdx-model.ttl").write_text(SHAPES0)
    (v_dir / "spdx-context.jsonld").write_text(Path(f["context"]).read_text())
    md = str(tmp_path / "models")
    assert not spdx3_validate.validate(f["doc"], model_dir=md).valid
    assert spdx3_validate.validate(f["doc"], model_dir=md, schema_urls=[f["schema"]]).valid  # fmt: skip
    graph = Document.load(f["doc"], model_dir=md).graph
    assert any(str(t).startswith(V301.rdf_base) for t in graph.objects(None, rdflib.RDF.type))  # fmt: skip


def test_context_without_spdx_types_fails_for_nonempty_doc(tmp_path: Path) -> None:
    """A context that maps no SPDX types would skip SHACL silently."""
    ctx = tmp_path / "c.jsonld"
    ctx.write_text(json.dumps({"@context": {"@vocab": "http://ex/"}}))
    doc = _typed_doc(tmp_path, [{"type": "Agent", "@id": "http://ex/a"}])
    with pytest.raises(spdx3_validate.SpdxValidateError, match="does not match"):
        Document.load(doc, context_urls=[str(ctx)])


@pytest.mark.parametrize("bad", ["[]", '"x"', "{bad"], ids=["array", "string", "json"])
def test_schema_must_be_json_object(bad: str, tmp_path: Path) -> None:
    schema = tmp_path / "s.json"
    schema.write_text(bad)
    with pytest.raises(spdx3_validate.SpdxValidateError):
        core.load_validation_data(V301, schema_urls=[str(schema)])


def test_pathlike_locations_accepted(tiny: Dict[str, str]) -> None:
    schema, graph = core.load_validation_data(
        V301, schema_urls=Path(tiny["schema"]), shacl_urls=[Path(tiny["shapes"])]
    )
    assert schema == {"type": "object"}


def test_empty_schema_and_shapes_warn(tmp_path: Path) -> None:
    """Empty files are allowed but flagged, naming the file."""
    schema, shapes = tmp_path / "s.json", tmp_path / "m.ttl"
    schema.write_text("{}")
    shapes.write_text("")
    with pytest.warns(UserWarning) as rec:
        core.load_validation_data(V301, schema_urls=[str(schema)], shacl_urls=[str(shapes)])  # fmt: skip
    msgs = " ".join(str(w.message) for w in rec)
    assert f"Schema {schema} is empty" in msgs and f"Shapes {shapes} are empty" in msgs
    assert {w.filename for w in rec} == {__file__}


def test_typeless_nodes_with_matching_context_load(tmp_path: Path) -> None:
    """Untyped nodes are fine when properties are in the version's namespace."""
    doc = _typed_doc(tmp_path, [{"@id": "http://ex/p", "name": "x"}])
    d = Document.load(doc, context_urls=[_ctx_for(tmp_path, "3.0.1")])
    assert len(d.graph) == 1
    with pytest.raises(spdx3_validate.SpdxValidateError, match="does not match"):
        Document.load(doc, context_urls=[_ctx_for(tmp_path, "3.0.0")])


@pytest.mark.parametrize(
    "kind", ["shapes", "ref"], ids=["invalid_shacl", "unresolvable_ref"]
)
def test_broken_model_files_are_clean_errors(kind: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:  # fmt: skip
    """Bad SHACL or $ref found at validation time is an SpdxValidateError."""
    f = _inputs(tmp_path)
    if kind == "shapes":
        Path(f["shapes"]).write_text(
            "@prefix sh: <http://www.w3.org/ns/shacl#> . @prefix ex: <http://ex/> .\n"
            f"ex:S a sh:NodeShape ; sh:targetClass <{V301.rdf_base}Core/Agent> ;"
            ' sh:property [ sh:path "x" ; sh:minCount 1 ] .'
        )
    else:
        Path(f["schema"]).write_text('{"$ref": "#/nope"}')
    opts: Dict[str, Any] = {"schema_urls": [f["schema"]], "shacl_urls": [f["shapes"]], "context_urls": [f["context"]]}  # fmt: skip
    with pytest.raises(spdx3_validate.SpdxValidateError):
        spdx3_validate.validate(f["doc"], **opts)
    cli = ["-q", "-j", f["doc"], "--schema", f["schema"], "--shapes", f["shapes"], "--context", f["context"]]  # fmt: skip
    assert main(cli) in (1,)


@pytest.mark.parametrize("ctx", ["{}", '{"@context": {}}', '{"@context": null}', '{"context": {"@vocab": "http://ex/"}}'], ids=["empty", "empty_ctx", "null", "wrong_key"])  # fmt: skip
def test_context_mapping_nothing_fails(ctx: str, tmp_path: Path) -> None:
    """A context that yields no triples must not let a document pass unchecked."""
    c = tmp_path / "c.jsonld"
    c.write_text(ctx)
    doc = _typed_doc(tmp_path, [{"type": "Agent", "@id": "http://ex/a"}])
    with pytest.raises(spdx3_validate.SpdxValidateError):
        Document.load(doc, context_urls=[str(c)])


def test_shapes_for_other_version_warn(tmp_path: Path) -> None:
    shapes = tmp_path / "m.ttl"
    shapes.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> .\n"
        "<http://ex/S> a sh:NodeShape ; sh:targetClass <https://spdx.org/rdf/3.0.0/terms/Core/Agent> .\n"  # noqa: E501
    )
    schema = tmp_path / "s.json"
    schema.write_text('{"type": "object"}')
    with pytest.warns(UserWarning, match="target no classes"):
        core.load_validation_data(V301, schema_urls=[str(schema)], shacl_urls=[str(shapes)])  # fmt: skip


def test_bad_sh_pattern_is_clean_error() -> None:
    g = rdflib.Graph().parse(
        data="@prefix sh: <http://www.w3.org/ns/shacl#> . @prefix ex: <http://ex/> .\n"
        'ex:S a sh:NodeShape ; sh:targetNode ex:a ; sh:pattern "[" .',
        format="turtle",
    )
    data = rdflib.Graph().parse(data="<http://ex/a> a <http://ex/T> .", format="turtle")
    with pytest.raises(spdx3_validate.SpdxValidateError, match="Invalid shapes"):
        core.check_graph(data, g, V301, True)


def test_implicit_class_targets_do_not_warn(tmp_path: Path) -> None:
    """SPDX shapes are NodeShape+owl:Class (no sh:targetClass); that is normal."""
    shapes, schema = tmp_path / "m.ttl", tmp_path / "s.json"
    shapes.write_text(
        "@prefix sh: <http://www.w3.org/ns/shacl#> . @prefix owl: <http://www.w3.org/2002/07/owl#> .\n"
        f"<{V301.rdf_base}Core/Agent> a owl:Class, sh:NodeShape .\n"
    )
    schema.write_text('{"type": "object"}')
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        core.load_validation_data(V301, schema_urls=[str(schema)], shacl_urls=[str(shapes)])  # fmt: skip
