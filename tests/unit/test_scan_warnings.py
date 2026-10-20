import io
import subprocess
import tarfile
from unittest.mock import patch

import responses

from kresheen.engine.ingest import github_repository_ingestor as G
from kresheen.engine.source_status import classify_source, has_unanalysed
from kresheen.models.facts import FactNode
from kresheen.models.threat_model_run import SourceResult


def _tarball(files: dict[str, str]) -> bytes:
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for name, text in files.items():
            data = text.encode()
            info = tarfile.TarInfo(f"acme-widget-abc/{name}")
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    return raw.getvalue()


def test_each_grype_failure_mode_records_a_reason(tmp_path, monkeypatch):
    notes: list[str] = []
    monkeypatch.setenv("PATH", str(tmp_path))  # no grype on PATH
    assert G._run_grype_scan(tmp_path, notes) is None
    assert any("not installed" in n for n in notes)

    for exc, word in (
        (subprocess.TimeoutExpired("grype", 1), "timed out"),
        (subprocess.CalledProcessError(3, "grype"), "failed"),
    ):
        notes = []
        with patch.object(G.subprocess, "run", side_effect=exc):
            assert G._run_grype_scan(tmp_path, notes) is None
        assert len(notes) == 1 and word in notes[0]

    notes = []
    with patch.object(G.subprocess, "run", return_value=None):  # "succeeds" but wrote no/garbage files
        assert G._run_grype_scan(tmp_path, notes) is None
    assert len(notes) == 1


@responses.activate
def test_skipped_scan_becomes_a_warning_on_the_source_result():
    responses.add(responses.GET, "https://api.github.com/repos/acme/widget/tarball",
                  body=_tarball({"package-lock.json": "{}", "k8s/d.yaml": "kind: Deployment"}), status=200)
    with patch.object(G, "_run_grype_scan", return_value=None):  # also covers callers that stub the scanner out
        nodes, _ = G.GithubRepositoryIngestor().run(
            run_id="R", application_id="A", connection_details={"repo_url": "https://github.com/acme/widget"}
        )
    result = classify_source("DS-1", "github_repository", nodes)
    assert result.warnings and "vulnerabilities" in result.warnings[0]
    assert has_unanalysed([result]), "a partly analysed source must not count as fully analysed"


@responses.activate
def test_successful_scan_has_no_warning():
    responses.add(responses.GET, "https://api.github.com/repos/acme/widget/tarball",
                  body=_tarball({"package-lock.json": "{}"}), status=200)
    empty_docs = ({"bomFormat": "CycloneDX", "components": []}, {"matches": []})
    with patch.object(G, "_run_grype_scan", return_value=empty_docs):
        nodes, _ = G.GithubRepositoryIngestor().run(
            run_id="R", application_id="A", connection_details={"repo_url": "https://github.com/acme/widget"}
        )
    assert not any(n.node_type == "scan_note" for n in nodes)
    assert classify_source("DS-1", "github_repository", nodes).warnings == []


def test_scan_note_is_not_a_diagram_component():
    note = FactNode(id="N", run_id="R", application_id="A", node_type="scan_note", name="x",
                    attributes={"warnings": ["w"]}, source_ref="github_repository",
                    discovered_at=__import__("datetime").datetime.now(__import__("datetime").UTC))
    r = classify_source("DS", "github_repository", [note])
    assert r.component_count == 0 and r.warnings == ["w"]


def test_dashboard_flag_and_completeness_see_the_warning():
    from kresheen.engine.completeness import assess_completeness

    partial = SourceResult(data_source_id="DS-1", type="github_repository", status="analysed", component_count=2,
                           warnings=["The vulnerability scan timed out."])
    assert has_unanalysed([partial])
    out = assess_completeness([], [], [partial])
    assert any(i.check == "partial_input" and "timed out" in i.why for i in out.items)


def _diagram_nodes(content: str):
    from kresheen.engine.ingest.architecture_diagram_ingestor import ArchitectureDiagramIngestor

    return ArchitectureDiagramIngestor().run(
        run_id="R", application_id="A", connection_details={"content": content, "filename": "d"}
    )[0]


def test_diagram_over_the_component_cap_says_it_was_truncated():
    cells = "".join(f'<mxCell id="c{i}" value="s{i}" vertex="1" parent="1"/>' for i in range(520))
    xml = f'<mxfile><diagram id="d"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/>{cells}</root></mxGraphModel></diagram></mxfile>'
    result = classify_source("DS", "architecture_diagram", _diagram_nodes(xml))
    assert result.status == "analysed" and result.component_count == 500
    assert result.warnings and "larger than the limit" in result.warnings[0]


def test_mermaid_over_the_line_cap_says_it_was_truncated():
    text = "flowchart LR\n" + "\n".join(f"A{i} --> B{i}" for i in range(5100))
    assert classify_source("DS", "architecture_diagram", _diagram_nodes(text)).warnings


def test_diagram_within_the_caps_has_no_warning():
    xml = '<mxfile><diagram id="d"><mxGraphModel><root><mxCell id="0"/><mxCell id="1" parent="0"/><mxCell id="a" value="web" vertex="1" parent="1"/></root></mxGraphModel></diagram></mxfile>'
    assert classify_source("DS", "architecture_diagram", _diagram_nodes(xml)).warnings == []


def test_unreadable_diagrams_get_a_specific_reason():
    xxe = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY x SYSTEM "file:///etc/passwd">]><mxfile><diagram id="d"></diagram></mxfile>'
    assert "refused for safety" in classify_source("DS", "architecture_diagram", _diagram_nodes(xxe)).message
    huge = "flowchart LR\n" + "A-->B\n" * 900_000
    assert "larger than" in classify_source("DS", "architecture_diagram", _diagram_nodes(huge)).message
    plain = classify_source("DS", "architecture_diagram", _diagram_nodes("just some prose"))
    assert plain.status == "reference_only" and "not recognised" in plain.message


def test_archive_with_too_many_entries_is_refused_before_extraction(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_MAX_ARCHIVE_MEMBERS", 100)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for i in range(250):
            info = tarfile.TarInfo(f"repo/f{i}.txt")
            t.addfile(info, io.BytesIO(b""))
    path = tmp_path / "a.tar.gz"
    path.write_bytes(raw.getvalue())
    out = tmp_path / "out"
    out.mkdir()
    import pytest

    with pytest.raises(ValueError, match="more than 100 files"):
        G._extract_tarball_safely(str(path), str(out))
    assert list(out.iterdir()) == [], "nothing may be written once the cap is exceeded"


def test_archive_at_the_entry_cap_is_still_extracted(tmp_path, monkeypatch):
    monkeypatch.setattr(G, "_MAX_ARCHIVE_MEMBERS", 100)
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w:gz") as t:
        for i in range(100):
            t.addfile(tarfile.TarInfo(f"repo/f{i}.txt"), io.BytesIO(b""))
    path = tmp_path / "a.tar.gz"
    path.write_bytes(raw.getvalue())
    out = tmp_path / "out"
    out.mkdir()
    G._extract_tarball_safely(str(path), str(out))
    assert len(list((out / "repo").iterdir())) == 100
