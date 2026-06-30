"""Tests for the FirmaUY inspection MCP server.

These mock the `firmauy` subprocess, so they need neither the CLI nor a card. They cover the JSON
wrapper, its error handling, the missing-file guard (no shell-out), the redaction default, and the
batch summary."""

import pytest

from firmauy_mcp import server


class _Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def _fake_run(stdout="", stderr="", returncode=0, capture=None):
    def run(args, **kw):
        if capture is not None:
            capture.append(args)
        return _Proc(stdout, stderr, returncode)
    return run


# --- _run: the JSON wrapper -------------------------------------------------

def test_run_parses_json(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout='{"schema_version": 1, "valid": true}'))
    assert server._run(["validate-ci", "12345672", "--json"]) == {"schema_version": 1, "valid": True}


def test_run_firmauy_missing(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", None)
    out = server._run(["doctor", "--json"])
    assert "error" in out and "not found" in out["error"].lower()


def test_run_non_json_output(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout="boom, not json"))
    assert "error" in server._run(["doctor", "--json"])


def test_run_rejects_non_object_json(monkeypatch):
    # Valid JSON that is not an object must still yield a structured error, so callers
    # (e.g. verify_batch) always get a dict and never raise.
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout="[1, 2, 3]"))
    out = server._run(["doctor", "--json"])
    assert "error" in out and "non-object" in out["error"]


def test_run_empty_stdout_surfaces_bounded_stderr(monkeypatch):
    # With no stdout, stderr becomes the error message, but bounded so a noisy stderr can't
    # dump unbounded text into the model context.
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout="", stderr="x" * 1000, returncode=2))
    out = server._run(["doctor", "--json"])
    assert "error" in out and set(out["error"]) == {"x"} and len(out["error"]) <= 500


def test_run_timeout(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")

    def boom(args, **kw):
        raise server.subprocess.TimeoutExpired(cmd=args, timeout=1)

    monkeypatch.setattr(server.subprocess, "run", boom)
    assert "timed out" in server._run(["doctor", "--json"])["error"]


# --- verify -----------------------------------------------------------------

def test_verify_missing_file_never_shells_out(monkeypatch, tmp_path):
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(capture=called))
    out = server.verify(str(tmp_path / "nope.pdf"))
    assert "error" in out and "not found" in out["error"]
    assert called == []                       # guarded before invoking firmauy


def test_verify_redacts_by_default(monkeypatch, tmp_path):
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"schema_version": 1, "redacted": true, "indication": "VALID", "signatures": []}',
        capture=called))
    out = server.verify(str(f))
    assert out["indication"] == "VALID"
    args = called[0]
    assert args[:2] == ["firmauy", "verify"]
    assert "--json" in args and "--redact" in args


def test_verify_redact_false_omits_flag(monkeypatch, tmp_path):
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout='{"indication": "VALID", "signatures": []}', capture=called))
    server.verify(str(f), redact=False)
    assert "--redact" not in called[0]


def test_verify_detached_passes_original(monkeypatch, tmp_path):
    p7s = tmp_path / "payload.zip.p7s"; p7s.write_text("x")
    orig = tmp_path / "payload.zip"; orig.write_text("y")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout='{"indication": "VALID", "signatures": []}', capture=called))
    server.verify(str(p7s), original=str(orig))
    assert "--original" in called[0] and str(orig) in called[0]


# --- verify_batch -----------------------------------------------------------

def test_verify_batch_summarizes_and_groups_issuers(monkeypatch):
    canned = {
        "a.pdf": {"indication": "VALID", "redacted": True,
                  "signatures": [{"trusted": True, "issuer": {"common_name": "AC MI"}}]},
        "b.pdf": {"indication": "INVALID",
                  "signatures": [{"trusted": False, "issuer": {"common_name": "AC MI"}}]},
        "c.pdf": {"error": "file not found: c.pdf"},
    }
    monkeypatch.setattr(server, "_verify_one", lambda path, original, redact: canned[path])
    out = server.verify_batch(["a.pdf", "b.pdf", "c.pdf"])
    assert out["summary"] == {"VALID": 1, "INVALID": 1, "INDETERMINATE": 0, "error": 1}
    by_path = {r["path"]: r for r in out["results"]}
    assert by_path["a.pdf"]["trusted"] is True
    assert by_path["a.pdf"]["issuers"] == ["AC MI"]
    assert "error" in by_path["c.pdf"]


def test_verify_batch_preserves_input_order(monkeypatch):
    # Results must come back in input order even though verification runs concurrently.
    paths = [f"f{i}.pdf" for i in range(20)]
    monkeypatch.setattr(server, "_verify_one",
                        lambda path, original, redact: {"indication": "VALID", "signatures": []})
    out = server.verify_batch(paths)
    assert [r["path"] for r in out["results"]] == paths
    assert out["summary"]["VALID"] == 20


# --- validate_ci / doctor pass-through --------------------------------------

def test_validate_ci_passthrough(monkeypatch):
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"valid": true, "expected_check_digit": "2"}', capture=called))
    assert server.validate_ci("1.234.567-2")["valid"] is True
    assert called[0][:2] == ["firmauy", "validate-ci"] and "--json" in called[0]


# --- path sandboxing: allowed roots + extension filter ----------------------

def test_norm_ext_normalizes_dot_and_case():
    assert server._norm_ext("PDF") == ".pdf"
    assert server._norm_ext(" .P7S ") == ".p7s"


def test_within_allowed_true_when_unconfigured(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", ())
    assert server._within_allowed(tmp_path / "anywhere.pdf") is True


def test_within_allowed_accepts_path_inside_root(monkeypatch, tmp_path):
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (tmp_path.resolve(),))
    assert server._within_allowed(tmp_path / "doc.pdf") is True


def test_within_allowed_rejects_parent_traversal(monkeypatch, tmp_path):
    root = tmp_path / "root"; root.mkdir()
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (root.resolve(),))
    # `..` escapes the root once resolved, even though the raw string starts inside it.
    assert server._within_allowed(root / ".." / "secret.pdf") is False


def test_within_allowed_rejects_sibling_prefix(monkeypatch, tmp_path):
    root = tmp_path / "docs"; root.mkdir()
    sibling = tmp_path / "docs-secret"; sibling.mkdir()
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (root.resolve(),))
    # /docs-secret shares a string prefix with /docs but is a different directory.
    assert server._within_allowed(sibling / "x.pdf") is False


def test_within_allowed_rejects_symlink_escape(monkeypatch, tmp_path):
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside.pdf"; outside.write_text("x")
    link = root / "link.pdf"; link.symlink_to(outside)
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (root.resolve(),))
    # The symlink lives inside the root but resolves to a target outside it.
    assert server._within_allowed(link) is False


def test_verify_rejects_path_outside_roots_without_shelling_out(monkeypatch, tmp_path):
    root = tmp_path / "root"; root.mkdir()
    outside = tmp_path / "outside.pdf"; outside.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (root.resolve(),))
    monkeypatch.setattr(server.subprocess, "run", _fake_run(capture=called))
    out = server.verify(str(outside))
    assert "error" in out and "allowed roots" in out["error"]
    assert called == []                       # guarded before invoking firmauy


def test_verify_rejects_original_outside_roots(monkeypatch, tmp_path):
    root = tmp_path / "root"; root.mkdir()
    p7s = root / "payload.zip.p7s"; p7s.write_text("x")     # signed file inside the root
    orig = tmp_path / "payload.zip"; orig.write_text("y")   # original outside the root
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_ALLOWED_ROOTS", (root.resolve(),))
    monkeypatch.setattr(server.subprocess, "run", _fake_run(capture=called))
    out = server.verify(str(p7s), original=str(orig))
    assert "error" in out and "original path is outside" in out["error"]
    assert called == []


def test_extension_filter_rejects_other_type_without_shelling_out(monkeypatch, tmp_path):
    f = tmp_path / "notes.txt"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_ALLOWED_EXTS", frozenset({".pdf", ".xml", ".p7s"}))
    monkeypatch.setattr(server.subprocess, "run", _fake_run(capture=called))
    out = server.verify(str(f))
    assert "error" in out and "not allowed" in out["error"]
    assert called == []


def test_extension_filter_unset_allows_any_type(monkeypatch, tmp_path):
    f = tmp_path / "notes.txt"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_ALLOWED_EXTS", frozenset())
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout='{"indication": "VALID", "signatures": []}', capture=called))
    out = server.verify(str(f))
    assert out["indication"] == "VALID"
    assert called and called[0][:2] == ["firmauy", "verify"]
