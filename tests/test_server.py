"""Tests for the FirmaUY inspection MCP server.

These mock the `firmauy` subprocess, so they need neither the CLI nor a card. They cover the JSON
wrapper, its error handling, the missing-file guard (no shell-out), the redaction default, and the
batch summary."""


from firmauy_mcp import server


import pytest

from firmauy_mcp import server as _server_module

# What a supported CLI answers `--version` with. Every mock serves it, because the server asks
# before it runs anything: it reports what the CLI concludes, so it will not run one whose
# conclusions have different semantics.
_SUPPORTED = "firmauy " + ".".join(str(n) for n in _server_module._MIN_FIRMAUY)


@pytest.fixture(autouse=True)
def _forget_the_cli_version():
    """The lookup is memoized, so a version mocked in one test must not leak into the next."""
    server._cli_version.cache_clear()
    yield
    server._cli_version.cache_clear()


class _Proc:
    def __init__(self, stdout="", stderr="", returncode=0):
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode


def _fake_run(stdout="", stderr="", returncode=0, capture=None, version=_SUPPORTED):
    def run(args, **kw):
        if "--version" in args:
            return _Proc(version)           # answered before anything else; never captured
        if capture is not None:
            capture.append(args)
        return _Proc(stdout, stderr, returncode)
    return run


# --- _run: the JSON wrapper -------------------------------------------------

def test_run_parses_json(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout='{"schema_version": 2, "valid": true}'))
    assert server._run(["validate-ci", "12345672", "--json"]) == {"schema_version": 2, "valid": True}


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
        if "--version" in args:
            return _Proc(_SUPPORTED)        # the gate answers; the work is what hangs
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
        stdout='{"schema_version": 2, "redacted": true, "indication": "VALID", "signatures": []}',
        capture=called))
    out = server.verify(str(f))
    assert out["indication"] == "VALID"
    args = called[0]
    assert args[:2] == ["firmauy", "verify"]
    assert "--json" in args and "--redact" in args


def test_verify_omits_the_flag_only_when_the_operator_allows_pii(monkeypatch, tmp_path):
    # The operator's startup setting is the only thing that lets identifying data through: the
    # tool takes no argument a model could use to ask for it.
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_ALLOW_PII", True)
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout='{"indication": "VALID", "signatures": []}', capture=called))
    server.verify(str(f))
    assert "--redact" not in called[0]


def test_verify_takes_no_redact_argument():
    import inspect
    assert "redact" not in inspect.signature(server.verify).parameters
    assert "redact" not in inspect.signature(server.verify_batch).parameters
    assert "redact" not in inspect.signature(server.doctor).parameters


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
    monkeypatch.setattr(server, "_verify_one", lambda path, original: canned[path])
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
                        lambda path, original: {"indication": "VALID", "signatures": []})
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


# --- doctor: the token label can be the cardholder's name -------------------

_DOCTOR_JSON = (
    '{"ok": true, "checks": ['
    '{"status": "PASS", "name": "firmauy", "detail": "1.9.0", "fix": null, "sensitive": false},'
    '{"status": "PASS", "name": "PKCS#11 module present", "detail": "/usr/lib/libgclib.so",'
    ' "fix": null, "sensitive": false},'
    '{"status": "PASS", "name": "c\\u00e9dula token detected", "detail": "PEREZ PEREZ JUAN",'
    ' "fix": null, "sensitive": true}'
    ']}'
)


def test_doctor_redacts_the_token_detail_by_default(monkeypatch):
    # OpenSC's cédula driver reports the holder's name as the token label, so that detail must not
    # reach the model. Every check's status and name still do.
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=_DOCTOR_JSON))

    result = server.doctor()

    assert result["ok"] is True
    details = {c["name"]: c["detail"] for c in result["checks"]}
    assert details["cédula token detected"] == "[REDACTED]"
    assert "PEREZ" not in str(result)
    # Non-identifying details survive, they are what makes the diagnosis useful.
    assert details["firmauy"] == "1.9.0"
    assert details["PKCS#11 module present"] == "/usr/lib/libgclib.so"
    assert [c["status"] for c in result["checks"]] == ["PASS", "PASS", "PASS"]


def test_doctor_returns_the_raw_report_only_when_the_operator_allows_pii(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=_DOCTOR_JSON))

    monkeypatch.setattr(server, "_ALLOW_PII", True)
    result = server.doctor()

    assert result["checks"][2]["detail"] == "PEREZ PEREZ JUAN"


def test_doctor_redaction_tolerates_an_error_result(monkeypatch):
    # _run returns {"error": ...} on failure: the redactor must pass it through untouched.
    monkeypatch.setattr(server, "_FIRMAUY", None)
    assert "error" in server.doctor()


def test_doctor_redacts_an_unknown_check_that_firmauy_marks_sensitive(monkeypatch):
    # The reason for trusting firmauy's flag over guessing from the name: a check this server has
    # never heard of, whose name carries no hint, is still redacted because firmauy said so.
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=(
        '{"ok": true, "checks": ['
        '{"status": "PASS", "name": "signing credential detected",'
        ' "detail": "PEREZ PEREZ JUAN", "fix": null, "sensitive": true}'
        ']}'
    )))

    result = server.doctor()

    assert result["checks"][0]["detail"] == "[REDACTED]"
    assert "PEREZ" not in str(result)


def test_doctor_fails_closed_on_a_check_without_the_flag(monkeypatch):
    # An older firmauy omits the key. Costing a detail is the right failure; leaking one is not.
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=(
        '{"ok": true, "checks": ['
        '{"status": "PASS", "name": "firmauy", "detail": "1.8.0", "fix": null}'
        ']}'
    )))

    assert server.doctor()["checks"][0]["detail"] == "[REDACTED]"


# --- the timestamp policy: the operator's, never the model's ------------------

_STAMP = ('{"schema_version": 2, "redacted": true, "indication": "VALID", "signatures": ['
          '{"indication": "VALID", "trusted": true, "issuer": {"common_name": "MICA"},'
          ' "timestamp": {"present": true, "intact": true, "valid": true, "trusted": %s,'
          ' "gen_time": "2026-08-01T06:48:04+00:00", "tsa_common_name": "Una TSA",'
          ' "detail": "..."}, "checks": []}]}')


def test_the_tsa_roots_travel_whenever_the_operator_configured_them(monkeypatch, tmp_path):
    pem = tmp_path / "tsa.pem"; pem.write_text("-----BEGIN CERTIFICATE-----")
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_TSA_CA", str(pem))
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout=_STAMP % "true", capture=called))

    server.verify(str(f))

    args = called[0]
    assert "--tsa-ca" in args
    assert args[args.index("--tsa-ca") + 1] == str(pem)


def test_without_the_setting_nothing_about_the_tsa_is_claimed(monkeypatch, tmp_path):
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout=_STAMP % "null", capture=called))

    out = server.verify(str(f))

    assert "--tsa-ca" not in called[0]
    assert out["signatures"][0]["timestamp"]["trusted"] is None


def test_a_configured_bundle_that_is_not_there_fails_closed(monkeypatch, tmp_path):
    """Never carry on unvalidated. Reporting every timestamp as merely asserted while the setting
    says otherwise is wrong and silent, which is the worst pair."""
    f = tmp_path / "doc.pdf"; f.write_text("x")
    called = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server, "_TSA_CA", str(tmp_path / "no-existe.pem"))
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=_STAMP % "true", capture=called))

    out = server.verify(str(f))

    assert "error" in out and "FIRMAUY_MCP_TSA_CA" in out["error"]
    assert called == [], "verified anyway, without the anchors the operator asked for"


def test_a_broken_policy_stops_the_server_from_starting(monkeypatch, tmp_path):
    import pytest

    monkeypatch.setattr(server, "_TSA_CA", str(tmp_path / "no-existe.pem"))
    monkeypatch.setattr(server.mcp, "run", lambda: pytest.fail("started with a broken policy"))

    with pytest.raises(SystemExit):
        server.main()


def test_the_model_cannot_choose_the_roots():
    """Letting a tool argument pick trust roots would let the model define the policy it is being
    measured against. Same boundary as --redact."""
    import inspect

    for tool in (server.verify, server.verify_batch):
        params = inspect.signature(tool).parameters
        assert not any("tsa" in p for p in params), tool.__name__


# --- the batch keeps the three-valued trust apart -----------------------------

def test_the_batch_no_longer_throws_the_timestamp_away(monkeypatch, tmp_path):
    f = tmp_path / "doc.pdf"; f.write_text("x")
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=_STAMP % "true"))

    out = server.verify_batch([str(f)])

    assert out["results"][0]["timestamps"] == {
        "trusted": 1, "unvalidated": 0, "untrusted": 0, "broken": 0}


def test_the_batch_does_not_turn_null_into_false(monkeypatch, tmp_path):
    """The whole point. Nobody looked is not the same as looked and it did not chain, and a batch
    that collapses them reports a problem that was never gone looking for."""
    f = tmp_path / "doc.pdf"; f.write_text("x")
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(stdout=_STAMP % "null"))

    counts = server.verify_batch([str(f)])["results"][0]["timestamps"]

    assert counts["unvalidated"] == 1
    assert counts["untrusted"] == 0


def test_the_batch_separates_untrusted_from_broken():
    sound_but_unanchored = {"timestamp": {"present": True, "intact": True, "valid": True,
                                          "trusted": False}}
    broken = {"timestamp": {"present": True, "intact": True, "valid": False, "trusted": False}}

    counts = server._timestamp_counts([sound_but_unanchored, broken])

    assert counts == {"trusted": 0, "unvalidated": 0, "untrusted": 1, "broken": 1}


def test_a_file_with_no_timestamp_counts_nothing(monkeypatch, tmp_path):
    """The common case: the standard cédula flow signs without one. The counts sum to the stamped
    signatures, so comparing against `signatures` says how many carry no time evidence at all."""
    f = tmp_path / "doc.pdf"; f.write_text("x")
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"schema_version": 2, "indication": "VALID", "signatures": ['
               '{"indication": "VALID", "trusted": true, "timestamp": null}]}'))

    row = server.verify_batch([str(f)])["results"][0]

    assert row["timestamps"] == {"trusted": 0, "unvalidated": 0, "untrusted": 0, "broken": 0}
    assert row["signatures"] == 1


def test_a_malformed_token_is_a_verdict_and_not_a_subprocess_failure(monkeypatch, tmp_path):
    """firmauy 1.13.1 stopped raising on an unreadable TSTInfo. The server must pass that verdict
    through as a result, not turn it into an error row."""
    f = tmp_path / "doc.pdf"; f.write_text("x")
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"schema_version": 2, "indication": "INDETERMINATE", "signatures": ['
               '{"indication": "INDETERMINATE", "trusted": true, "timestamp": '
               '{"present": true, "intact": false, "valid": false, "trusted": null,'
               ' "gen_time": null, "detail": "could not parse timestamp: ..."}}]}'))

    out = server.verify_batch([str(f)])

    assert out["summary"]["INDETERMINATE"] == 1
    assert out["summary"]["error"] == 0
    assert out["results"][0]["timestamps"]["broken"] == 1


# --- only the CLI this server was written against -----------------------------

def test_an_old_cli_is_refused_rather_than_trusted(monkeypatch):
    """This server reports what the CLI concludes. On older semantics --tsa-ca was accepted on
    commands that ignored it, so it would be stating a conclusion the CLI never reached."""
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"indication": "VALID"}', version="firmauy 1.11.0"))

    out = server._run(["doctor", "--json"])

    assert "error" in out and "too old" in out["error"]


def test_a_cli_that_will_not_say_its_version_is_refused_too(monkeypatch):
    """Unknown reads like old. A binary that does not answer is not one to report conclusions
    from."""
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"indication": "VALID"}', version="que soy yo"))

    assert "error" in server._run(["doctor", "--json"])


def test_the_supported_cli_passes_the_gate(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run",
                        _fake_run(stdout='{"ok": true, "checks": []}'))

    assert "error" not in server._run(["doctor", "--json"])


def test_a_newer_cli_is_not_refused(monkeypatch):
    """A floor, not a pin. The image pins exactly; a local install is free to be ahead."""
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(
        stdout='{"ok": true, "checks": []}', version="firmauy 2.0.0"))

    assert "error" not in server._run(["doctor", "--json"])


def test_the_version_is_asked_once(monkeypatch):
    """Memoized: a batch of fifty files must not shell out fifty extra times."""
    asked = []
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")

    def run(args, **kw):
        if "--version" in args:
            asked.append(args)
            return _Proc(_SUPPORTED)
        return _Proc('{"ok": true}')

    monkeypatch.setattr(server.subprocess, "run", run)
    for _ in range(5):
        server._run(["doctor", "--json"])

    assert len(asked) == 1


def test_an_old_cli_stops_the_server_from_starting(monkeypatch):
    monkeypatch.setattr(server, "_FIRMAUY", "firmauy")
    monkeypatch.setattr(server.subprocess, "run", _fake_run(version="firmauy 1.11.0"))
    monkeypatch.setattr(server.mcp, "run", lambda: pytest.fail("started on an unsupported CLI"))

    with pytest.raises(SystemExit):
        server.main()
