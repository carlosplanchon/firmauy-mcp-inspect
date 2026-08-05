# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Read-only MCP server for inspecting FirmaUY signatures.

It exposes only the **safe, offline, no-card, no-PIN** surface of the `firmauy` CLI: verifying
signatures and validating cédula check digits. It deliberately does **not** expose:

  - signing (it would let a model trigger a legally significant signature with a national ID and PIN),
  - reading the cardholder's biographical data or photo (PII and biometrics that must not enter a
    model's context).

The server wraps the `firmauy` CLI's stable `--json` interface via subprocess (no shell). FirmaUY also
ships a public Python API (`firmauy.api`), and importing it here would be a mistake: it would load the
capability to sign and to read the cardholder's data into this process, where it would sit one
attribute away from a model-driven code path. The signing capability still exists in the `firmauy`
executable on the host, of course; what this server guarantees is that it is absent from *this*
process and unreachable from it, because `_run` builds every argument list itself and no tool takes a
subcommand from its caller. See the README for the full rationale.

Personal data (the signer's name and document number, and the token label, which some PKCS#11
modules set to the cardholder's name) is withheld unless the operator sets FIRMAUY_MCP_ALLOW_PII at
startup. No tool argument can request it: a default the model could override would be a suggestion,
not a boundary.

Requires the `firmauy` CLI on PATH (e.g. `uv tool install firmauy`); override with FIRMAUY_BIN.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Optional

from mcp.server.mcpserver import MCPServer

try:
    _VERSION = _pkg_version("firmauy-mcp-inspect")
except PackageNotFoundError:  # running from source without an installed distribution
    _VERSION = "0.0.0"

mcp = MCPServer("firmauy-inspect", version=_VERSION)

# The one CLI this server supports. Not a floor with older versions tolerated: it hands the CLI's
# own JSON to the model and reports what the CLI concludes, so an older one would have it stating
# conclusions that were never reached. See _cli_version_error.
#
# Raised to 1.14.0 because the two verifier escapes that release closed are exactly this server's
# job: damage past the first field read of a TSTInfo, and an OID naming a hash algorithm nobody
# implements. Both raised inside pyHanko on 1.13.1, so a crafted file came back here as an error
# row rather than as a verdict. That is a degraded answer rather than a false one, which is why
# this is a considered choice and not a security fix.
_MIN_FIRMAUY = (1, 14, 0)

_FIRMAUY = os.environ.get("FIRMAUY_BIN") or shutil.which("firmauy")
try:
    _TIMEOUT = float(os.environ.get("FIRMAUY_MCP_TIMEOUT", "60"))
except ValueError:  # a malformed override must not crash startup; fall back to the default
    _TIMEOUT = 60.0
try:
    _MAX_WORKERS = max(1, int(os.environ.get("FIRMAUY_MCP_MAX_WORKERS", "8")))
except ValueError:  # ditto: a bad override falls back rather than crashing (set to 1 for sequential)
    _MAX_WORKERS = 8

# Opt-in path sandboxing; both unset -> no restriction (current behavior), set -> enforced, fail
# closed.
#   FIRMAUY_MCP_ALLOWED_ROOTS       os.pathsep-separated dirs; confines every file read (the signed
#                                   file AND a detached signature's original) to those roots.
#   FIRMAUY_MCP_ALLOWED_EXTENSIONS  comma-separated; restricts the signed file's type only, never
#                                   the arbitrary `original`.
_ALLOWED_ROOTS = tuple(
    Path(r).expanduser().resolve()
    for r in os.environ.get("FIRMAUY_MCP_ALLOWED_ROOTS", "").split(os.pathsep)
    if r
)


def _norm_ext(e: str) -> str:
    e = e.strip().lower()
    return e if e.startswith(".") else f".{e}"


_ALLOWED_EXTS = frozenset(
    _norm_ext(e) for e in os.environ.get("FIRMAUY_MCP_ALLOWED_EXTENSIONS", "").split(",") if e.strip()
)

# Whether personal data may reach the model at all. It is the operator's decision, taken once at
# startup, and no tool argument can change it: a default the model itself could override would not
# be a boundary, only a suggestion. Off means the signer's name and document number, and the token
# label (which some PKCS#11 modules set to the cardholder's name), never leave the machine through
# this server.
#   FIRMAUY_MCP_ALLOW_PII   1/true/yes/on to let identifying data through; anything else keeps it out.
_ALLOW_PII = os.environ.get("FIRMAUY_MCP_ALLOW_PII", "").strip().lower() in {"1", "true", "yes", "on"}

# Which timestamping authorities count. An operator setting for the same reason as the one above:
# choosing whose word is accepted for *when* a document was signed is a trust policy, and a policy
# the model could pick per call would not be one. So it is not a tool argument, and there is no way
# to ask for different roots than the ones this server was started with.
#
# Unset means a signature timestamp is reported as present and unvalidated, which is honest and is
# the default because there is no list to assume: public authorities live in the web PKI bundles,
# and an accredited Uruguayan provider's certificate arrives with the subscription and is in no
# bundle at all. Whichever applies is the operator's to say.
#   FIRMAUY_MCP_TSA_CA   path to a PEM bundle of timestamping authority certificates.
_TSA_CA = os.environ.get("FIRMAUY_MCP_TSA_CA", "").strip()


def _tsa_policy_error() -> Optional[str]:
    """Why the configured timestamp policy cannot be applied, or None when it can.

    Fails closed, unlike the timeout and worker overrides above, which fall back to a default when
    malformed. Those are performance knobs and a wrong one costs speed. This one decides whether a
    date is treated as proven, and quietly carrying on without the anchors an operator asked for
    would report every timestamp as merely asserted while the setting says otherwise. Wrong and
    silent, which is the worst pair.
    """
    if not _TSA_CA:
        return None
    if not Path(_TSA_CA).expanduser().is_file():
        return (f"FIRMAUY_MCP_TSA_CA is set to {_TSA_CA!r}, which is not a readable file. "
                "Refusing to verify rather than silently reporting every timestamp as "
                "unvalidated. Fix the path or unset the variable.")
    return None


def _within_allowed(p: Path) -> bool:
    """True if p, canonicalized (symlinks and ``..`` resolved), is inside an allowed root.

    True when no roots are configured. Compares by path components via ``is_relative_to``, not string
    prefixes, so none of ``..`` traversal, a symlink escaping the root, or a sibling directory that
    merely shares a name prefix can slip through."""
    if not _ALLOWED_ROOTS:
        return True
    real = p.resolve()
    return any(real.is_relative_to(r) for r in _ALLOWED_ROOTS)


@lru_cache(maxsize=1)
def _cli_version() -> Optional[tuple]:
    """The version of the ``firmauy`` on PATH, or None when it cannot be determined.

    Asked once. ``firmauy --version`` prints ``firmauy 1.14.0``; anything else, including a binary
    that will not run, reads as unknown, and an unknown version is refused like an old one.
    """
    if not _FIRMAUY:
        return None
    try:
        proc = subprocess.run([_FIRMAUY, "--version"], capture_output=True, text=True,
                              timeout=_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    parts = proc.stdout.strip().split()
    if len(parts) < 2:
        return None
    try:
        return tuple(int(n) for n in parts[-1].split("."))
    except ValueError:
        return None


def _cli_version_error() -> Optional[str]:
    """Why the CLI on PATH cannot be used, or None when it can.

    This server reports what the CLI concludes, so it only supports the version it was written
    against. An older one differs in exactly the places this matters: a signature timestamp's
    integrity, validity and trust were not consistently three separate answers, ``--tsa-ca`` was
    accepted on commands that ignored it, and a malformed token raised instead of coming back
    INDETERMINATE. Running on those semantics would mean stating conclusions the CLI never reached.

    Enforced here because the packaging floor does not bind where it matters. ``[cli]`` only
    constrains an install that pulls firmauy in as an extra, and the documented way to run this is
    a separately installed CLI or ``FIRMAUY_BIN``, neither of which pip ever sees.
    """
    if not _FIRMAUY:
        return None                 # a different problem, and _run already says so plainly
    found = _cli_version()
    if found is None:
        return (f"Could not determine the version of {_FIRMAUY}. This server requires firmauy "
                f"{'.'.join(str(n) for n in _MIN_FIRMAUY)} or newer.")
    if found < _MIN_FIRMAUY:
        # What the message may not do is attach the reason for one floor to a different one. It
        # used to name the release where integrity, validity and trust became three answers, which
        # was true while the floor sat there and false the moment it moved. So it says what every
        # older version has in common instead, which is the only claim that survives a bump.
        return (f"firmauy {'.'.join(str(n) for n in found)} is too old: this server requires "
                f"{'.'.join(str(n) for n in _MIN_FIRMAUY)} or newer. It reports what the CLI "
                "concludes, and older ones reach different conclusions about timestamps and "
                "damaged tokens, so running on them would state findings the CLI never made. "
                "Upgrade it, or point FIRMAUY_BIN at a newer one.")
    return None


def _run(args: list[str]) -> dict:
    """Run `firmauy <args>` and return the parsed JSON object.

    Never raises: on any failure (firmauy missing, timeout, non-JSON output) it returns
    ``{"error": "..."}`` so the model always gets a clean, structured result."""
    if not _FIRMAUY:
        return {"error": "The 'firmauy' executable was not found on PATH. Install it (for example "
                         "`uv tool install firmauy`) or set the FIRMAUY_BIN environment variable."}
    stale = _cli_version_error()
    if stale:
        return {"error": stale}
    try:
        proc = subprocess.run([_FIRMAUY, *args], capture_output=True, text=True, timeout=_TIMEOUT)
    except subprocess.TimeoutExpired:
        return {"error": f"firmauy timed out after {_TIMEOUT:g}s."}
    except OSError as exc:
        return {"error": f"could not run firmauy: {exc}"}
    out = proc.stdout.strip()
    if not out:
        err = proc.stderr.strip()
        return {"error": err[:500] if err else f"firmauy exited with code {proc.returncode} and no output."}
    try:
        data = json.loads(out)
    except json.JSONDecodeError:
        return {"error": f"firmauy produced output that is not JSON: {out[:500]}"}
    if not isinstance(data, dict):
        return {"error": f"firmauy produced non-object JSON: {out[:500]}"}
    return data


def _verify_one(path: str, original: Optional[str]) -> dict:
    problem = _tsa_policy_error()
    if problem:
        return {"error": problem}
    p = Path(path).expanduser()
    if not _within_allowed(p):
        return {"error": f"path is outside the allowed roots: {path}"}
    if _ALLOWED_EXTS and p.suffix.lower() not in _ALLOWED_EXTS:
        return {"error": f"file type not allowed (expected one of {sorted(_ALLOWED_EXTS)}): {path}"}
    if not p.is_file():
        return {"error": f"file not found: {path}"}
    args = ["verify", str(p), "--json"]
    if not _ALLOW_PII:
        args.append("--redact")
    if _TSA_CA:
        args += ["--tsa-ca", str(Path(_TSA_CA).expanduser())]
    if original:
        op = Path(original).expanduser()
        if not _within_allowed(op):  # roots apply to the original too; the extension filter does not
            return {"error": f"original path is outside the allowed roots: {original}"}
        args += ["--original", str(op)]
    return _run(args)


@mcp.tool()
def verify(path: str, original: Optional[str] = None) -> dict:
    """Verify a signed file (PDF/PAdES, XAdES XML, or detached CMS/.p7s) and report its validity.

    Returns the structured result: the overall ``indication`` (VALID / INVALID / INDETERMINATE) and,
    per signature, the trust status, the issuer (a public CA) and each individual check. Chain
    validation is offline, up to the Uruguayan national root, and needs no smart card.

    **Two independent trusts, and neither implies the other.** Do not read one as the other:

    - ``signature.trusted`` answers *who signed*: the signer's certificate chained to the Uruguayan
      national root.
    - ``signature.timestamp.trusted`` answers *when*: the timestamping authority's own certificate
      chained to the roots this server's operator configured. It is three-valued. ``null`` means no
      roots were configured and nothing was evaluated, which is neither a pass nor a failure and is
      the default. ``false`` means they were evaluated and did not chain. Treating ``null`` as
      ``false`` reports a problem nobody went looking for.

    A signature can be VALID with a timestamp that is only asserted, and can carry a sound
    signature with a broken timestamp. ``timestamp`` is ``null`` when the file has no timestamp at
    all, which is the common case: the standard cédula flow signs without one.

    **Neither trust decides the legal question.** Under Uruguayan law (Ley 18.600 art. 6) a document
    makes proof of its date only through a timestamping provider accredited by the UCE. A timestamp
    from any other authority is real cryptographic evidence of when the signature existed and is not
    that. Whether the configured roots belong to an accredited provider is not visible here, so do
    not describe a trusted timestamp as qualified or as legally sufficient in Uruguay.

    The signer's personal data (name, document number) is withheld unless the operator has enabled
    it for this server, so it does not reach the model. That is a startup setting, not something
    this tool can ask for. So are the timestamping roots: which authorities count is the operator's
    policy, and there is no argument here to change it.

    Args:
        path: the signed file to verify.
        original: for a detached ``.p7s`` only, the original file it signs.
    """
    return _verify_one(path, original)


def _timestamp_counts(sigs: list) -> dict:
    """How this file's signature timestamps came out, as four counts.

    Counts rather than a flag, because the interesting states are not two. A timestamp's own trust
    is three-valued and squeezing it into a boolean is exactly the mistake the whole thing is built
    to avoid: ``unvalidated`` means nobody looked, ``untrusted`` means somebody looked and it did
    not chain, and reporting the first as the second invents a problem while reporting it as the
    third hides one.

    ``broken`` is separate again: the token itself does not hold up, which says nothing about who
    issued it. A signature can be VALID with a timestamp that is merely asserted, and until these
    counts existed the batch gave a model no way to notice that.

    They sum to the number of *stamped* signatures, so comparing against ``signatures`` says how
    many carry no time evidence at all. That is the common case here: the standard cédula flow
    signs without a timestamp.
    """
    counts = {"trusted": 0, "unvalidated": 0, "untrusted": 0, "broken": 0}
    for s in sigs:
        ts = s.get("timestamp")
        if not isinstance(ts, dict) or not ts.get("present"):
            continue
        if not (ts.get("intact") and ts.get("valid")):
            counts["broken"] += 1
        elif ts.get("trusted") is True:
            counts["trusted"] += 1
        elif ts.get("trusted") is False:
            counts["untrusted"] += 1
        else:                       # null: no anchors were configured, so nothing was evaluated
            counts["unvalidated"] += 1
    return counts


@mcp.tool()
def verify_batch(paths: list[str]) -> dict:
    """Verify many signed files at once and return a summary plus a compact per-file result.

    Built for triaging a folder of signed documents: it counts how many are VALID / INVALID /
    INDETERMINATE / errored, and for each file reports the indication, whether it is trusted to the
    national root, and the issuing CA(s). Use ``verify`` on a single path to get the full per-check
    detail, or to check a detached ``.p7s`` (which needs its original file and is not supported here).
    The signer's personal data is withheld, as in ``verify``.

    ``timestamps`` counts how that file's signature timestamps came out, keeping apart the four
    states that a single flag would blur:

    - ``trusted``: the token holds up and its authority chained to the configured roots.
    - ``unvalidated``: the token holds up and no roots were configured, so nobody looked. Not a
      failure, and the default. Do not report it as untrusted.
    - ``untrusted``: the token holds up and its authority did not chain to those roots.
    - ``broken``: the token itself does not hold up, which says nothing about who issued it.

    They sum to the number of *stamped* signatures, so comparing against ``signatures`` tells you
    how many carry no time evidence at all. ``trusted`` on the file itself is the signer's chain and
    is a different question, as in ``verify``: a file can be VALID with every timestamp merely
    asserted.

    Args:
        paths: the signed files to verify.
    """
    summary = {"VALID": 0, "INVALID": 0, "INDETERMINATE": 0, "error": 0}
    results = []
    # Verify the files concurrently (each is an independent, blocking subprocess), then aggregate
    # single-threaded and in input order below, so the summary stays race-free and results stay
    # aligned with `paths`.
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(paths) or 1)) as pool:
        verified = list(pool.map(lambda p: _verify_one(p, None), paths))
    for path, res in zip(paths, verified):
        if "indication" in res:
            sigs = res.get("signatures", [])
            ind = res["indication"]
            summary[ind] = summary.get(ind, 0) + 1
            issuers = sorted(
                {s.get("issuer", {}).get("common_name") for s in sigs if s.get("issuer")} - {None}
            )
            results.append({
                "path": path,
                "indication": ind,
                "signatures": len(sigs),
                "trusted": bool(sigs) and all(s.get("trusted") for s in sigs),
                "issuers": issuers,
                "timestamps": _timestamp_counts(sigs),
            })
        else:
            summary["error"] += 1
            results.append({"path": path, "error": res.get("error", "unknown error")})
    return {"summary": summary, "results": results}


@mcp.tool()
def validate_ci(number: str) -> dict:
    """Validate a Uruguayan cédula's check digit: a purely arithmetic consistency check, offline.

    Returns ``{valid, normalized, body, check_digit, expected_check_digit}``. This is **not** an
    identity check: it only verifies that the number is internally consistent (it catches typos and
    obviously malformed numbers), not that the person exists or the document is valid.

    Args:
        number: the cédula number, with or without separators (for example "1.234.567-2").
    """
    return _run(["validate-ci", number, "--json"])


def _redact_doctor(data: dict) -> dict:
    """Blank the detail of every check firmauy did not mark as safe to show.

    firmauy tags each diagnostic check with ``sensitive``, saying whether its ``detail`` can carry
    the cardholder's own data (the token label is the holder's name with some PKCS#11 modules).
    Trusting that tag beats guessing from the check's name, which would let a future check slip
    through unredacted. A check without the tag is treated as sensitive, so an older firmauy costs
    detail rather than privacy.
    """
    checks = data.get("checks")
    if not isinstance(checks, list):
        return data                       # an {"error": ...} result, or an unexpected shape
    redacted = [
        {**c, "detail": "[REDACTED]"}
        if isinstance(c, dict) and c.get("detail") and c.get("sensitive", True)
        else c
        for c in checks
    ]
    return {**data, "checks": redacted}


@mcp.tool()
def doctor() -> dict:
    """Report the local FirmaUY setup status (PC/SC stack, PKCS#11 module, card, bundled CAs).

    Useful to check whether the environment can verify (and sign). Returns ``{ok, checks}``, where
    each check is a named PASS/WARN/FAIL with a detail.

    The detail of the card and token checks is withheld unless the operator has enabled personal
    data for this server, because some PKCS#11 modules report the cardholder's name as the token
    label. The status of every check, which is what diagnoses the setup, is always reported.
    """
    data = _run(["doctor", "--json"])
    return data if _ALLOW_PII else _redact_doctor(data)


def main() -> None:
    """Run the MCP server over stdio."""
    # At startup, not at the first call. An operator who mistypes a path or leaves an old CLI on
    # PATH finds out while they are still looking at the terminal, rather than from a model
    # reporting an error about a file that is not the problem.
    for problem in (_cli_version_error(), _tsa_policy_error()):
        if problem:
            raise SystemExit(problem)
    mcp.run()


if __name__ == "__main__":
    main()
