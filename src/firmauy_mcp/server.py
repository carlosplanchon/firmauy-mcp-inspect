# Copyright 2026 Carlos Andrés Planchón Prestes
# Licensed under the Apache License, Version 2.0

"""Read-only MCP server for inspecting FirmaUY signatures.

It exposes only the **safe, offline, no-card, no-PIN** surface of the `firmauy` CLI: verifying
signatures and validating cédula check digits. It deliberately does **not** expose:

  - signing (it would let a model trigger a legally significant signature with a national ID and PIN),
  - reading the cardholder's biographical data or photo (PII and biometrics that must not enter a
    model's context).

The server wraps the `firmauy` CLI's stable `--json` interface via subprocess (no shell), so it stays
decoupled from FirmaUY's internals. Verification redacts the signer's personal data by default, so the
model sees the indication, trust status and issuer (a public CA) but not the signer's name or document
number.

Requires the `firmauy` CLI on PATH (e.g. `uv tool install firmauy`); override with FIRMAUY_BIN.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from importlib.metadata import PackageNotFoundError, version as _pkg_version
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP

try:
    _VERSION = _pkg_version("firmauy-mcp-inspect")
except PackageNotFoundError:  # running from source without an installed distribution
    _VERSION = "0.0.0"

mcp = FastMCP("firmauy-inspect")
try:  # FastMCP takes no version argument; set it on the wrapped server (a private attribute)
    mcp._mcp_server.version = _VERSION
except AttributeError:  # tolerate a future mcp that renames or removes the internal server
    pass

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
#   FIRMAUY_MCP_ALLOWED_EXTENSIONS  comma-separated; restricts the signed file's type only — never
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


def _within_allowed(p: Path) -> bool:
    """True if p, canonicalized (symlinks and ``..`` resolved), is inside an allowed root.

    True when no roots are configured. Compares by path components via ``is_relative_to``, not string
    prefixes, so none of ``..`` traversal, a symlink escaping the root, or a sibling directory that
    merely shares a name prefix can slip through."""
    if not _ALLOWED_ROOTS:
        return True
    real = p.resolve()
    return any(real.is_relative_to(r) for r in _ALLOWED_ROOTS)


def _run(args: list[str]) -> dict:
    """Run `firmauy <args>` and return the parsed JSON object.

    Never raises: on any failure (firmauy missing, timeout, non-JSON output) it returns
    ``{"error": "..."}`` so the model always gets a clean, structured result."""
    if not _FIRMAUY:
        return {"error": "The 'firmauy' executable was not found on PATH. Install it (for example "
                         "`uv tool install firmauy`) or set the FIRMAUY_BIN environment variable."}
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


def _verify_one(path: str, original: Optional[str], redact: bool) -> dict:
    p = Path(path).expanduser()
    if not _within_allowed(p):
        return {"error": f"path is outside the allowed roots: {path}"}
    if _ALLOWED_EXTS and p.suffix.lower() not in _ALLOWED_EXTS:
        return {"error": f"file type not allowed (expected one of {sorted(_ALLOWED_EXTS)}): {path}"}
    if not p.is_file():
        return {"error": f"file not found: {path}"}
    args = ["verify", str(p), "--json"]
    if redact:
        args.append("--redact")
    if original:
        op = Path(original).expanduser()
        if not _within_allowed(op):  # roots apply to the original too; the extension filter does not
            return {"error": f"original path is outside the allowed roots: {original}"}
        args += ["--original", str(op)]
    return _run(args)


@mcp.tool()
def verify(path: str, original: Optional[str] = None, redact: bool = True) -> dict:
    """Verify a signed file (PDF/PAdES, XAdES XML, or detached CMS/.p7s) and report its validity.

    Returns the structured result: the overall ``indication`` (VALID / INVALID / INDETERMINATE) and,
    per signature, the trust status, the issuer (a public CA) and each individual check. Chain
    validation is offline, up to the Uruguayan national root, and needs no smart card.

    Args:
        path: the signed file to verify.
        original: for a detached ``.p7s`` only, the original file it signs.
        redact: when true (default) the signer's personal data (name, document number) is hidden, so
            it never enters the model context. Set it false only if you explicitly need the signer
            identity.
    """
    return _verify_one(path, original, redact)


@mcp.tool()
def verify_batch(paths: list[str], redact: bool = True) -> dict:
    """Verify many signed files at once and return a summary plus a compact per-file result.

    Built for triaging a folder of signed documents: it counts how many are VALID / INVALID /
    INDETERMINATE / errored, and for each file reports the indication, whether it is trusted to the
    national root, and the issuing CA(s). Use ``verify`` on a single path to get the full per-check
    detail, or to check a detached ``.p7s`` (which needs its original file and is not supported here).
    The signer's personal data is redacted by default.

    Args:
        paths: the signed files to verify.
        redact: hide the signer's personal data (default true).
    """
    summary = {"VALID": 0, "INVALID": 0, "INDETERMINATE": 0, "error": 0}
    results = []
    # Verify the files concurrently (each is an independent, blocking subprocess), then aggregate
    # single-threaded and in input order below, so the summary stays race-free and results stay
    # aligned with `paths`.
    with ThreadPoolExecutor(max_workers=min(_MAX_WORKERS, len(paths) or 1)) as pool:
        verified = list(pool.map(lambda p: _verify_one(p, None, redact), paths))
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


@mcp.tool()
def doctor() -> dict:
    """Report the local FirmaUY setup status (PC/SC stack, PKCS#11 module, card, bundled CAs).

    Useful to check whether the environment can verify (and sign). Returns ``{ok, checks}``, where
    each check is a named PASS/WARN/FAIL with a detail. No personal data is involved.
    """
    return _run(["doctor", "--json"])


def main() -> None:
    """Run the MCP server over stdio."""
    mcp.run()


if __name__ == "__main__":
    main()
