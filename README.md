<p align="center">
  <img src="https://raw.githubusercontent.com/carlosplanchon/firmauy-mcp-inspect/main/assets/banner.jpg" alt="FirmaUY MCP Inspect, AI-assisted read-only inspection for Uruguayan digital signatures" width="800">
</p>

# firmauy-mcp-inspect

[![CI](https://github.com/carlosplanchon/firmauy-mcp-inspect/actions/workflows/ci.yml/badge.svg)](https://github.com/carlosplanchon/firmauy-mcp-inspect/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/firmauy-mcp-inspect.svg)](https://pypi.org/project/firmauy-mcp-inspect/)
[![Python versions](https://img.shields.io/pypi/pyversions/firmauy-mcp-inspect.svg)](https://pypi.org/project/firmauy-mcp-inspect/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/carlosplanchon/firmauy-mcp-inspect)
[![Docker](https://img.shields.io/badge/Docker-2496ED?logo=docker&logoColor=white)](https://github.com/users/carlosplanchon/packages/container/package/firmauy-mcp-inspect)

**firmauy-mcp-inspect** is a small, **read-only** [MCP](https://modelcontextprotocol.io/) server that
lets an AI assistant inspect documents signed with a Uruguayan cédula de identidad using
[FirmaUY](https://github.com/carlosplanchon/firmauy). It verifies signatures (PDF/PAdES, XAdES XML,
or a detached CMS `.p7s`) and validates cédula check digits. Verification runs offline and does not
require a smart card.

It exists for the one task where an assistant genuinely beats the bare CLI, **triaging a batch of
signed documents** in plain language. Point it at a folder and it verifies every file, groups the
results by issuing CA, and flags anything that is not VALID or whose certificate chain is not
trusted, leaving you a summary to act on.

By design it **only ever inspects**. It cannot sign, never sees a PIN, and redacts the signer's
personal data by default, so identities stay out of the model's context.

## Scope (inspection only, by design)

FirmaUY can also **sign** with the national ID card and **read the cardholder's data**. This server
deliberately exposes **neither** of them.

- **No signing.** A signature with a national ID is a legally significant act that needs the physical
  card and a PIN. A model must never be able to trigger it. Signing stays a human, manual action.
- **No identity or photo.** `fetch-identity` and `fetch-photo` return personal and biometric data.
  That must not flow into a model's context, so those commands are not exposed.

What the model sees from verification is **redacted by default**. The model receives the indication,
the trust status, and the issuer (a public CA), but not the signer's name or document number.

## Tools

| Tool | What it does |
|---|---|
| `verify(path, original=None, redact=True)` | Verify one signed file (PDF/PAdES, XAdES XML, detached CMS/.p7s). Returns the indication, per-signature trust and checks. |
| `verify_batch(paths, redact=True)` | Verify many files. Returns a summary count by indication plus a compact per-file result (indication, trusted, issuing CA). |
| `validate_ci(number)` | Validate a cédula's check digit (arithmetic consistency only, not an identity check). |
| `doctor()` | Report the local setup status (PC/SC, PKCS#11 module, card, bundled CAs). |

`verify_batch` handles self-contained signatures (PDF/PAdES, XAdES XML). A detached `.p7s` needs its
original file, so verify those one at a time with `verify(path, original=...)`.

Verification is offline, with certificate-chain validation up to the Uruguayan national root. A
`VALID` result is a technical assessment, not a statement of legal validity. For authoritative
verification, use [AGESIC's official validator](https://firma.gub.uy/). This is an independent, unofficial tool,
not affiliated with or endorsed by AGESIC.

## Requirements

The `firmauy` CLI must be installed and on `PATH`.

```bash
uv tool install firmauy
firmauy --version
```

(Override the executable with the `FIRMAUY_BIN` environment variable if it lives elsewhere.)

## Configuration

All are optional and configured through environment variables.

| Variable | Default | Purpose |
|---|---|---|
| `FIRMAUY_BIN` | (found on `PATH`) | Path to the `firmauy` executable, if it is not on `PATH`. |
| `FIRMAUY_MCP_TIMEOUT` | `60` | Per-call timeout, in seconds, for each `firmauy` invocation. |
| `FIRMAUY_MCP_MAX_WORKERS` | `8` | Max concurrent verifications in `verify_batch`. Set to `1` for sequential. |
| `FIRMAUY_MCP_ALLOWED_ROOTS` | none (no limit) | Directories the tools may read from, separated by the OS path separator (`:` on Linux/macOS, `;` on Windows). When set, any path outside them (after resolving symlinks and `..`) is refused. |
| `FIRMAUY_MCP_ALLOWED_EXTENSIONS` | none (no limit) | Comma-separated types allowed for the **signed** file, e.g. `.pdf,.xml,.p7s`. Does not restrict a detached `.p7s`'s original. |

A malformed numeric override is ignored (it falls back to the default) rather than failing startup.

### Sandboxing (recommended)

This server hands file paths from the model to `firmauy`, which opens them. Confining what it can
read matters for a tool that touches national-ID signatures, so set both allowlists. They are
opt-in and fail closed.

```bash
export FIRMAUY_MCP_ALLOWED_ROOTS="/srv/inbox/signed"
export FIRMAUY_MCP_ALLOWED_EXTENSIONS=".pdf,.xml,.p7s"
```

Containment is checked on the resolved, canonical path (symlinks and `..` followed), so it is not
fooled by traversal, symlink escapes, or sibling directories sharing a name prefix. The root
allowlist also covers the `original` of a detached `.p7s`. The extension allowlist does not, because
that original is arbitrary content.

## Install

```bash
uv tool install firmauy-mcp-inspect
```

This puts the `firmauy-mcp-inspect` command on your `PATH`, which starts the server over stdio. You
can also run it without installing, straight from PyPI, with `uvx firmauy-mcp-inspect`.

Try it interactively with the MCP Inspector.

```bash
npx @modelcontextprotocol/inspector firmauy-mcp-inspect
```

To work on it from a clone instead, run `uv sync` and then `uv run firmauy-mcp-inspect`.

## Docker

A prebuilt image is published to the GitHub Container Registry on every release, so you can run
the server without installing Python or the `firmauy` CLI.

```bash
docker pull ghcr.io/carlosplanchon/firmauy-mcp-inspect:latest
```

Mount a directory with signed documents and pass any configuration via environment variables:

```bash
docker run -i --rm \
  -v /srv/inbox:/srv/inbox \
  -e FIRMAUY_MCP_ALLOWED_ROOTS=/srv/inbox \
  -e FIRMAUY_MCP_ALLOWED_EXTENSIONS=.pdf,.xml,.p7s \
  ghcr.io/carlosplanchon/firmauy-mcp-inspect:latest
```

Paths you ask the tools to inspect must exist **inside** the container, so mount the documents
(here at the same path on both sides) and point `FIRMAUY_MCP_ALLOWED_ROOTS` at the container path.
The container speaks the MCP stdio transport (hence `-i`), so let your MCP client manage it.

**Claude Code**

```bash
claude mcp add firmauy-inspect -- \
  docker run -i --rm \
  -v /srv/inbox:/srv/inbox \
  -e FIRMAUY_MCP_ALLOWED_ROOTS=/srv/inbox \
  -e FIRMAUY_MCP_ALLOWED_EXTENSIONS=.pdf,.xml,.p7s \
  ghcr.io/carlosplanchon/firmauy-mcp-inspect:latest
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "firmauy-inspect": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-v", "/srv/inbox:/srv/inbox",
        "-e", "FIRMAUY_MCP_ALLOWED_ROOTS=/srv/inbox",
        "-e", "FIRMAUY_MCP_ALLOWED_EXTENSIONS=.pdf,.xml,.p7s",
        "ghcr.io/carlosplanchon/firmauy-mcp-inspect:latest"
      ]
    }
  }
}
```

To build the image yourself instead (for example from a clone), a `Dockerfile` is included:

```bash
docker build -t firmauy-mcp-inspect .
```

## Configure your client

Both forms below assume `firmauy-mcp-inspect` is on your `PATH` from `uv tool install`. If a GUI
client cannot find it, use `uvx` as the command (`"command": "uvx"`, `"args": ["firmauy-mcp-inspect"]`)
or give the absolute path.

**Claude Code**

```bash
claude mcp add firmauy-inspect -- firmauy-mcp-inspect
```

**Claude Desktop** (`claude_desktop_config.json`)

```json
{
  "mcpServers": {
    "firmauy-inspect": {
      "command": "firmauy-mcp-inspect"
    }
  }
}
```

Then ask it things such as *"Verify every signed PDF in this folder, group them by issuing CA, and flag
anything that is not VALID or whose chain is not trusted."*

## Tests

```bash
uv run pytest
```

The tests mock the `firmauy` subprocess, so they need neither the CLI nor a card. The
path-sandboxing tests additionally create temporary files and a symlink on the local filesystem.

## License

Apache-2.0.
