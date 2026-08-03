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

What the model sees from verification carries **no personal data**. The model receives the
indication, the trust status, and the issuer (a public CA), but not the signer's name or document
number. That is not a default the model can override: no tool takes an argument for it. Letting
identifying data through is the operator's decision, made once at startup with
`FIRMAUY_MCP_ALLOW_PII` (see [Configuration](#configuration)).

### Why a subprocess and not the Python API

FirmaUY ships a public Python API (`firmauy.api`) that this server could import instead of running
the CLI. That would be a mistake here, and the process boundary is deliberate:

- **The capability stays out of the process.** Importing `firmauy.api` would load signing and
  cardholder-data reading into the same process as the model-driven code, one attribute away.
  Running the CLI means those capabilities are not present at all, which is a stronger guarantee
  than being present and not called. To be precise about what this does and does not buy: signing
  still exists in the `firmauy` executable on the host. What this server guarantees is that it is
  absent from *this* process and unreachable from it, because the argument list of every call is
  built in code and no tool accepts a subcommand from its caller.
- **The `--json` output is a versioned contract.** It carries a `schema_version` and changes far
  more slowly than the young library API.
- **Timeouts actually work.** `subprocess` kills a hung process. A blocking in-process call cannot
  be cancelled that way in Python.

The cost is a process spawn per call, which is irrelevant next to those three.

## Tools

| Tool | What it does |
|---|---|
| `verify(path, original=None)` | Verify one signed file (PDF/PAdES, XAdES XML, detached CMS/.p7s). Returns the indication, per-signature trust and checks. |
| `verify_batch(paths)` | Verify many files. Returns a summary count by indication plus a compact per-file result (indication, trusted, issuing CA). |
| `validate_ci(number)` | Validate a cédula's check digit (arithmetic consistency only, not an identity check). |
| `doctor()` | Report the local setup status (PC/SC, PKCS#11 module, card, bundled CAs). Every check's status is reported; the card and token details are withheld, since some PKCS#11 modules use the cardholder's name as the token label. |

None of them takes a redaction argument: whether personal data may reach the model is set by the
operator at startup, not chosen per call.

`verify_batch` handles self-contained signatures (PDF/PAdES, XAdES XML). A detached `.p7s` needs its
original file, so verify those one at a time with `verify(path, original=...)`.

Verification is offline, with certificate-chain validation up to the Uruguayan national root. A
`VALID` result is a technical assessment, not a statement of legal validity. For authoritative
verification, use [AGESIC's official validator](https://firma.gub.uy/). This is an independent, unofficial tool,
not affiliated with or endorsed by AGESIC.

## Requirements

The `firmauy` CLI must be installed and on `PATH`, version **1.13.1 or newer**.

That is where a signature timestamp's integrity, validity and trust became three separate answers,
where `--tsa-ca` started applying to every format instead of being accepted and ignored on some, and
where a malformed timestamp token started coming back as INDETERMINATE instead of raising. This
server reports what the CLI concludes, so on older semantics it would be announcing timestamp trust
the CLI never established.

1.9 is where each diagnostic check declares whether its detail carries the cardholder's data, which
is how this server decides what to withhold. With an older CLI the `doctor` tool still works, but
withholds every detail.

```bash
uv tool install firmauy
firmauy --version
```

It is an extra rather than a hard dependency, so you can pin the CLI version yourself or reuse one
you already have. To pull it in with the server instead, install the `cli` extra:

```bash
uv tool install firmauy-mcp-inspect --with firmauy    # or: pip install "firmauy-mcp-inspect[cli]"
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
| `FIRMAUY_MCP_ALLOW_PII` | `false` | Let identifying data reach the model: the signer's name and document number, and the card and token check details. Off by default, and no tool can override it. Turn it on only if you understand that this data will enter (and usually leave with) the model's context. |
| `FIRMAUY_MCP_TSA_CA` | none | Path to a PEM bundle of timestamping authority certificates. When set, a signature timestamp's own chain is validated against it and `timestamp.trusted` becomes `true` or `false`. Unset, it stays `null`: nothing was evaluated, which is not the same as untrusted. Like `ALLOW_PII`, no tool can override it. |

A malformed numeric override is ignored (it falls back to the default) rather than failing startup.
`FIRMAUY_MCP_TSA_CA` is different: if it is set and the file is not there, the server refuses to
start. Carrying on would report every timestamp as unvalidated while the setting says otherwise,
which is wrong and silent.

### Timestamps and who vouches for them

The two trusts in a result answer different questions and neither implies the other.
`signature.trusted` is the signer's chain to the Uruguayan national root. `signature.timestamp.trusted`
is the timestamping authority's chain to the roots **you** configured here, and it is three-valued:
`null` means no roots were configured and nothing was looked at, `false` means they were and it did
not chain. A file can be `VALID` with a timestamp that is only asserted.

Which authorities count is deliberately yours to decide and not the model's. Letting a tool argument
pick its own trust roots would let the model define the policy it is being measured against.

Note what this does **not** settle: under Ley 18.600 art. 6 a document makes proof of its date only
through a provider accredited by the UCE. A timestamp validated against any other authority is real
cryptographic evidence of when the signature existed, and is not that.

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
  -v /srv/inbox:/srv/inbox:ro \
  -e FIRMAUY_MCP_ALLOWED_ROOTS=/srv/inbox \
  -e FIRMAUY_MCP_ALLOWED_EXTENSIONS=.pdf,.xml,.p7s \
  ghcr.io/carlosplanchon/firmauy-mcp-inspect:latest
```

Paths you ask the tools to inspect must exist **inside** the container, so mount the documents
(read-only via `:ro`, since the server only ever reads them, at the same path on both sides) and point
`FIRMAUY_MCP_ALLOWED_ROOTS` at the container path. The container speaks the MCP stdio transport
(hence `-i`), so let your MCP client manage it.

**Claude Code**

```bash
claude mcp add firmauy-inspect -- \
  docker run -i --rm \
  -v /srv/inbox:/srv/inbox:ro \
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
        "-v", "/srv/inbox:/srv/inbox:ro",
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

## Contributing & security

Pull requests are welcome. The mechanics, including the required
[DCO](https://developercertificate.org/) sign-off (`git commit -s`) and the two properties a change
must not weaken, are in **[CONTRIBUTING.md](CONTRIBUTING.md)**.

Found a way past the reduced authority, the redaction or the path sandbox? Report it privately:
see **[SECURITY.md](SECURITY.md)**, not a public issue.

## License

Apache-2.0.
