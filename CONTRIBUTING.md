# Contributing to firmauy-mcp-inspect

Bug reports, questions and pull requests are welcome. This document covers the mechanics.

For security problems, do not open an issue: see [SECURITY.md](SECURITY.md).

## Developer Certificate of Origin (required)

This server is the safety layer between an AI model and a national ID card: the path sandbox, the
redaction and the reduced authority all live in its code. Provenance of a change to that code
matters, so every commit must be signed off under the
[Developer Certificate of Origin 1.1](https://developercertificate.org/):

```bash
git commit -s
```

That adds a `Signed-off-by: Your Name <your@email>` trailer, certifying that you wrote the change or
otherwise have the right to submit it under the project's license (Apache-2.0). Use your real name
and a working email. Pull requests with unsigned commits will be asked to add the sign-off:

```bash
git commit --amend --no-edit -s     # fix the last commit
```

Signing your commits cryptographically (`git commit -s -S`) is welcome on top of that, but not
required.

## What not to break

Two properties are the point of this project, so a change that weakens either needs to say so
out loud in the pull request:

- **The published surface stays small.** No tool may sign, read the cardholder's identity or photo,
  or take a subcommand from its caller. `_run` builds every argument list in code, and that is what
  keeps a model from reaching a capability this server does not offer.
- **Policy belongs to the operator.** Redaction and the path sandbox are configured through
  environment variables read at startup. Do not add a tool argument that lets the model choose
  either: a default the caller can override is a suggestion, not a boundary.

The reasoning behind running the CLI as a subprocess, instead of importing `firmauy.api`, is in the
[README](README.md#why-a-subprocess-and-not-the-python-api). It is deliberate, not a leftover.

## Pull requests

- Run the suite and the linter before pushing:

  ```bash
  uv sync
  uv run pytest
  uvx ruff check src/
  ```

- Tests must never need a card, a PIN, a network or the `firmauy` CLI: they mock the subprocess.
- Never include real personal data: no names, document numbers, MRZ data, photos, certificates or
  unredacted output, in code, fixtures, or the pull request itself.
- English for code, comments, commit messages and docs. Spanish is fine everywhere else.
