# Security Policy

This server hands results from a national ID card to an AI model. Its whole job is to keep the
authority small and the personal data out, so a report about either is taken seriously. Thank you
for reporting responsibly.

## Reporting a vulnerability

Please do **not** open a public issue or pull request for a security problem.

Report it privately through GitHub's private vulnerability reporting:

- Go to <https://github.com/carlosplanchon/firmauy-mcp-inspect/security/advisories/new>, or the
  repository's **Security** tab, then **Report a vulnerability**.
- If that is not possible, email **carlosplanchon@cognitialabs.com** with `[SECURITY]` in the
  subject.

Include what you can: a description, steps to reproduce, a proof of concept, the affected version
and your assessment of the impact. Reports in Spanish or English are equally welcome.

## What counts

The two properties this server exists to provide, in rough order of severity:

- **Escaping the reduced authority.** Any path that reaches a capability the tools do not publish:
  signing, reading the cardholder's identity or photo, or running an arbitrary `firmauy` subcommand.
  The tools build every argument list in code, so a way to influence that list from a tool argument is
  a finding.
- **Leaking personal data to the model.** Any path that puts the signer's name or document number,
  or a token label carrying the holder's name, into a result while `FIRMAUY_MCP_ALLOW_PII` is off.
- **Escaping the path sandbox.** With `FIRMAUY_MCP_ALLOWED_ROOTS` set, any way to read a file
  outside those roots: traversal, symlinks, race conditions, encoding tricks.
- **Trusting the input too much.** A crafted file name or verification result that changes what the
  server does, rather than what it reports.
- **Release integrity**: the `firmauy-mcp-inspect` package on PyPI or the image on GHCR.

Out of scope here (report upstream instead):

- Bugs in the verification itself, the signing engine, or the CLI's `--json` contract: those belong
  to [FirmaUY](https://github.com/carlosplanchon/firmauy/security).
- The cédula card, AGESIC services, the official validator, and the proprietary PKCS#11 middleware.
- The cédula driver inside OpenSC: [OpenSC's security process](https://github.com/OpenSC/OpenSC/security).
- The MCP protocol itself or your MCP client.
- A model doing something unhelpful with results the tools were allowed to return. Deciding what
  the model may see is the operator's job, through the configuration documented in the README.

## What to expect

This is a community project with a single maintainer, so the process is honest rather than
corporate:

- Acknowledgment within **7 days**.
- An assessment and, when confirmed, a fix released as soon as practical, coordinated with you.
- Public disclosure through a GitHub security advisory once a fix is available, with credit to the
  reporter unless you prefer otherwise.

Only the **latest release** receives security fixes.
