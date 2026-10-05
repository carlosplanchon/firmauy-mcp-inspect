# Pinned by digest rather than by tag. `python:3.12-slim` is a name its owner moves, so the same
# Dockerfile built twice a month apart is two different images with nothing in the repository
# saying so. The tag it carried is beside it, because a bare sixty-four character hash says
# nothing about what it is and an upgrade has to be reviewable.
#
# What this does not freeze is the apt layer below: Debian's archive serves what it has on the
# day, and pinning package versions there breaks the moment the archive rotates them out. That is
# the deliberate seam. Everything this server's answers depend on is pinned; the C libraries
# underneath it float forward with Debian's security updates, which is the safer direction for
# the one part that is not resolving Python packages.
FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcsclite-dev \
    swig \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.24@sha256:99ea34acedc870ba4ad11a1f540a1c04267c9f30aadc465a94406f52dfda2c36 /uv /usr/local/bin/uv

# The CLI this image serves, and the tree underneath it. Pinning the version alone was half the
# job: an exact `uv tool install firmauy==<version>` still resolved cryptography, pyHanko and the
# rest to whatever was newest that morning, so two builds could bake different verifiers behind
# the same CLI version, which is exactly the thing the pin was there to prevent. --exclude-newer
# resolves the whole tree as it stood on one date. The two are bumped together, and a build can
# override either (docker build --build-arg FIRMAUY_VERSION=... --build-arg FIRMAUY_RESOLVED_AT=...).
#
# The pin can never sit below _MIN_FIRMAUY in server.py, which refuses an older CLI: an image pinned
# under the floor builds cleanly and then refuses every call. And the date has to fall after the
# pinned release, or --exclude-newer hides it and the build fails.
ARG FIRMAUY_VERSION=1.21.0
ARG FIRMAUY_RESOLVED_AT=2026-10-05T00:00:00Z
RUN uv tool install --exclude-newer "${FIRMAUY_RESOLVED_AT}" "firmauy==${FIRMAUY_VERSION}"

WORKDIR /app
COPY pyproject.toml uv.lock ./
COPY src/ src/

# From the lockfile, not from a fresh resolve. `uv pip install .` reads the ranges in pyproject
# and picks whatever satisfies them that day, which put the server's own dependencies in the same
# position the CLI's were. --locked is the other half: it refuses if the lock and pyproject have
# drifted, so an image can never be built from dependencies that are in no commit.
RUN uv export --locked --no-dev --no-emit-project --no-hashes --format requirements.txt \
        > /tmp/requirements.txt \
    && uv pip install --system -r /tmp/requirements.txt \
    && uv pip install --system --no-deps .

ENV PATH="/root/.local/bin:${PATH}"

RUN firmauy --version

COPY tests/ tests/
# Smoke-test the installed package. pytest goes to a throwaway prefix so it never
# ends up in the site-packages copied into the runtime image.
RUN uv pip install --target /tmp/testdeps pytest \
    && PYTHONPATH=/tmp/testdeps python -m pytest tests/ -q \
    && rm -rf /tmp/testdeps

FROM python:3.12-slim@sha256:2c941e860699f878900b0edc2403613c234d4b32eda3cc9fa7036991a2a63c4a

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /root/.local /root/.local

ENV PATH="/root/.local/bin:${PATH}"

ENTRYPOINT ["firmauy-mcp-inspect"]
