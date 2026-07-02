FROM python:3.12-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcsclite-dev \
    swig \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

RUN uv tool install firmauy

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/
RUN uv pip install --system .

ENV PATH="/root/.local/bin:${PATH}"

RUN firmauy --version

COPY tests/ tests/
RUN uv run pytest tests/ -v

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcsclite1 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin
COPY --from=builder /root/.local /root/.local

ENV PATH="/root/.local/bin:${PATH}"

ENTRYPOINT ["firmauy-mcp-inspect"]
