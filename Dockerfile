# syntax=docker/dockerfile:1
# Hardened imap-mcp image: Streamable HTTP transport, non-root, read-only friendly.
# Base images are pinned by digest; Python deps come from uv.lock (--locked).

ARG PYTHON_IMAGE=python:3.13.18-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.13.5@sha256:32a7bb39b496babbd997b0a39a4d66c126bdaf5661b302bf6f06abda8deca6ff

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS build
COPY --from=uv /uv /usr/local/bin/uv
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_PYTHON=/usr/local/bin/python3 \
    UV_PROJECT_ENVIRONMENT=/app/.venv
WORKDIR /src
# Dependencies first (cached layer), exactly as locked, no dev group.
COPY pyproject.toml uv.lock README.md LICENSE ./
RUN uv sync --locked --no-dev --no-install-project
# Then the project itself, installed non-editable into the venv.
COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM ${PYTHON_IMAGE}
RUN groupadd --gid 10001 imapmcp \
 && useradd --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin imapmcp
COPY --from=build /app/.venv /app/.venv
ENV PATH=/app/.venv/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IMAP_MCP_TRANSPORT=streamable-http \
    IMAP_MCP_HTTP_HOST=0.0.0.0 \
    IMAP_MCP_HTTP_PORT=8000 \
    IMAP_MCP_ACCOUNTS=/config/accounts.toml
# IMAP_MCP_HTTP_TOKEN, IMAP_MCP_ALLOWED_HOSTS and the password env vars are
# provided at runtime (env_file), never baked into the image.
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import socket; socket.create_connection(('127.0.0.1', 8000), 3).close()"]
ENTRYPOINT ["imap-mcp"]
