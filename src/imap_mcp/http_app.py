"""Streamable HTTP transport with a mandatory bearer token.

Opt-in (stdio stays the default). Configuration comes from the environment:

- IMAP_MCP_HTTP_TOKEN    REQUIRED, >= 32 chars. Every request must send
                         `Authorization: Bearer <token>`; compared in constant time.
                         The server refuses to start without it.
- IMAP_MCP_HTTP_HOST     bind address (default 127.0.0.1; the container uses 0.0.0.0)
- IMAP_MCP_HTTP_PORT     port (default 8000)
- IMAP_MCP_ALLOWED_HOSTS comma-separated Host header values accepted (DNS-rebinding
                         protection), default "127.0.0.1:<port>,localhost:<port>".

The MCP endpoint is served at /mcp, stateless (no server-side sessions), JSON
responses, request bodies capped at 64 KiB.
"""

from __future__ import annotations

import hmac
import os
import re
from dataclasses import dataclass

from mcp.server.transport_security import TransportSecuritySettings

MIN_TOKEN_CHARS = 32
MAX_REQUEST_BODY = 64 * 1024
MCP_PATH = "/mcp"

_TOKEN_RE = re.compile(r"^[\x21-\x7e]+$")  # printable ASCII, no spaces


class HTTPConfigError(ValueError):
    """Invalid or missing HTTP transport configuration."""


@dataclass(frozen=True)
class HTTPConfig:
    token: str
    host: str
    port: int
    allowed_hosts: tuple[str, ...]


def load_http_config(env: dict[str, str] | None = None) -> HTTPConfig:
    env = os.environ if env is None else env
    token = env.get("IMAP_MCP_HTTP_TOKEN", "")
    if len(token) < MIN_TOKEN_CHARS or not _TOKEN_RE.match(token):
        raise HTTPConfigError(
            f"IMAP_MCP_HTTP_TOKEN must be set to >= {MIN_TOKEN_CHARS} printable characters "
            "(e.g. `openssl rand -hex 32`); refusing to serve HTTP without authentication"
        )
    host = env.get("IMAP_MCP_HTTP_HOST", "127.0.0.1")
    try:
        port = int(env.get("IMAP_MCP_HTTP_PORT", "8000"))
    except ValueError:
        raise HTTPConfigError("IMAP_MCP_HTTP_PORT must be an integer") from None
    if not 1 <= port <= 65535:
        raise HTTPConfigError("IMAP_MCP_HTTP_PORT must be between 1 and 65535")
    raw_hosts = env.get("IMAP_MCP_ALLOWED_HOSTS") or f"127.0.0.1:{port},localhost:{port}"
    allowed = tuple(h.strip() for h in raw_hosts.split(",") if h.strip())
    if not allowed:
        raise HTTPConfigError("IMAP_MCP_ALLOWED_HOSTS is empty")
    return HTTPConfig(token=token, host=host, port=port, allowed_hosts=allowed)


class BearerAuthMiddleware:
    """ASGI middleware: 401 unless the exact bearer token is presented."""

    def __init__(self, app, token: str):
        self.app = app
        self._expected = f"Bearer {token}".encode("ascii")

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":  # lifespan events pass through
            await self.app(scope, receive, send)
            return
        values = [v for k, v in scope.get("headers", []) if k == b"authorization"]
        presented = values[0] if len(values) == 1 else b""
        if not hmac.compare_digest(presented, self._expected):
            body = b'{"error":"unauthorized"}'
            await send(
                {
                    "type": "http.response.start",
                    "status": 401,
                    "headers": [
                        (b"content-type", b"application/json"),
                        (b"content-length", str(len(body)).encode()),
                        (b"www-authenticate", b'Bearer realm="imap-mcp"'),
                    ],
                }
            )
            await send({"type": "http.response.body", "body": body})
            return
        await self.app(scope, receive, send)


def build_app(server, config: HTTPConfig):
    """Starlette app for `server` (an MCPServer), wrapped in bearer auth."""
    app = server.streamable_http_app(
        streamable_http_path=MCP_PATH,
        json_response=True,
        stateless_http=True,
        max_request_body_size=MAX_REQUEST_BODY,
        transport_security=TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(config.allowed_hosts),
            allowed_origins=[],
        ),
        host=config.host,
    )
    return BearerAuthMiddleware(app, config.token)


def serve(server, config: HTTPConfig) -> None:  # pragma: no cover -- exercised in container
    import uvicorn

    uvicorn.run(
        build_app(server, config),
        host=config.host,
        port=config.port,
        log_level="warning",
        access_log=False,
        server_header=False,
        proxy_headers=False,
    )
