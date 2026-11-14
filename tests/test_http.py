"""Streamable HTTP transport: mandatory bearer token, Host check, body cap, startup refusal.

A real uvicorn server runs on 127.0.0.1 (random port); no IMAP account is involved
(the test config only has a disabled account).
"""

from __future__ import annotations

import json
import socket
import threading
import time
import urllib.error
import urllib.request

import pytest
import uvicorn

from imap_mcp import accounts, http_app, server

TOKEN = "a" * 20 + "B" * 20  # 40 printable chars


@pytest.fixture
def disabled_only_config(tmp_path, monkeypatch):
    path = tmp_path / "accounts.toml"
    path.write_text(
        '[[account]]\nkey = "off"\nemail = "a@example.com"\nhost = "imap.example.com"\n'
        'password_env = "OFF_PW"\nenabled = false\n'
    )
    monkeypatch.setenv("IMAP_MCP_ACCOUNTS", str(path))
    accounts._load.cache_clear()
    yield path
    accounts._load.cache_clear()


@pytest.fixture
def http_server(disabled_only_config):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    cfg = http_app.load_http_config({"IMAP_MCP_HTTP_TOKEN": TOKEN, "IMAP_MCP_HTTP_PORT": str(port)})
    srv = uvicorn.Server(
        uvicorn.Config(
            http_app.build_app(server.mcp, cfg), host="127.0.0.1", port=port, log_level="error"
        )
    )
    thread = threading.Thread(target=srv.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 10
    while not srv.started:
        if time.monotonic() > deadline:
            pytest.fail("uvicorn did not start")
        time.sleep(0.02)
    yield port
    srv.should_exit = True
    thread.join(5)


def post(port, body: bytes | dict, headers: dict | None = None):
    data = body if isinstance(body, bytes) else json.dumps(body).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}/mcp",
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": "2025-06-18",
            **(headers or {}),
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


AUTH = {"Authorization": f"Bearer {TOKEN}"}
TOOLS_LIST = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}


# ----------------------------------------------------------------------------- startup


@pytest.mark.parametrize(
    "env",
    [
        {},
        {"IMAP_MCP_HTTP_TOKEN": ""},
        {"IMAP_MCP_HTTP_TOKEN": "short"},
        {"IMAP_MCP_HTTP_TOKEN": "x" * 31},
        {"IMAP_MCP_HTTP_TOKEN": "with space " + "x" * 40},
    ],
)
def test_refuses_to_start_without_a_strong_token(env):
    with pytest.raises(http_app.HTTPConfigError, match="IMAP_MCP_HTTP_TOKEN"):
        http_app.load_http_config(env)


def test_main_exits_without_token(disabled_only_config, monkeypatch):
    monkeypatch.delenv("IMAP_MCP_HTTP_TOKEN", raising=False)
    monkeypatch.setattr(http_app, "serve", lambda *a: pytest.fail("must not serve"))
    with pytest.raises(SystemExit) as exc:
        server.main(["--transport", "streamable-http"])
    assert "IMAP_MCP_HTTP_TOKEN" in str(exc.value)


def test_main_defaults_to_stdio(monkeypatch):
    monkeypatch.delenv("IMAP_MCP_TRANSPORT", raising=False)
    called = []
    monkeypatch.setattr(server.mcp, "run", lambda *a, **k: called.append((a, k)))
    server.main([])
    assert called == [((), {})]


def test_config_defaults():
    cfg = http_app.load_http_config({"IMAP_MCP_HTTP_TOKEN": TOKEN})
    assert (cfg.host, cfg.port) == ("127.0.0.1", 8000)
    assert cfg.allowed_hosts == ("127.0.0.1:8000", "localhost:8000")


def test_config_allowed_hosts_override():
    cfg = http_app.load_http_config(
        {"IMAP_MCP_HTTP_TOKEN": TOKEN, "IMAP_MCP_ALLOWED_HOSTS": "imap-mcp:8000, x:1"}
    )
    assert cfg.allowed_hosts == ("imap-mcp:8000", "x:1")


# ----------------------------------------------------------------------------- auth


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer " + "z" * 40},
        {"Authorization": f"Bearer {TOKEN}x"},
        {"Authorization": f"bearer {TOKEN}"},
        {"Authorization": TOKEN},
        {"Authorization": f"Basic {TOKEN}"},
    ],
)
def test_requests_without_the_exact_token_get_401(http_server, headers):
    status, body = post(http_server, TOOLS_LIST, headers)
    assert status == 401
    assert "tools" not in body


def test_valid_token_lists_the_four_read_only_tools(http_server):
    status, body = post(http_server, TOOLS_LIST, AUTH)
    assert status == 200
    names = {t["name"] for t in json.loads(body)["result"]["tools"]}
    assert names == {"list_accounts", "list_emails", "search_emails", "get_email"}


def test_valid_token_can_call_a_tool(http_server):
    call = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "list_accounts", "arguments": {}},
    }
    status, body = post(http_server, call, AUTH)
    assert status == 200
    result = json.loads(body)["result"]
    assert result["isError"] is False
    assert result["structuredContent"]["result"][0]["status"] == "disabled"


def test_input_validation_still_applies_over_http(http_server):
    call = {
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {"name": "search_emails", "arguments": {"query": "x\r\nA1 EXPUNGE"}},
    }
    status, body = post(http_server, call, AUTH)
    assert status == 200
    assert json.loads(body)["result"]["isError"] is True


# ----------------------------------------------------------------------------- transport hardening


def test_forged_host_header_is_rejected(http_server):
    status, _ = post(http_server, TOOLS_LIST, {**AUTH, "Host": "evil.example:80"})
    assert status == 421


def test_oversized_body_is_rejected(http_server):
    big = json.dumps({**TOOLS_LIST, "pad": "x" * (http_app.MAX_REQUEST_BODY + 1)}).encode()
    status, _ = post(http_server, big, AUTH)
    assert status == 413


def test_only_mcp_path_is_served(http_server):
    req = urllib.request.Request(f"http://127.0.0.1:{http_server}/", headers=AUTH)
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 404
