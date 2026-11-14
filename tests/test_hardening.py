"""Tests of the hardened fork: TLS options, read-only guard, limits, newsletter flag.

All network tests talk to tests/fake_imap.py on 127.0.0.1 -- never to a real account.
"""

from __future__ import annotations

import ast
import re
import ssl
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from fake_imap import FakeIMAPServer, make_cert  # tests/ is on sys.path (rootdir import)

from imap_mcp import accounts, imap, server, tls
from imap_mcp.tls import CertificatePinError, ForbiddenCommandError, StartTLSError

SRC = Path(__file__).resolve().parents[1] / "src" / "imap_mcp"


# ----------------------------------------------------------------------------- fixtures


@pytest.fixture
def certs(tmp_path):
    return SimpleNamespace(
        bridge=make_cert(tmp_path, "bridge", ip="127.0.0.1"),  # like Proton Bridge
        other=make_cert(tmp_path, "other", ip="127.0.0.1"),  # untrusted impostor
    )


@pytest.fixture
def servers():
    started = []

    def start(cert, **kw):
        srv = FakeIMAPServer(cert, **kw)
        started.append(srv)
        return srv

    yield start
    for s in started:
        s.close()


@pytest.fixture
def write_config(tmp_path, monkeypatch):
    def write(account_toml: str, settings_toml: str = "") -> None:
        path = tmp_path / "accounts.toml"
        path.write_text(textwrap.dedent(settings_toml) + textwrap.dedent(account_toml))
        monkeypatch.setenv("IMAP_MCP_ACCOUNTS", str(path))
        monkeypatch.setenv("T_PW", "test-password")
        accounts._load.cache_clear()

    yield write
    accounts._load.cache_clear()


def account_toml(port, *, security="ssl", host="localhost", extra=""):
    return f"""
    [[account]]
    key = "t"
    email = "alpha@example.com"
    host = "{host}"
    port = {port}
    security = "{security}"
    password_env = "T_PW"
    {extra}
    """


# ----------------------------------------------------------------------------- config


def test_defaults_are_backward_compatible(write_config):
    write_config(
        """
        [[account]]
        key = "t"
        email = "a@example.com"
        host = "imap.example.com"
        password_env = "T_PW"
        """
    )
    a = accounts.get_account("t")
    assert (a.security, a.port, a.ca_file, a.tls_server_name, a.tls_fingerprint_sha256) == (
        "ssl",
        993,
        None,
        None,
        None,
    )
    assert accounts.settings().max_body_chars == 20_000


def test_starttls_default_port_is_143(write_config):
    write_config(account_toml(0, security="starttls").replace("port = 0\n", ""))
    assert accounts.get_account("t").port == 143


@pytest.mark.parametrize(
    "extra, message",
    [
        ('security = "plain"', "security must be one of"),
        ('ca_file = "/nonexistent/ca.pem"', "ca_file not found"),
        ('tls_fingerprint_sha256 = "abcd"', "64 hex chars"),
        ('tls_server_name = "  "', "non-empty string"),
    ],
)
def test_invalid_tls_options_are_rejected(write_config, extra, message):
    toml = account_toml(993).replace('security = "ssl"', "") + extra
    write_config(toml)
    with pytest.raises(accounts.ConfigError, match=message):
        accounts.all_accounts()


def test_fingerprint_is_normalized(write_config):
    fp = ":".join(["AB"] * 32)
    write_config(account_toml(993, extra=f'tls_fingerprint_sha256 = "{fp}"'))
    assert accounts.get_account("t").tls_fingerprint_sha256 == "ab" * 32


def test_ssl_context_always_verifies(certs, write_config):
    write_config(account_toml(993, extra=f'ca_file = "{certs.bridge.cert_path}"'))
    ctx = tls.build_ssl_context(accounts.get_account("t"))
    assert ctx.verify_mode == ssl.CERT_REQUIRED
    assert ctx.check_hostname is True


# ----------------------------------------------------------------------------- TLS: success paths


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_ca_file_and_tls_server_name_succeed(certs, servers, write_config, mode):
    srv = servers(certs.bridge, mode=mode)
    write_config(
        account_toml(
            srv.port,
            security=mode,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    rows = imap.fetch_rows(accounts.get_account("t"), limit=5)
    assert [r["subject"] for r in rows] == ["Weekly digest"]
    cmds = srv.commands()
    assert "LOGIN" in cmds
    if mode == "starttls":
        assert cmds.index("STARTTLS") < cmds.index("LOGIN")  # never log in in cleartext


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_correct_fingerprint_succeeds(certs, servers, write_config, mode):
    srv = servers(certs.bridge, mode=mode)
    write_config(
        account_toml(
            srv.port,
            security=mode,
            extra=(
                f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"\n'
                f'tls_fingerprint_sha256 = "{certs.bridge.fingerprint}"'
            ),
        )
    )
    with imap.open_box(accounts.get_account("t")):
        pass
    assert "LOGIN" in srv.commands()


# ----------------------------------------------------------------------------- TLS: refusals


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_untrusted_certificate_is_refused(certs, servers, write_config, mode):
    srv = servers(certs.other, mode=mode)  # impostor presents a cert we don't trust
    write_config(
        account_toml(
            srv.port,
            security=mode,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    with pytest.raises(ssl.SSLCertVerificationError), imap.open_box(accounts.get_account("t")):
        pass
    assert "LOGIN" not in srv.commands()


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_system_store_does_not_trust_self_signed(certs, servers, write_config, mode):
    srv = servers(certs.bridge, mode=mode)
    write_config(account_toml(srv.port, security=mode, extra='tls_server_name = "127.0.0.1"'))
    with pytest.raises(ssl.SSLCertVerificationError), imap.open_box(accounts.get_account("t")):
        pass
    assert "LOGIN" not in srv.commands()


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_name_mismatch_is_refused_without_tls_server_name(certs, servers, write_config, mode):
    # Connect host "localhost" vs a cert valid only for IP 127.0.0.1 (the Bridge case).
    srv = servers(certs.bridge, mode=mode)
    write_config(
        account_toml(srv.port, security=mode, extra=f'ca_file = "{certs.bridge.cert_path}"')
    )
    with (
        pytest.raises(ssl.SSLCertVerificationError, match="(?i)mismatch"),
        imap.open_box(accounts.get_account("t")),
    ):
        pass
    assert "LOGIN" not in srv.commands()


def test_wrong_tls_server_name_is_refused(certs, servers, write_config):
    srv = servers(certs.bridge)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "10.9.9.9"',
        )
    )
    with pytest.raises(ssl.SSLCertVerificationError), imap.open_box(accounts.get_account("t")):
        pass


@pytest.mark.parametrize("mode", ["ssl", "starttls"])
def test_wrong_fingerprint_is_refused(certs, servers, write_config, mode):
    srv = servers(certs.bridge, mode=mode)
    write_config(
        account_toml(
            srv.port,
            security=mode,
            extra=(
                f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"\n'
                f'tls_fingerprint_sha256 = "{"0" * 64}"'
            ),
        )
    )
    with pytest.raises(CertificatePinError), imap.open_box(accounts.get_account("t")):
        pass
    assert "LOGIN" not in srv.commands()


@pytest.mark.parametrize("server_kw", [dict(refuse_starttls=True), dict(advertise_starttls=False)])
def test_starttls_failure_never_falls_back_to_cleartext(certs, servers, write_config, server_kw):
    srv = servers(certs.bridge, mode="starttls", **server_kw)
    write_config(
        account_toml(
            srv.port,
            security="starttls",
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    with pytest.raises(StartTLSError), imap.open_box(accounts.get_account("t")):
        pass
    assert "LOGIN" not in srv.commands()


def test_login_refused_on_unencrypted_connection():
    with pytest.raises(ForbiddenCommandError, match="unencrypted"):
        tls.check_command("LOGIN", ('"a"', '"b"'), encrypted=False)


def test_tls_errors_are_reported_without_details(certs, servers, write_config):
    srv = servers(certs.other)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    rows = server.list_emails(account="t")
    assert rows[0]["error"].startswith("tls: certificate verification failed")
    assert "test-password" not in str(rows)


# ----------------------------------------------------------------------------- read-only


def test_inbox_is_opened_with_examine_never_select(certs, servers, write_config):
    srv = servers(certs.bridge)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    imap.fetch_rows(accounts.get_account("t"))
    imap.fetch_one(accounts.get_account("t"), "42")
    cmds = srv.commands()
    assert "EXAMINE" in cmds and "SELECT" not in cmds
    fetches = [line for line in srv.received if b"UID FETCH" in line.upper()]
    assert fetches and all(b"BODY.PEEK[" in line.upper() for line in fetches)


@pytest.mark.parametrize(
    "name, args",
    [
        ("STORE", ("1", "+FLAGS", "(\\Deleted)")),
        ("UID", ("STORE", "1", "+FLAGS", "(\\Seen)")),
        ("UID", ("COPY", "1", "Trash")),
        ("UID", ("MOVE", "1", "Trash")),
        ("UID", ("EXPUNGE", "1")),
        ("EXPUNGE", ()),
        ("APPEND", ("INBOX",)),
        ("DELETE", ("INBOX",)),
        ("CREATE", ("X",)),
        ("RENAME", ("INBOX", "X")),
        ("SUBSCRIBE", ("X",)),
        ("SELECT", ("INBOX",)),
        ("FETCH", ("1", "(BODY.PEEK[])")),
        ("UID", ("FETCH", "1", "(BODY[] UID)")),
        ("UID", ("FETCH", "1", "(RFC822)")),
        ("UID", ("FETCH", "1", "(RFC822.TEXT)")),
        ("UID", ("SEARCH", "CHARSET", "US-ASCII", b'(TEXT "x\r\nA1 EXPUNGE")')),
    ],
)
def test_guard_blocks_write_and_seen_setting_commands(name, args):
    with pytest.raises(ForbiddenCommandError):
        tls.check_command(name, args, encrypted=True)


@pytest.mark.parametrize(
    "name, args",
    [
        ("EXAMINE", ('"INBOX"',)),
        ("UID", ("SEARCH", "CHARSET", "US-ASCII", b"(ALL)")),
        ("UID", ("FETCH", "42", "(BODY.PEEK[] UID FLAGS RFC822.SIZE)")),
        ("UID", ("FETCH", "42", "(BODY.PEEK[HEADER] UID FLAGS RFC822.SIZE)")),
        ("LOGOUT", ()),
    ],
)
def test_guard_allows_read_only_commands(name, args):
    tls.check_command(name, args, encrypted=True)


def test_guard_stops_write_commands_before_the_wire(certs, servers, write_config):
    srv = servers(certs.bridge)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    with imap.open_box(accounts.get_account("t")) as box:
        with pytest.raises(ForbiddenCommandError):
            box.client.uid("STORE", "42", "+FLAGS", "(\\Deleted)")
        with pytest.raises(ForbiddenCommandError):
            box.client.expunge()
        with pytest.raises(ForbiddenCommandError):
            box.client.select("INBOX")
    assert not {"UID STORE", "EXPUNGE", "SELECT"} & set(srv.commands())


# ----------------------------------------------------------------------------- injection & inputs


@pytest.mark.parametrize("query", ["x\r\nA1 EXPUNGE", "x\nA1 EXPUNGE", "x\x00y", "a" * 300, " "])
def test_search_query_injection_is_rejected_before_network(config, query, monkeypatch):
    monkeypatch.setattr(imap, "open_box", lambda a: pytest.fail("network must not be used"))
    with pytest.raises(ValueError):
        server.search_emails(query)


@pytest.mark.parametrize("uid", ["1:*", "*", "1,2", "0", "-1", "1 OR ALL", "abc", ""])
def test_get_email_rejects_uid_sets_and_garbage(config, uid, monkeypatch):
    monkeypatch.setattr(imap, "fetch_one", lambda a, u: pytest.fail("network must not be used"))
    with pytest.raises(ValueError):
        server.get_email("alpha", uid)


@pytest.mark.parametrize("limit, expected", [(1, 1), (25, 25), (100, 100), (10_000, 100)])
def test_limit_is_capped(limit, expected):
    assert imap.clamp_limit(limit) == expected


@pytest.mark.parametrize("limit", [0, -5, True])
def test_invalid_limit_is_rejected(limit):
    with pytest.raises(ValueError):
        imap.clamp_limit(limit)


def test_non_ascii_search_uses_utf8(certs, servers, write_config):
    srv = servers(certs.bridge)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    imap.fetch_rows(accounts.get_account("t"), query="été")
    assert any(b"SEARCH CHARSET UTF-8" in line.upper() for line in srv.received)


# ----------------------------------------------------------------------------- content


def test_list_unsubscribe_flag_end_to_end(certs, servers, write_config):
    srv = servers(certs.bridge)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        )
    )
    rows = imap.fetch_rows(accounts.get_account("t"))
    assert rows[0]["list_unsubscribe"] is True
    assert rows[0]["untrusted_content"] is True
    assert rows[0]["snippet"].startswith("Hello reader")


def test_list_unsubscribe_absent():
    msg = SimpleNamespace(
        uid="1",
        from_="a@b",
        to=(),
        subject="s",
        date=None,
        flags=(),
        text="t",
        html="",
        headers={},
    )
    assert imap.row(msg, "x")["list_unsubscribe"] is False


def test_body_is_truncated_to_max_body_chars(certs, servers, write_config):
    long_body = ("A" * 1000 + "\r\n") * 30  # ~30k chars
    message = (
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: long\r\n"
        b"Content-Type: text/plain\r\n\r\n" + long_body.encode()
    )
    srv = servers(certs.bridge, message=message)
    write_config(
        account_toml(
            srv.port,
            extra=f'ca_file = "{certs.bridge.cert_path}"\ntls_server_name = "127.0.0.1"',
        ),
        settings_toml="max_body_chars = 5000\n",
    )
    out = imap.fetch_one(accounts.get_account("t"), "42")
    assert out["body_truncated"] is True
    assert out["body"].endswith("[tronqué]")
    assert len(out["body"]) == 5000 + len(imap.TRUNCATED_MARK)
    assert out["body_chars"] > 5000


def test_short_body_is_not_truncated():
    assert imap.truncate("hello", 20_000) == ("hello", False)


def test_html_only_body_is_converted_to_text():
    html = (
        "<html><head><style>p{}</style><script>evil()</script></head>"
        "<body><p>Hi&nbsp;there</p></body></html>"
    )
    assert imap.html_to_text(html) == "Hi\xa0there"


# ----------------------------------------------------------------------------- static guard

# Command verbs that modify a mailbox or open it read-write.
WRITE_VERBS = r"(STORE|COPY|MOVE|EXPUNGE|APPEND|CREATE|RENAME|DELETE|SUBSCRIBE|UNSUBSCRIBE|SELECT)"
# imap-tools / imaplib methods that send those commands.
WRITE_METHODS = {
    "store",
    "copy",
    "move",
    "expunge",
    "append",
    "delete",
    "flag",
    "subscribe",
    "unsubscribe",
    "select",
    "create",
    "rename",
    "uid_copy",
    "uid_move",
}
IMAP_RECEIVERS = {"box", "mailbox", "client", "folder", "imap", "conn"}
UNVERIFIED_TLS = {"CERT_NONE", "_create_unverified_context", "_create_stdlib_context"}


def _docstring_nodes(tree):
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            body = node.body
            if body and isinstance(body[0], ast.Expr) and isinstance(body[0].value, ast.Constant):
                yield body[0].value


def _receiver_names(node):
    names = []
    while isinstance(node, ast.Attribute):
        names.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        names.append(node.id)
    return set(names)


def _violations(path: Path) -> list[str]:
    tree = ast.parse(path.read_text())
    docstrings = {id(n) for n in _docstring_nodes(tree)}
    # Patterns given to re.compile() are detectors (e.g. tls.py's deny regex), not commands.
    regex_literals = {
        id(node.args[0])
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "compile"
        and _receiver_names(node.func.value) == {"re"}
        and node.args
    }
    out = []
    for node in ast.walk(tree):
        where = f"{path.name}:{getattr(node, 'lineno', '?')}"
        # 1. String literals that are (or start with) a write command verb, or a non-PEEK fetch.
        if isinstance(node, ast.Constant) and isinstance(node.value, str | bytes):
            if id(node) in docstrings or id(node) in regex_literals:
                continue
            s = node.value.decode("latin-1") if isinstance(node.value, bytes) else node.value
            if re.match(rf"\s*(UID\s+)?{WRITE_VERBS}\b", s, re.I):
                out.append(f"{where}: command string {s!r}")
            if re.search(r"(?<!PEEK)BODY\[(?!HEADER)", s, re.I) or re.search(
                r"\bRFC822(?!\.(SIZE|HEADER))\b", s
            ):
                out.append(f"{where}: \\Seen-setting fetch item {s!r}")
        # 2. Calls to write methods on IMAP-ish objects (box.delete(), client.store()...).
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if (
                node.func.attr in WRITE_METHODS
                and _receiver_names(node.func.value) & IMAP_RECEIVERS
            ):
                out.append(f"{where}: call .{node.func.attr}() on an IMAP object")
            for kw in node.keywords:
                if kw.arg == "mark_seen" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is False
                ):
                    out.append(f"{where}: mark_seen must be the literal False")
                if kw.arg == "readonly" and not (
                    isinstance(kw.value, ast.Constant) and kw.value.value is True
                ):
                    out.append(f"{where}: readonly must be the literal True")
        # 3. Anything that weakens TLS verification.
        if isinstance(node, ast.Attribute) and node.attr in UNVERIFIED_TLS:
            out.append(f"{where}: unverified TLS ({node.attr})")
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if isinstance(target, ast.Attribute) and target.attr in (
                    "verify_mode",
                    "check_hostname",
                ):
                    out.append(f"{where}: assignment to {target.attr}")
    return out


def test_no_write_imap_command_in_source():
    """FAILS if any write/flag/SELECT command, non-PEEK fetch, or TLS weakening
    appears anywhere in src/imap_mcp (docstrings excluded)."""
    offenders = [v for path in sorted(SRC.glob("*.py")) for v in _violations(path)]
    assert offenders == []


@pytest.mark.parametrize(
    "snippet",
    [
        'box.client.uid("STORE", "1", "+FLAGS", "(\\\\Deleted)")',
        "box.delete(['1'])",
        "box.folder.create('X')",
        "box.fetch(crit, mark_seen=True)",
        'box.folder.set("INBOX", readonly=False)',
        'client.uid("FETCH", "1", "(BODY[])")',
        "ctx.check_hostname = False",
        "ctx = ssl._create_unverified_context()",
        'client.select("INBOX")',
    ],
)
def test_static_guard_detects_violations(tmp_path, snippet):
    """The static check itself must catch each forbidden construct."""
    f = tmp_path / "bad.py"
    f.write_text(snippet + "\n")
    assert _violations(f), snippet
