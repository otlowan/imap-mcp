"""Hardened IMAP transport: verified TLS and a read-only protocol guard.

Two independent layers:

1. TLS. Certificates are ALWAYS verified (ssl.create_default_context: CERT_REQUIRED
   and check_hostname=True; never weakened here). Per account you may:
   - trust a specific CA/certificate (ca_file) instead of the system store,
   - verify the certificate against another name than the connect host
     (tls_server_name; IP addresses are matched against IP SANs),
   - additionally pin the SHA-256 fingerprint of the presented certificate.
   STARTTLS never falls back to cleartext: if the upgrade fails, the connection
   is closed and LOGIN is never sent.

2. Protocol guard. Every command goes through `_command`, the single choke point
   of imaplib before bytes hit the socket. Only an allow-list of read-only
   commands may pass (no STORE/COPY/MOVE/EXPUNGE/APPEND/DELETE/CREATE/RENAME/
   SUBSCRIBE/SELECT…), UID FETCH must use BODY.PEEK, and NUL/CR/LF are refused in
   every argument (imaplib only does that itself since CPython 3.13).
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import imaplib
import re
import ssl

from imap_tools import BaseMailBox

from .accounts import Account

# Commands this server may ever send. EXAMINE (not SELECT) opens folders read-only.
ALLOWED_COMMANDS = frozenset(
    {"CAPABILITY", "STARTTLS", "LOGIN", "EXAMINE", "UID", "LOGOUT", "NOOP"}
)
ALLOWED_UID_COMMANDS = frozenset({"SEARCH", "FETCH"})

# FETCH data items that set \Seen: BODY[...] (non-PEEK), RFC822, RFC822.TEXT.
_SEEN_SETTING_FETCH = re.compile(r"BODY\[|RFC822(?!\.(?:SIZE|HEADER)\b)", re.IGNORECASE)
_CONTROL_BYTES = re.compile(rb"[\x00\r\n]")


class ForbiddenCommandError(imaplib.IMAP4.error):
    """A command outside the read-only allow-list was about to be sent."""


class CertificatePinError(ssl.SSLError):
    """The server certificate does not match tls_fingerprint_sha256."""


class StartTLSError(ConnectionError):
    """STARTTLS upgrade failed; connection closed without sending credentials."""


def build_ssl_context(account: Account) -> ssl.SSLContext:
    """Verified client context. With ca_file, ONLY that file is trusted."""
    ctx = ssl.create_default_context(cafile=account.ca_file)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # Defensive: create_default_context guarantees this; fail loudly if it ever doesn't.
    if ctx.verify_mode != ssl.CERT_REQUIRED or not ctx.check_hostname:
        raise RuntimeError("refusing an SSL context without certificate verification")
    return ctx


def _as_bytes(arg) -> bytes:
    return arg if isinstance(arg, bytes) else str(arg).encode("utf-8", "surrogateescape")


def check_command(name: str, args: tuple, *, encrypted: bool) -> None:
    """Raise unless `name args` is an allowed read-only command."""
    cmd = name.upper()
    if cmd not in ALLOWED_COMMANDS:
        raise ForbiddenCommandError(f"IMAP command {cmd} is not allowed (read-only server)")
    if cmd == "LOGIN" and not encrypted:
        raise ForbiddenCommandError("refusing to send LOGIN over an unencrypted connection")
    for arg in args:
        if arg is not None and _CONTROL_BYTES.search(_as_bytes(arg)):
            raise ForbiddenCommandError("NUL, CR and LF are not allowed in IMAP arguments")
    if cmd == "UID":
        sub = _as_bytes(args[0]).decode("ascii", "replace").upper() if args else ""
        if sub not in ALLOWED_UID_COMMANDS:
            raise ForbiddenCommandError(f"IMAP command UID {sub} is not allowed (read-only server)")
        if sub == "FETCH":
            items = b" ".join(_as_bytes(a) for a in args[1:] if a is not None).decode(
                "ascii", "replace"
            )
            if _SEEN_SETTING_FETCH.search(items):
                raise ForbiddenCommandError("FETCH must use BODY.PEEK (would set \\Seen)")


class _GuardMixin:
    """Shared by both client classes; must come first in the MRO."""

    _tls_name: str
    _fingerprint: str | None

    def _command(self, name, *args):  # imaplib's single send path
        check_command(name, args, encrypted=isinstance(self.sock, ssl.SSLSocket))
        return super()._command(name, *args)

    def _check_pin(self, tls_sock: ssl.SSLSocket) -> None:
        if not self._fingerprint:
            return
        der = tls_sock.getpeercert(binary_form=True) or b""
        if not hmac.compare_digest(hashlib.sha256(der).hexdigest(), self._fingerprint):
            raise CertificatePinError("server certificate does not match tls_fingerprint_sha256")


class GuardedIMAP4_SSL(_GuardMixin, imaplib.IMAP4_SSL):  # noqa: N801 -- mirrors imaplib
    """Implicit TLS (port 993)."""

    def __init__(self, host, port, *, ssl_context, timeout, tls_name, fingerprint=None):
        self._tls_name = tls_name
        self._fingerprint = fingerprint
        super().__init__(host, port, ssl_context=ssl_context, timeout=timeout)

    def _create_socket(self, timeout):
        sock = imaplib.IMAP4._create_socket(self, timeout)
        try:
            tls = self.ssl_context.wrap_socket(sock, server_hostname=self._tls_name)
        except BaseException:
            sock.close()
            raise
        try:
            self._check_pin(tls)
        except BaseException:
            tls.close()
            raise
        return tls


class GuardedIMAP4(_GuardMixin, imaplib.IMAP4):
    """Cleartext connect, then mandatory STARTTLS (port 143)."""

    def __init__(self, host, port, *, timeout, tls_name, fingerprint=None):
        self._tls_name = tls_name
        self._fingerprint = fingerprint
        super().__init__(host, port, timeout=timeout)

    def starttls(self, ssl_context=None):
        if ssl_context is None:  # never let imaplib build its unverified default
            raise ValueError("an explicit verified SSL context is required")
        # imaplib verifies against self.host; point it at the expected name for
        # the duration of the handshake only.
        connect_host, self.host = self.host, self._tls_name
        try:
            result = super().starttls(ssl_context)
        finally:
            self.host = connect_host
        if not getattr(self, "_tls_established", False) or not isinstance(self.sock, ssl.SSLSocket):
            raise StartTLSError("STARTTLS did not establish TLS")
        self._check_pin(self.sock)
        return result


def connect(account: Account, timeout: float) -> imaplib.IMAP4:
    """Open a verified, guarded connection (not yet logged in)."""
    ctx = build_ssl_context(account)
    tls_name = account.tls_server_name or account.host
    if account.security == "ssl":
        return GuardedIMAP4_SSL(
            account.host,
            account.port,
            ssl_context=ctx,
            timeout=timeout,
            tls_name=tls_name,
            fingerprint=account.tls_fingerprint_sha256,
        )
    client = GuardedIMAP4(
        account.host,
        account.port,
        timeout=timeout,
        tls_name=tls_name,
        fingerprint=account.tls_fingerprint_sha256,
    )
    try:
        client.starttls(ctx)
    except Exception as e:
        with contextlib.suppress(OSError):
            client.shutdown()
        if isinstance(e, ssl.SSLError):
            raise
        raise StartTLSError(f"STARTTLS failed: {type(e).__name__}") from e
    return client


class HardenedMailBox(BaseMailBox):
    """imap-tools mailbox on top of the guarded, verified client."""

    def __init__(self, account: Account, timeout: float):
        self._account = account
        self._timeout = timeout
        super().__init__()

    def _get_mailbox_client(self) -> imaplib.IMAP4:
        return connect(self._account, self._timeout)
