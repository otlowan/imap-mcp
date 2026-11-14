"""Tiny local IMAP server for tests (127.0.0.1 only, no real account involved).

Speaks just enough IMAP4rev1 for imaplib/imap-tools: CAPABILITY, STARTTLS, LOGIN,
EXAMINE/SELECT, UID SEARCH, UID FETCH, NOOP, LOGOUT. Every received line is
recorded so tests can assert what did (and did not) reach the wire.
"""

from __future__ import annotations

import contextlib
import datetime as dt
import hashlib
import ipaddress
import socket
import ssl
import threading
from dataclasses import dataclass, field
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

# ----------------------------------------------------------------------------- certs


@dataclass
class Cert:
    cert_path: Path
    key_path: Path
    der: bytes

    @property
    def fingerprint(self) -> str:
        return hashlib.sha256(self.der).hexdigest()


def make_cert(tmp: Path, name: str, *, ip: str | None = None, dns: str | None = None) -> Cert:
    """Self-signed CA:TRUE cert shaped like Proton Bridge's (no Subject Key Identifier)."""
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Test"),
            x509.NameAttribute(NameOID.COMMON_NAME, ip or dns or name),
        ]
    )
    sans: list[x509.GeneralName] = []
    if ip:
        sans.append(x509.IPAddress(ipaddress.ip_address(ip)))
    if dns:
        sans.append(x509.DNSName(dns))
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(
            x509.KeyUsage(True, False, True, False, False, True, False, False, False),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp / f"{name}.pem", tmp / f"{name}.key"
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return Cert(cert_path, key_path, cert.public_bytes(serialization.Encoding.DER))


# ----------------------------------------------------------------------------- server

MESSAGE = (
    b"From: Newsletter <news@example.com>\r\n"
    b"To: alpha@example.com\r\n"
    b"Subject: Weekly digest\r\n"
    b"Date: Fri, 13 Nov 2026 08:00:00 +0000\r\n"
    b"Message-ID: <digest@example.com>\r\n"
    b"List-Unsubscribe: <mailto:unsub@example.com>\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=utf-8\r\n"
    b"\r\n"
    b"Hello reader, this is the digest body.\r\n"
)


@dataclass
class FakeIMAPServer:
    cert: Cert
    mode: str = "ssl"  # "ssl" | "starttls"
    advertise_starttls: bool = True
    refuse_starttls: bool = False
    message: bytes = MESSAGE
    received: list[bytes] = field(default_factory=list)

    def __post_init__(self):
        self._ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._ctx.load_cert_chain(self.cert.cert_path, self.cert.key_path)
        self._sock = socket.socket()
        self._sock.bind(("127.0.0.1", 0))
        self._sock.listen(8)
        self.port = self._sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._accept_loop, daemon=True).start()

    # -- helpers for assertions
    def commands(self) -> list[str]:
        """Command verbs received (after the tag), e.g. ['CAPABILITY', 'LOGIN', ...]."""
        out = []
        for line in self.received:
            parts = line.split(b" ", 2)
            if len(parts) >= 2:
                verb = parts[1].decode("ascii", "replace").upper()
                if verb == "UID" and len(parts) == 3:
                    verb += " " + parts[2].split(b" ", 1)[0].decode("ascii", "replace").upper()
                out.append(verb)
        return out

    def close(self):
        self._stop = True
        self._sock.close()

    # -- protocol
    def _accept_loop(self):
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._session, args=(conn,), daemon=True).start()

    def _caps(self, tls: bool) -> bytes:
        caps = b"IMAP4rev1"
        if not tls and self.advertise_starttls:
            caps += b" STARTTLS"
        if tls:
            caps += b" AUTH=PLAIN"
        return caps

    def _session(self, conn: socket.socket):
        tls = False
        try:
            if self.mode == "ssl":
                conn = self._ctx.wrap_socket(conn, server_side=True)
                tls = True
            f = conn.makefile("rb")
            conn.sendall(b"* OK [CAPABILITY " + self._caps(tls) + b"] fake ready\r\n")
            while True:
                line = f.readline()
                if not line:
                    return
                self.received.append(line.rstrip(b"\r\n"))
                tag, _, rest = line.rstrip(b"\r\n").partition(b" ")
                verb, _, args = rest.partition(b" ")
                verb = verb.upper()
                if verb == b"CAPABILITY":
                    conn.sendall(
                        b"* CAPABILITY " + self._caps(tls) + b"\r\n" + tag + b" OK done\r\n"
                    )
                elif verb == b"STARTTLS":
                    if self.refuse_starttls:
                        conn.sendall(tag + b" NO STARTTLS unavailable\r\n")
                        continue
                    conn.sendall(tag + b" OK begin TLS\r\n")
                    conn = self._ctx.wrap_socket(conn, server_side=True)
                    f = conn.makefile("rb")
                    tls = True
                elif verb == b"LOGIN":
                    conn.sendall(tag + b" OK logged in\r\n")
                elif verb in (b"EXAMINE", b"SELECT"):
                    ro = b"READ-ONLY" if verb == b"EXAMINE" else b"READ-WRITE"
                    conn.sendall(
                        b"* 1 EXISTS\r\n* OK [UIDVALIDITY 1]\r\n"
                        + tag
                        + b" OK ["
                        + ro
                        + b"] done\r\n"
                    )
                elif verb == b"UID":
                    sub = args.split(b" ", 1)[0].upper()
                    if sub == b"SEARCH":
                        conn.sendall(b"* SEARCH 42\r\n" + tag + b" OK done\r\n")
                    elif sub == b"FETCH":
                        self._fetch(conn, tag, args)
                    else:
                        conn.sendall(tag + b" OK done\r\n")
                elif verb == b"LOGOUT":
                    conn.sendall(b"* BYE\r\n" + tag + b" OK done\r\n")
                    return
                else:
                    conn.sendall(tag + b" OK done\r\n")
        except (OSError, ssl.SSLError):
            return
        finally:
            with contextlib.suppress(OSError):
                conn.close()

    def _fetch(self, conn, tag, args: bytes):
        up = args.upper()
        if b"[HEADER]" in up:
            section, data = b"BODY[HEADER]", self.message.split(b"\r\n\r\n", 1)[0] + b"\r\n\r\n"
        else:
            section, data = b"BODY[]", self.message
        conn.sendall(
            b"* 1 FETCH (UID 42 FLAGS () RFC822.SIZE "
            + str(len(self.message)).encode()
            + b" "
            + section
            + b" {"
            + str(len(data)).encode()
            + b"}\r\n"
            + data
            + b")\r\n"
            + tag
            + b" OK done\r\n"
        )
