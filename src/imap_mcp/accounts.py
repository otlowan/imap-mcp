"""Account registry. Loads non-secret config from accounts.toml; resolves each
account's password from the environment at runtime (export it, use direnv, a
secrets manager like 1Password's `op run`, whatever fits your setup).

Hardened fork: per-account TLS options (security, ca_file, tls_server_name,
tls_fingerprint_sha256) and global settings (max_body_chars, timeout_seconds).
Every option is optional; without them the behaviour is the original one,
except that TLS certificates are now always verified.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

# Config resolution order: $IMAP_MCP_ACCOUNTS if set, else accounts.toml at the
# project root (src/imap_mcp/accounts.py -> two parents up). When the package is
# installed (not editable), always set IMAP_MCP_ACCOUNTS.
DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "accounts.toml"

SECURITY_MODES = ("ssl", "starttls")
DEFAULT_PORTS = {"ssl": 993, "starttls": 143}

DEFAULT_MAX_BODY_CHARS = 20_000
DEFAULT_TIMEOUT_SECONDS = 30.0

_FINGERPRINT_RE = re.compile(r"^[0-9a-f]{64}$")


class ConfigError(ValueError):
    """Invalid accounts.toml content."""


def config_path() -> Path:
    override = os.environ.get("IMAP_MCP_ACCOUNTS")
    return Path(override) if override else DEFAULT_CONFIG_PATH


def normalize_fingerprint(value: str) -> str:
    """'AB:CD:…' / 'abcd…' -> 64 lowercase hex chars. Raises ConfigError."""
    fp = value.replace(":", "").replace(" ", "").lower()
    if not _FINGERPRINT_RE.match(fp):
        raise ConfigError("tls_fingerprint_sha256 must be 64 hex chars (colons allowed)")
    return fp


@dataclass(frozen=True)
class Settings:
    max_body_chars: int = DEFAULT_MAX_BODY_CHARS
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS


@dataclass(frozen=True)
class Account:
    key: str
    label: str
    email: str
    host: str
    port: int
    password_env: str
    enabled: bool
    security: str = "ssl"
    ca_file: str | None = None
    tls_server_name: str | None = None
    tls_fingerprint_sha256: str | None = None

    def password(self) -> str | None:
        """Password from the named env var, or None if unset/empty."""
        return os.environ.get(self.password_env) or None


def _parse_account(a: dict, base_dir: Path) -> Account:
    key = a["key"]
    security = str(a.get("security", "ssl")).lower()
    if security not in SECURITY_MODES:
        raise ConfigError(f"account {key!r}: security must be one of {SECURITY_MODES}")

    enabled = bool(a.get("enabled", True))
    ca_file = a.get("ca_file")
    if ca_file is not None:
        ca_path = Path(ca_file)
        if not ca_path.is_absolute():
            ca_path = base_dir / ca_path
        # Disabled accounts never connect; only enabled ones need the file now.
        if enabled and not ca_path.is_file():
            raise ConfigError(f"account {key!r}: ca_file not found: {ca_path}")
        ca_file = str(ca_path)

    server_name = a.get("tls_server_name")
    if server_name is not None and (not isinstance(server_name, str) or not server_name.strip()):
        raise ConfigError(f"account {key!r}: tls_server_name must be a non-empty string")

    fingerprint = a.get("tls_fingerprint_sha256")
    if fingerprint is not None:
        try:
            fingerprint = normalize_fingerprint(str(fingerprint))
        except ConfigError as e:
            raise ConfigError(f"account {key!r}: {e}") from None

    return Account(
        key=key,
        label=a.get("label", a["email"]),
        email=a["email"],
        host=a["host"],
        port=int(a.get("port", DEFAULT_PORTS[security])),
        password_env=a["password_env"],
        enabled=enabled,
        security=security,
        ca_file=ca_file,
        tls_server_name=server_name.strip() if server_name else None,
        tls_fingerprint_sha256=fingerprint,
    )


def _parse_settings(raw: dict) -> Settings:
    max_body = int(raw.get("max_body_chars", DEFAULT_MAX_BODY_CHARS))
    if max_body < 500:
        raise ConfigError("max_body_chars must be >= 500")
    timeout = float(raw.get("timeout_seconds", DEFAULT_TIMEOUT_SECONDS))
    if not 1 <= timeout <= 300:
        raise ConfigError("timeout_seconds must be between 1 and 300")
    return Settings(max_body_chars=max_body, timeout_seconds=timeout)


@lru_cache(maxsize=1)
def _load() -> tuple[dict[str, Account], Settings]:
    path = config_path()
    if not path.exists():
        raise FileNotFoundError(
            f"no account config at {path}; copy accounts.example.toml to "
            "accounts.toml and fill in your accounts (or point "
            "IMAP_MCP_ACCOUNTS at a config file)"
        )
    with path.open("rb") as fh:
        raw = tomllib.load(fh)
    out: dict[str, Account] = {}
    for a in raw.get("account", []):
        acct = _parse_account(a, path.parent)
        out[acct.key] = acct
    return out, _parse_settings(raw)


def settings() -> Settings:
    return _load()[1]


def all_accounts() -> list[Account]:
    return list(_load()[0].values())


def enabled_accounts() -> list[Account]:
    return [a for a in all_accounts() if a.enabled]


def get_account(key: str) -> Account:
    accts = _load()[0]
    if key not in accts:
        raise KeyError(f"unknown account {key!r}; known: {', '.join(accts)}")
    return accts[key]
