"""Read-only IMAP helpers built on imap-tools.

Every fetch uses mark_seen=False, so imap-tools issues BODY.PEEK and reading a
message never sets the \\Seen flag in the real mailbox. INBOX is opened with
EXAMINE (read-only), and the transport (tls.py) refuses any command outside a
read-only allow-list, whatever this module asks for.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from html.parser import HTMLParser

from imap_tools import AND, OR

from .accounts import Account, settings
from .tls import HardenedMailBox

# Kept as a module attribute so tests can swap in a fake (no network).
MailBox = HardenedMailBox

MAX_LIMIT = 100  # rows per account per call
MAX_QUERY_CHARS = 256
SNIPPET_CHARS = 200
SNIPPET_MAX_BYTES = 256 * 1024  # don't download bigger messages just for a snippet
TRUNCATED_MARK = "\n[tronqué]"

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_UID_RE = re.compile(r"^[1-9][0-9]{0,9}$")


# --------------------------------------------------------------------------- inputs


def validate_query(query: str) -> str:
    """Free-text search term from the model: refuse control chars (CR/LF injection)."""
    if not isinstance(query, str) or not query.strip():
        raise ValueError("query must be a non-empty string")
    if len(query) > MAX_QUERY_CHARS:
        raise ValueError(f"query longer than {MAX_QUERY_CHARS} characters")
    if _CONTROL_CHARS.search(query):
        raise ValueError("query must not contain control characters")
    return query


def validate_uid(uid: str) -> str:
    """A single positive IMAP UID; sets/ranges like '1:*' or '1,2' are refused."""
    uid = str(uid).strip()
    if not _UID_RE.match(uid):
        raise ValueError("id must be a single positive integer UID")
    return uid


def clamp_limit(limit: int) -> int:
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
        raise ValueError("limit must be a positive integer")
    return min(limit, MAX_LIMIT)


# --------------------------------------------------------------------------- connection


@contextmanager
def open_box(account: Account) -> Iterator[HardenedMailBox]:
    """Yield a logged-in mailbox with INBOX opened read-only (EXAMINE)."""
    pw = account.password()
    if not pw:
        raise RuntimeError(f"no password for {account.key} (env {account.password_env} unset)")
    # Google shows app passwords with spaces for readability; IMAP wants them bare.
    if account.host.endswith("gmail.com"):
        pw = pw.replace(" ", "")
    box = MailBox(account, settings().timeout_seconds)
    try:
        box.login(account.email, pw, initial_folder=None)
        box.folder.set("INBOX", readonly=True)  # EXAMINE, never SELECT
        yield box
    finally:
        with suppress(Exception):
            box.logout()


# --------------------------------------------------------------------------- content


class _TextExtractor(HTMLParser):
    _SKIP = {"script", "style", "head", "title", "noscript", "template"}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag, attrs):
        if tag in self._SKIP:
            self._skip_depth += 1
        elif tag in ("br", "p", "div", "li", "tr", "h1", "h2", "h3", "h4", "h5", "h6"):
            self.parts.append("\n")

    def handle_endtag(self, tag):
        if tag in self._SKIP and self._skip_depth:
            self._skip_depth -= 1

    def handle_data(self, data):
        if not self._skip_depth:
            self.parts.append(data)


def html_to_text(html: str) -> str:
    """Plain text from HTML with the standard library only (no markup, no scripts)."""
    parser = _TextExtractor()
    with suppress(Exception):
        parser.feed(html)
        parser.close()
    text = "".join(parser.parts)
    text = re.sub(r"[ \t\r\f\v]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n\n", text).strip()


def _plain_body(msg) -> str:
    if (msg.text or "").strip():
        return msg.text.strip()
    if (msg.html or "").strip():
        return html_to_text(msg.html)
    return ""


def truncate(text: str, max_chars: int) -> tuple[str, bool]:
    if len(text) <= max_chars:
        return text, False
    return text[:max_chars] + TRUNCATED_MARK, True


def _snippet(msg, length: int = SNIPPET_CHARS) -> str:
    body = _plain_body(msg).replace("\r", " ").replace("\n", " ")
    return re.sub(r" {2,}", " ", body)[:length]


def _has_list_unsubscribe(msg) -> bool:
    return bool(msg.headers.get("list-unsubscribe"))


def row(msg, account_key: str, snippet: str | None = None) -> dict:
    """Compact metadata row for list/search results."""
    return {
        "account": account_key,
        "id": msg.uid,
        "from": msg.from_,
        "to": list(msg.to),
        "subject": msg.subject,
        "date": msg.date.isoformat() if msg.date else None,
        "unread": "\\Seen" not in msg.flags,
        "list_unsubscribe": _has_list_unsubscribe(msg),
        "snippet": _snippet(msg) if snippet is None else snippet,
        "untrusted_content": True,  # subject/snippet come from external senders
    }


def _criteria(query: str | None, since: dt.date | None, unread_only: bool):
    parts = []
    if query:
        parts.append(OR(from_=query, subject=query, text=query))
    if since:
        parts.append(AND(date_gte=since))
    if unread_only:
        parts.append(AND(seen=False))
    if not parts:
        return AND(all=True)
    return AND(*parts) if len(parts) > 1 else parts[0]


# --------------------------------------------------------------------------- fetches


def fetch_rows(
    account: Account,
    *,
    query: str | None = None,
    since: dt.date | None = None,
    unread_only: bool = False,
    limit: int = 25,
) -> list[dict]:
    if query is not None:
        query = validate_query(query)
    limit = clamp_limit(limit)
    crit = _criteria(query, since, unread_only)
    charset = "US-ASCII" if (query or "").isascii() else "UTF-8"
    with open_box(account) as box:
        # Pass 1: headers + size only (cheap; no attachments downloaded).
        heads = list(
            box.fetch(
                crit,
                charset=charset,
                limit=limit,
                reverse=True,  # newest first
                mark_seen=False,  # BODY.PEEK -- never touch \Seen
                bulk=True,
                headers_only=True,
            )
        )
        # Pass 2: full body only for reasonably small messages, for the snippet.
        small = [m.uid for m in heads if m.uid and 0 < (m.size_rfc822 or 0) <= SNIPPET_MAX_BYTES]
        snippets: dict[str, str] = {}
        if small:
            for m in box.fetch(uid_list=small, mark_seen=False, bulk=25):
                snippets[m.uid] = _snippet(m)
        return [row(m, account.key, snippets.get(m.uid, "")) for m in heads]


def fetch_one(account: Account, uid: str) -> dict | None:
    """Full message by UID (INBOX). Returns None if not found."""
    uid = validate_uid(uid)
    with open_box(account) as box:
        msgs = list(box.fetch(uid_list=[uid], mark_seen=False, bulk=False))
        if not msgs:
            return None
        m = msgs[0]
        body = _plain_body(m)
        body_out, truncated = truncate(body, settings().max_body_chars)
        return {
            "account": account.key,
            "id": m.uid,
            "from": m.from_,
            "to": list(m.to),
            "cc": list(m.cc),
            "subject": m.subject,
            "date": m.date.isoformat() if m.date else None,
            "unread": "\\Seen" not in m.flags,
            "message_id": m.headers.get("message-id", [None])[0],
            "list_unsubscribe": _has_list_unsubscribe(m),
            "body": body_out,
            "body_truncated": truncated,
            "body_chars": len(body),
            "untrusted_content": True,  # body/subject come from external senders
        }
