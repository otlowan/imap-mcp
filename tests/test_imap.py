import datetime as dt
from types import SimpleNamespace

import pytest

from imap_mcp import accounts, imap


class FakeFolder:
    def __init__(self, box):
        self.box = box

    def set(self, folder, readonly=False):
        self.box.folder_set = (folder, readonly)


class FakeMailBox:
    """Stands in for HardenedMailBox; records login/folder/fetch args, no network."""

    instances = []
    messages = []

    def __init__(self, account, timeout):
        self.host = account.host
        self.port = account.port
        self.timeout = timeout
        self.login_args = None
        self.folder_set = None
        self.fetch_kwargs = None
        self.fetch_calls = []
        self.logged_out = False
        self.folder = FakeFolder(self)
        FakeMailBox.instances.append(self)

    def login(self, email, password, initial_folder="INBOX"):
        self.login_args = (email, password, initial_folder)
        return self

    def fetch(self, criteria="ALL", **kwargs):
        self.fetch_criteria = criteria
        self.fetch_kwargs = kwargs
        self.fetch_calls.append(kwargs)
        return iter(FakeMailBox.messages)

    def logout(self):
        self.logged_out = True


@pytest.fixture(autouse=True)
def fake_mailbox(monkeypatch):
    FakeMailBox.instances = []
    FakeMailBox.messages = []
    monkeypatch.setattr(imap, "MailBox", FakeMailBox)


def fake_msg(**overrides):
    base = dict(
        uid="42",
        from_="sender@example.com",
        to=("rcpt@example.com",),
        cc=(),
        subject="Hello",
        date=dt.datetime(2026, 7, 30, 12, 0, tzinfo=dt.UTC),
        flags=("\\Seen",),
        text="line one\nline two",
        html="",
        headers={"message-id": ["<abc@example.com>"]},
        size_rfc822=1000,
    )
    base.update(overrides)
    return SimpleNamespace(**base)


def test_open_box_requires_password(config):
    alpha = accounts.get_account("alpha")
    with pytest.raises(RuntimeError, match="ALPHA_PW"), imap.open_box(alpha):
        pass


def test_open_box_logs_in_and_out(config, monkeypatch):
    monkeypatch.setenv("ALPHA_PW", "s3cret")
    with imap.open_box(accounts.get_account("alpha")) as box:
        assert box.login_args == ("alpha@example.com", "s3cret", None)
        assert box.folder_set == ("INBOX", True)  # EXAMINE (read-only), not SELECT
        assert (box.host, box.port) == ("imap.example.com", 1993)
        assert not box.logged_out
    assert box.logged_out


def test_open_box_strips_spaces_for_gmail_only(config, monkeypatch):
    monkeypatch.setenv("BETA_PW", "abcd efgh ijkl mnop")
    with imap.open_box(accounts.get_account("gmailish")) as box:
        assert box.login_args[1] == "abcdefghijklmnop"

    monkeypatch.setenv("ALPHA_PW", "pass with spaces")
    with imap.open_box(accounts.get_account("alpha")) as box:
        assert box.login_args[1] == "pass with spaces"


def test_snippet_collapses_newlines_and_truncates():
    msg = fake_msg(text="a\nb\nc" + "x" * 500)
    snip = imap._snippet(msg)
    assert snip.startswith("a b c")
    assert len(snip) == 200


def test_snippet_falls_back_to_html():
    msg = fake_msg(text="", html="<p>hi</p>")
    assert imap._snippet(msg) == "hi"  # HTML converted to plain text


def test_row_shape():
    msg = fake_msg(flags=())
    assert imap.row(msg, "alpha") == {
        "account": "alpha",
        "id": "42",
        "from": "sender@example.com",
        "to": ["rcpt@example.com"],
        "subject": "Hello",
        "date": "2026-07-30T12:00:00+00:00",
        "unread": True,
        "list_unsubscribe": False,
        "snippet": "line one line two",
        "untrusted_content": True,
    }


def test_row_seen_flag_means_read():
    assert imap.row(fake_msg(), "alpha")["unread"] is False


@pytest.mark.parametrize(
    "kwargs, expected",
    [
        (dict(query=None, since=None, unread_only=False), "(ALL)"),
        (dict(query=None, since=dt.date(2026, 7, 1), unread_only=False), "(SINCE 1-Jul-2026)"),
        (dict(query=None, since=None, unread_only=True), "(UNSEEN)"),
    ],
)
def test_criteria_simple(kwargs, expected):
    assert str(imap._criteria(**kwargs)) == expected


def test_criteria_query_matches_from_subject_body():
    crit = str(imap._criteria("invoice", None, False))
    for token in ("FROM", "SUBJECT", "TEXT", "invoice"):
        assert token in crit


def test_criteria_combines_with_and():
    crit = str(imap._criteria("invoice", dt.date(2026, 7, 1), True))
    for token in ("invoice", "SINCE 1-Jul-2026", "UNSEEN"):
        assert token in crit


def test_fetch_rows_never_marks_seen(config, monkeypatch):
    monkeypatch.setenv("ALPHA_PW", "pw")
    FakeMailBox.messages = [fake_msg()]
    rows = imap.fetch_rows(accounts.get_account("alpha"), limit=7)

    assert [r["id"] for r in rows] == ["42"]
    assert rows[0]["account"] == "alpha"
    calls = FakeMailBox.instances[-1].fetch_calls
    assert calls and all(c["mark_seen"] is False for c in calls)  # PEEK on every fetch
    assert calls[0]["reverse"] is True
    assert calls[0]["limit"] == 7


def test_fetch_one_full_message(config, monkeypatch):
    monkeypatch.setenv("ALPHA_PW", "pw")
    FakeMailBox.messages = [fake_msg()]
    msg = imap.fetch_one(accounts.get_account("alpha"), "42")

    assert msg == {
        "account": "alpha",
        "id": "42",
        "from": "sender@example.com",
        "to": ["rcpt@example.com"],
        "cc": [],
        "subject": "Hello",
        "date": "2026-07-30T12:00:00+00:00",
        "unread": False,
        "message_id": "<abc@example.com>",
        "list_unsubscribe": False,
        "body": "line one\nline two",
        "body_truncated": False,
        "body_chars": 17,
        "untrusted_content": True,
    }
    assert FakeMailBox.instances[-1].fetch_kwargs["mark_seen"] is False
    assert FakeMailBox.instances[-1].fetch_kwargs["uid_list"] == ["42"]


def test_fetch_one_not_found(config, monkeypatch):
    monkeypatch.setenv("ALPHA_PW", "pw")
    FakeMailBox.messages = []
    assert imap.fetch_one(accounts.get_account("alpha"), "42") is None
