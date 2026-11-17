# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
"""Shared fixtures.

The environment has to be set before `app.database` is imported, because the
engine is built at import time from `DATABASE_URL`. Hence the assignments at
module scope rather than in a fixture — conftest is imported before any test
module, so this runs early enough.
"""
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="coverbound-tests-")

# A file-backed SQLite database rather than `:memory:`: the app opens its own
# connections through SessionLocal, and an in-memory database is per-connection.
os.environ.setdefault("DATABASE_URL", f"sqlite:///{_TMP}/test.db")

# Forced, not defaulted. TestClient speaks plain HTTP, so `Secure` cookies would
# be dropped and every authenticated test would fail in a confusing way.
os.environ["DEBUG"] = "true"
os.environ["SECRET_KEY"] = "test-secret-key-not-for-production"

# Never let a developer's real credentials leak into a test run: an unset
# GITHUB_TOKEN keeps `create_issue` offline, and no Google client keeps the
# OAuth routes returning 404 instead of trying to reach accounts.google.com.
for _var in ("GITHUB_TOKEN", "GOOGLE_CLIENT_ID", "GOOGLE_CLIENT_SECRET", "SOURCE_URL"):
    os.environ.pop(_var, None)

# Same reason: a stray real Pocket ID client in a developer's shell would make
# the ordinary suite reach out to it. The round trip is exercised separately,
# against a local stand-in, and only when asked for.
for _var in ("POCKETID_CLIENT_ID", "POCKETID_CLIENT_SECRET", "POCKETID_BASE_URL"):
    os.environ.pop(_var, None)

POCKETID_E2E = os.environ.get("POCKETID_E2E") == "1"
_MOCK_IDP = None
if POCKETID_E2E:
    # `app.pocketid_oauth` reads its configuration at import time and registers
    # the client immediately, so the stand-in has to be listening *before*
    # `app.main` is imported below. Started here, stopped by the session fixture
    # further down. The ordinary suite imports nothing and opens no socket.
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from pocketid_mock import MockIdP

    _MOCK_IDP = MockIdP(client_id="coverbound-test").start()
    os.environ["POCKETID_CLIENT_ID"] = _MOCK_IDP.client_id
    os.environ["POCKETID_BASE_URL"] = _MOCK_IDP.base_url
    # The mock's default redirect URI is the TestClient address, so the app has
    # to be told the same thing. Overriding a real PUBLIC_BASE_URL is deliberate:
    # the callback must match what the stand-in was configured with.
    os.environ["PUBLIC_BASE_URL"] = "http://testserver"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app import rate_limit  # noqa: E402
from app.database import Base, SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Book, Club, Member, User  # noqa: E402

SECRET = "test-account-secret"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    """Nothing here may reach the internet.

    Suggesting a book schedules a cover lookup as a background task, which
    TestClient runs inline — so without this the suite spends a 15s timeout per
    suggestion waiting on Open Library, and fails differently when offline.
    Any call that slips past the stubs raises instead of hanging.
    """
    from app import github_issues, open_library

    monkeypatch.setattr(open_library, "lookup_cover", lambda *a, **k: None)
    monkeypatch.setattr(open_library, "search", lambda *a, **k: ([], False))
    monkeypatch.setattr(open_library, "top_rated", lambda *a, **k: [])
    monkeypatch.setattr(github_issues, "create_issue", lambda *a, **k: None)

    def blocked(*args, **kwargs):
        raise AssertionError(
            "a test tried to make a real network call — stub it in conftest"
        )

    import requests
    monkeypatch.setattr(requests.Session, "request", blocked)
    monkeypatch.setattr(requests, "get", blocked)
    monkeypatch.setattr(requests, "post", blocked)


@pytest.fixture(scope="session", autouse=True)
def schema():
    """Build the schema once for the whole run.

    Dropping and recreating ~30 tables per test cost about 1.5s each in DDL
    alone — over two minutes across the suite. The schema is static, so it only
    needs building once; isolation comes from clearing the rows instead.
    """
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture(autouse=True)
def fresh_database(schema):
    """Empty every table before each test, so ordering can never matter.

    Reverse dependency order, so a child table is always cleared before the
    parent it points at.
    """
    with engine.begin() as connection:
        for table in reversed(Base.metadata.sorted_tables):
            connection.execute(table.delete())
    rate_limit.reset()
    yield


@pytest.fixture
def db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    """Anonymous client. Redirects are not followed — most assertions here are
    about *where* a route sends you, which following would hide."""
    return TestClient(app, follow_redirects=False)


@pytest.fixture(scope="session", autouse=True)
def stop_pocketid_mock():
    """Stop the stand-in IdP when the run ends.

    The mock is started at module scope (above) so it is listening before the
    app registers its OAuth client; stopping it at interpreter exit leaves a
    live server thread behind.
    """
    yield
    if _MOCK_IDP is not None:
        _MOCK_IDP.stop()


@pytest.fixture(autouse=True)
def pocketid_mock():
    """The stand-in IdP, back to its defaults before every test.

    Only the claims and the issued-code ledger need resetting — the app reads
    its provider configuration at import time, and a test that rewrites a claim
    would otherwise hand the next test a surprise.
    """
    if _MOCK_IDP is None:
        return None
    _MOCK_IDP.reset()
    return _MOCK_IDP


@pytest.fixture
def make_user(db):
    def _make(username, secret=SECRET, **kwargs):
        user = User(username=username, account_secret=secret, **kwargs)
        db.add(user)
        db.commit()
        db.refresh(user)
        return user
    return _make


@pytest.fixture
def login():
    """Return a TestClient authenticated as `user`."""
    def _login(user, secret=SECRET):
        c = TestClient(app, follow_redirects=False)
        response = c.post(
            "/auth/login",
            data={"username": user.username, "account_secret": secret},
        )
        assert response.status_code == 303, (
            f"login failed for {user.username}: {response.status_code}"
        )
        return c
    return _login


@pytest.fixture
def club_factory(db):
    def _make(name="Readers", code="CLUB0001", **kwargs):
        club = Club(name=name, code=code, **kwargs)
        db.add(club)
        db.commit()
        db.refresh(club)
        return club
    return _make


@pytest.fixture
def member_factory(db):
    def _make(club, user, display_name=None, is_admin=False):
        member = Member(
            club_id=club.id,
            user_id=user.id,
            display_name=display_name or user.username,
            is_admin=is_admin,
        )
        db.add(member)
        db.commit()
        db.refresh(member)
        return member
    return _make


@pytest.fixture
def book_factory(db):
    def _make(club, title="Dune", author="Herbert", status="suggested", **kwargs):
        book = Book(club_id=club.id, title=title, author=author, status=status, **kwargs)
        db.add(book)
        db.commit()
        db.refresh(book)
        return book
    return _make


@pytest.fixture
def null_weight(db):
    """Force a book's `weight` to NULL.

    Passing `weight=None` to the constructor is not enough — the column's
    Python-side default fills it back in. Rows written by a migration, the seed
    script or raw SQL genuinely are NULL.
    """
    def _null(book):
        db.query(Book).filter(Book.id == book.id).update({"weight": None})
        db.commit()
        db.refresh(book)
        return book
    return _null


@pytest.fixture
def world(db, make_user, club_factory, member_factory, book_factory, login):
    """One club with an admin, a plain member, an outsider, and two shortlisted
    books — the arrangement most tests here need.

    Exposed as a namespace so tests read `world.admin_client`, not `w[3]`.
    """
    class World:
        pass

    w = World()
    w.admin_user = make_user("admin")
    w.member_user = make_user("member")
    w.outsider_user = make_user("outsider")

    w.club = club_factory()
    w.admin = member_factory(w.club, w.admin_user, "Admin", is_admin=True)
    w.member = member_factory(w.club, w.member_user, "Member")

    # Both ordinary. An edge case belongs in the test that is about it, not
    # baked into the fixture every other test happens to inherit.
    w.book_a = book_factory(w.club, "Dune", "Herbert")
    w.book_b = book_factory(w.club, "Circe", "Miller")

    w.anon = TestClient(app, follow_redirects=False)
    w.admin_client = login(w.admin_user)
    w.member_client = login(w.member_user)
    w.outsider_client = login(w.outsider_user)
    return w
