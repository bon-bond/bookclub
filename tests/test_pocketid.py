# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
"""Pocket ID sign-in, end to end, against the stand-in provider.

Run with ``POCKETID_E2E=1``. The mock IdP is started by ``conftest`` *before*
``app.main`` is imported, because ``app.pocketid_oauth`` reads its configuration
at import time. ``conftest.no_network`` blocks ``requests`` but leaves ``httpx``
alone, so the only host these tests contact is the mock on 127.0.0.1.

Each test drives the path a browser would: the app's ``/pocketid/login``
redirect, the provider's ``/authorize``, then the provider's redirect back to the
app's callback. Nothing here depends on the real provider — the mock decides
what it returns, including the failures.
"""
import base64
import hashlib
import os
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from app.database import SessionLocal
from app.models import User

pytestmark = pytest.mark.skipif(
    os.environ.get("POCKETID_E2E") != "1",
    reason="starts a stand-in IdP; run with POCKETID_E2E=1",
)

LOGIN = "/auth/pocketid/login"
CALLBACK = "/auth/pocketid/callback"
FINISH = "/auth/pocketid/finish"


def _consent(client, pocketid_mock, login_params=None):
    """Start the flow and consent at the provider.

    Returns the redirect the provider sends back to the app — which a browser
    would follow, and which is absolute, so the caller re-enters through the
    app's own client rather than the mock's host.
    """
    response = client.get(LOGIN, params=login_params or {})
    assert response.status_code in (302, 307), response.text
    location = response.headers["location"]
    assert location.startswith(pocketid_mock.base_url), location

    consent = httpx.get(location, follow_redirects=False)
    assert consent.status_code == 302, consent.text
    return consent.headers["location"]


def _round_trip(client, pocketid_mock, login_params=None):
    """The whole browser half of the flow, landing on the app's callback."""
    target = _consent(client, pocketid_mock, login_params)
    parts = urlparse(target)
    return client.get(parts.path, params=parse_qs(parts.query))


def _pick_username(client, username="reader1", expect=303):
    response = client.post(FINISH, data={"username": username})
    assert response.status_code == expect, response.text
    return response


# -- the happy path -------------------------------------------------------


def test_login_redirect_carries_state_and_a_pkce_challenge(client, pocketid_mock):
    response = client.get(LOGIN)
    assert response.status_code in (302, 307)

    query = parse_qs(urlparse(response.headers["location"]).query)
    assert query["client_id"] == [pocketid_mock.client_id]
    assert query["response_type"] == ["code"]
    assert query["redirect_uri"] == ["http://testserver" + CALLBACK]
    assert query["code_challenge_method"] == ["S256"]
    # 32 bytes, base64url, unpadded — the shape RFC 7636 asks for.
    assert len(query["code_challenge"][0]) == 43
    assert query["state"]


def test_the_verifier_presented_at_the_token_endpoint_solves_the_challenge(
    client, pocketid_mock
):
    _round_trip(client, pocketid_mock)

    authorize = pocketid_mock.authorize_requests[-1]
    token = pocketid_mock.token_requests[-1]
    digest = hashlib.sha256(token["code_verifier"].encode()).digest()
    assert base64.urlsafe_b64encode(digest).decode().rstrip("=") == authorize[
        "code_challenge"
    ][0]
    assert token["grant_type"] == "authorization_code"
    assert token["redirect_uri"] == "http://testserver" + CALLBACK


def test_a_first_sign_in_collects_a_username_then_creates_the_account(
    client, pocketid_mock
):
    response = _round_trip(client, pocketid_mock)
    assert response.status_code == 303
    assert response.headers["location"] == FINISH

    form = client.get(FINISH)
    assert form.status_code == 200
    # Prefilled from the provider's `preferred_username`, not invented.
    assert "reader1" in form.text
    assert "reader@example.com" in form.text

    done = _pick_username(client, "reader1")
    assert done.headers["location"] == "/"

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "reader1").one()
        assert user.pocketid_sub == "pid-0001"
        assert user.account_secret is None  # Pocket ID is this account's only credential
        assert user.email == "reader@example.com"
        assert user.email_verified is True
        assert user.display_name == "Reader One"
    finally:
        db.close()


def test_a_returning_user_signs_in_without_picking_a_username_again(
    client, pocketid_mock
):
    _round_trip(client, pocketid_mock)
    _pick_username(client, "reader1")
    client.post("/auth/logout")

    response = _round_trip(client, pocketid_mock)
    assert response.status_code == 303
    assert response.headers["location"] == "/"

    # No second account, and nothing left pending — the picker is not shown.
    db = SessionLocal()
    try:
        assert db.query(User).count() == 1
    finally:
        db.close()
    assert client.get(FINISH).status_code == 303


def test_an_unverified_email_is_not_stored_as_a_contact_address(
    client, pocketid_mock
):
    pocketid_mock.claims["email_verified"] = False
    _round_trip(client, pocketid_mock)
    _pick_username(client, "reader1")

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "reader1").one()
        assert user.email is None
        assert user.email_verified is False
    finally:
        db.close()


def test_the_provider_username_is_sanitised_before_it_reaches_the_form(
    client, pocketid_mock
):
    pocketid_mock.claims["preferred_username"] = "Ann O'Brien-Smith!"
    _round_trip(client, pocketid_mock)

    form = client.get(FINISH)
    assert form.status_code == 200
    assert "AnnOBrienSmith" in form.text
    # Nothing unescaped leaks into the page.
    assert "O'Brien" not in form.text


# -- where you end up -----------------------------------------------------


def test_a_same_site_next_is_honoured(client, pocketid_mock):
    response = _round_trip(client, pocketid_mock, {"next": "/clubs"})
    assert response.headers["location"] == FINISH
    assert _pick_username(client, "reader1").headers["location"] == "/clubs"


def test_an_off_site_next_is_dropped(client, pocketid_mock):
    _round_trip(client, pocketid_mock, {"next": "https://evil.example/steal"})
    assert _pick_username(client, "reader1").headers["location"] == "/"


def test_a_protocol_relative_next_is_dropped(client, pocketid_mock):
    _round_trip(client, pocketid_mock, {"next": "//evil.example/"})
    assert _pick_username(client, "reader1").headers["location"] == "/"


# -- the picker's own validation -----------------------------------------


def test_the_picker_rejects_a_username_that_is_too_short(client, pocketid_mock):
    _round_trip(client, pocketid_mock)
    response = client.post(FINISH, data={"username": "ab"})
    assert response.status_code == 400
    assert "3–30 characters" in response.text


def test_the_picker_rejects_a_taken_username(client, pocketid_mock, make_user):
    make_user("reader1")
    _round_trip(client, pocketid_mock)

    response = client.post(FINISH, data={"username": "reader1"})
    assert response.status_code == 400
    assert "already taken" in response.text


def test_the_picker_warns_when_the_address_belongs_to_an_existing_account(
    client, pocketid_mock, make_user
):
    # A reader who already has a password account but signed in with the
    # provider must be pointed at it, not silently given a second one.
    make_user("oldreader", email="reader@example.com")
    _round_trip(client, pocketid_mock)

    form = client.get(FINISH)
    assert form.status_code == 200
    assert "oldreader" in form.text
    assert "connect Pocket ID from settings instead" in form.text


def test_the_picker_is_not_reachable_without_a_pending_provider(
    client, pocketid_mock
):
    assert client.get(FINISH).status_code == 303
    assert client.post(FINISH, data={"username": "reader1"}).status_code == 303


# -- failures the provider can cause -------------------------------------


def test_a_state_that_does_not_match_the_session_is_rejected(client, pocketid_mock):
    client.get(LOGIN)
    response = client.get(
        CALLBACK, params={"code": "mock-code", "state": "not-the-sessions-state"}
    )
    assert response.status_code == 400
    assert "Pocket ID sign-in failed" in response.text


def test_a_callback_without_a_session_is_rejected(client, pocketid_mock):
    response = client.get(CALLBACK, params={"code": "mock-code", "state": "x"})
    assert response.status_code == 400


def test_a_token_endpoint_failure_is_surfaced_rather_than_swallowed(
    client, pocketid_mock
):
    pocketid_mock.token_fault = "reject_grant"
    response = _round_trip(client, pocketid_mock)
    assert response.status_code == 400
    assert "invalid_grant" in response.text


def test_a_code_that_was_already_spent_is_refused(client, pocketid_mock):
    # The provider retires a code as soon as it is redeemed, so replaying the
    # redirect from the first login cannot mint a second session.
    target = _consent(client, pocketid_mock)
    parts = urlparse(target)

    first = client.get(parts.path, params=parse_qs(parts.query))
    assert first.status_code == 303
    assert len(pocketid_mock.token_requests) == 1

    replay = client.get(parts.path, params=parse_qs(parts.query))
    assert replay.status_code == 400
    assert len(pocketid_mock.token_requests) == 1


def test_a_provider_response_without_an_account_identifier_is_rejected(
    client, pocketid_mock
):
    pocketid_mock.claims["sub"] = ""
    response = _round_trip(client, pocketid_mock)
    assert response.status_code == 400
    assert "account identifier" in response.text


# -- linking an existing account -----------------------------------------


def test_an_existing_account_can_be_linked_to_a_provider(client, pocketid_mock, make_user, login):
    user = make_user("sam")
    authed = login(user)

    started = authed.post("/auth/pocketid/link")
    assert started.status_code in (302, 307)
    assert started.headers["location"].startswith(pocketid_mock.base_url)

    target = urlparse(started.headers["location"])
    consent = httpx.get(started.headers["location"], follow_redirects=False)
    assert consent.status_code == 302, consent.text
    back = urlparse(consent.headers["location"])
    finished = authed.get(back.path, params=parse_qs(back.query))

    assert finished.status_code == 303
    assert finished.headers["location"] == "/profile/settings"

    db = SessionLocal()
    try:
        linked = db.query(User).filter(User.id == user.id).one()
        assert linked.pocketid_sub == "pid-0001"
        assert linked.email == "reader@example.com"
        # Linking is an addition, not a replacement — the password still works.
        assert linked.account_secret == "test-account-secret"
    finally:
        db.close()


def test_one_provider_account_cannot_be_linked_twice(client, pocketid_mock, make_user, login):
    first = login(make_user("sam"))
    consent = first.post("/auth/pocketid/link")
    target = urlparse(consent.headers["location"])
    back = urlparse(
        httpx.get(consent.headers["location"], follow_redirects=False).headers["location"]
    )
    assert first.get(back.path, params=parse_qs(back.query)).status_code == 303

    second = login(make_user("lee"))
    consent = second.post("/auth/pocketid/link")
    back = urlparse(
        httpx.get(consent.headers["location"], follow_redirects=False).headers["location"]
    )
    refused = second.get(back.path, params=parse_qs(back.query))
    assert refused.status_code == 400
    assert "already connected" in refused.text


def test_unlinking_a_provider_only_account_issues_a_password(client, pocketid_mock):
    # Sign in through the provider, not a password — there isn't one yet.
    _round_trip(client, pocketid_mock)
    assert _pick_username(client, "pocketonly").status_code == 303

    db = SessionLocal()
    try:
        signed = db.query(User).filter(User.username == "pocketonly").one()
        assert signed.pocketid_sub == "pid-0001"
        assert signed.account_secret is None
    finally:
        db.close()

    response = client.post("/auth/pocketid/unlink")
    assert response.status_code == 303

    db = SessionLocal()
    try:
        after = db.query(User).filter(User.username == "pocketonly").one()
        assert after.pocketid_sub is None
        assert after.email is None
        assert after.email_verified is False
        # A credential-less account cannot be left lockable-out, so one is made.
        assert after.account_secret
    finally:
        db.close()


def test_unlinking_is_refused_for_an_account_that_never_had_a_provider(
    make_user, login
):
    authed = login(make_user("sam"))
    assert authed.post("/auth/pocketid/unlink").status_code == 303

    db = SessionLocal()
    try:
        user = db.query(User).filter(User.username == "sam").one()
        assert user.pocketid_sub is None
    finally:
        db.close()
