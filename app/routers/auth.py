# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
import hmac
import logging
import re
import secrets

from authlib.integrations.starlette_client import OAuthError
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..dependencies import (
    LEGACY_COOKIE_NAME,
    get_current_user,
    login_user,
    logout_user,
    require_current_user,
)
from ..google_oauth import google_enabled, oauth, redirect_uri, safe_next
from ..pocketid_oauth import pocketid_enabled, pocketid_redirect_uri
from ..models import User
from ..templating import templates, base_context

router = APIRouter()

logger = logging.getLogger(__name__)

USERNAME_RE = re.compile(r'^[a-zA-Z0-9_]{3,30}$')


@router.get("/register", response_class=HTMLResponse)
async def register_form(request: Request, db: Session = Depends(get_db)):
    """Show the registration form."""
    current_user = get_current_user(request, db)
    if current_user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request,
        "auth/register.html",
        {**base_context(request, db, None), "title": "Register"}
    )


@router.post("/register")
async def register(
    request: Request,
    username: str = Form(...),
    display_name: str = Form(""),
    db: Session = Depends(get_db)
):
    """Create a new user account."""
    # Validate username format
    if not USERNAME_RE.match(username):
        return templates.TemplateResponse(
            request,
            "auth/register.html",
            {
                **base_context(request, db, None),
                "title": "Register",
                "error": "Username must be 3–30 characters: letters, numbers, and underscores only.",
                "username": username,
                "display_name": display_name,
            },
            status_code=400,
        )

    # Check uniqueness
    existing = db.query(User).filter(User.username == username).first()
    if existing:
        return templates.TemplateResponse(
            request,
            "auth/register.html",
            {
                **base_context(request, db, None),
                "title": "Register",
                "error": "That username is already taken. Please choose another.",
                "username": username,
                "display_name": display_name,
            },
            status_code=400,
        )

    # Create the user
    account_secret = secrets.token_urlsafe(36)
    user = User(
        username=username,
        account_secret=account_secret,
        display_name=display_name.strip() or None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    # login_user clears the session, so authenticate first and only then stash
    # the one-time secret — otherwise it would be wiped before it is shown.
    login_user(request, user)
    request.session['new_account_secret'] = account_secret
    request.session['new_account_username'] = user.username

    return RedirectResponse(url="/auth/register/success", status_code=303)


@router.get("/register/success", response_class=HTMLResponse)
async def register_success(request: Request, db: Session = Depends(get_db)):
    """Show the account secret one time after registration."""
    secret = request.session.pop('new_account_secret', None)
    username = request.session.pop('new_account_username', None)
    heading = request.session.pop('new_account_heading', None)
    current_user = get_current_user(request, db)

    if not secret:
        return RedirectResponse(url="/", status_code=303)

    return templates.TemplateResponse(
        request,
        "auth/register_success.html",
        {
            **base_context(request, db, current_user),
            "title": "Save Your Account Secret",
            "username": username,
            "account_secret": secret,
            "heading": heading,
        }
    )


@router.get("/login", response_class=HTMLResponse)
async def login_form(request: Request, db: Session = Depends(get_db)):
    """Show the login form."""
    current_user = get_current_user(request, db)
    if current_user:
        return RedirectResponse(url="/", status_code=303)
    return templates.TemplateResponse(
        request,
        "auth/login.html",
        {**base_context(request, db, None), "title": "Login"}
    )


def _external_signin_name(user) -> str:
    """Which provider an account that has no account secret signs in with.

    Only used for the login error message, so it can name the provider instead
    of leaving the user to guess why their secret is rejected.
    """
    if user is None:
        return ""
    if getattr(user, "google_sub", None):
        return "Google"
    if getattr(user, "pocketid_sub", None):
        return "Pocket ID"
    return "an external provider"


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    account_secret: str = Form(...),
    db: Session = Depends(get_db)
):
    """Validate account secret and set session cookie."""
    user = db.query(User).filter(User.username == username).first()

    # Use constant-time comparison to prevent timing attacks.
    # `account_secret` is None for accounts created through Google sign-in that
    # never set one — those can only be reached via Google, so no secret matches.
    secret_matches = (
        user is not None
        and user.account_secret
        and hmac.compare_digest(user.account_secret, account_secret)
    )

    if not secret_matches:
        return templates.TemplateResponse(
            request,
            "auth/login.html",
            {
                **base_context(request, db, None),
                "title": "Login",
                "error": (
                    f"This account signs in with {_external_signin_name(user)}."
                    if user is not None and not user.account_secret
                    else "Invalid username or account secret."
                ),
                "username": username,
            },
            status_code=401,
        )

    login_user(request, user)
    return RedirectResponse(url="/", status_code=303)


@router.post("/logout")
async def logout(request: Request):
    """Clear the signed session, and any leftover legacy identity cookie."""
    logout_user(request)
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(LEGACY_COOKIE_NAME)
    return response


# ---------------------------------------------------------------------------
# Google sign-in
# ---------------------------------------------------------------------------

def _require_google_configured():
    """Google routes 404 rather than 500 when the deployment has no credentials."""
    if not google_enabled():
        raise HTTPException(status_code=404, detail="Google sign-in is not configured")


def _suggest_username(claims: dict, db: Session) -> str:
    """A free username derived from the Google account, for the picker to prefill."""
    raw = (claims.get("email") or "").split("@")[0] or (claims.get("given_name") or "reader")
    base = re.sub(r"[^a-zA-Z0-9_]", "", raw)[:30] or "reader"
    # The field demands at least 3 characters; pad a very short local part.
    while len(base) < 3:
        base += "0"
    candidate, n = base, 1
    while db.query(User).filter(User.username == candidate).first():
        suffix = str(n)
        candidate = base[:30 - len(suffix)] + suffix
        n += 1
    return candidate


@router.get("/google/login")
async def google_login(request: Request, next: str = "/"):
    """Kick off the OAuth dance for signing in."""
    _require_google_configured()
    request.session["oauth_intent"] = "login"
    request.session["oauth_next"] = safe_next(next)
    return await oauth.google.authorize_redirect(request, redirect_uri(request))


@router.post("/google/link")
async def google_link_start(request: Request, db: Session = Depends(get_db)):
    """Begin attaching a Google identity to the account already signed in."""
    _require_google_configured()
    user = require_current_user(request, db)
    request.session["oauth_intent"] = "link"
    request.session["oauth_link_uid"] = user.id
    request.session["oauth_next"] = "/profile/settings"
    return await oauth.google.authorize_redirect(request, redirect_uri(request))


@router.get("/google/callback", name="google_callback")
async def google_callback(request: Request, db: Session = Depends(get_db)):
    """Where Google sends the user back. Resolves the identity to an account."""
    _require_google_configured()

    intent = request.session.pop("oauth_intent", "login")
    link_uid = request.session.pop("oauth_link_uid", None)
    destination = safe_next(request.session.pop("oauth_next", None))

    try:
        # Verifies `state`, exchanges the code, and validates the ID token's
        # signature and `nonce` against Google's published keys.
        token = await oauth.google.authorize_access_token(request)
    except OAuthError as exc:
        # The user-facing page shows only `exc.error`; the description and the
        # session state are what actually identify a misconfigured redirect URI
        # or a session cookie that never made it back, so log them server-side.
        logger.warning(
            "Google callback rejected: error=%s description=%s host=%s "
            "redirect_uri=%s session_keys=%s",
            exc.error,
            getattr(exc, "description", None),
            request.headers.get("host"),
            redirect_uri(request),
            sorted(request.session.keys()),
        )
        return _google_error(request, db, f"Google sign-in failed: {exc.error}")

    claims = token.get("userinfo") or {}
    sub = claims.get("sub")
    if not sub:
        return _google_error(request, db, "Google did not return an account identifier.")

    # Only trust the address if Google says it verified it; an unverified one
    # proves nothing about who controls the mailbox.
    verified = bool(claims.get("email_verified"))
    email = claims.get("email") if verified else None

    existing = db.query(User).filter(User.google_sub == sub).first()

    if intent == "link":
        user = db.query(User).filter(User.id == link_uid).first() if link_uid else None
        if not user:
            return _google_error(request, db, "Your session expired before linking finished.")
        if existing and existing.id != user.id:
            return _google_error(
                request, db,
                f"That Google account is already connected to “{existing.username}”."
            )
        user.google_sub = sub
        user.email = email
        user.email_verified = verified
        user.avatar_url = claims.get("picture")
        db.commit()
        return RedirectResponse(url=destination or "/profile/settings", status_code=303)

    if existing:
        existing.email = email
        existing.email_verified = verified
        existing.avatar_url = claims.get("picture")
        db.commit()
        login_user(request, existing)
        return RedirectResponse(url=destination, status_code=303)

    # No account yet. Usernames here are public and permanent, so the person
    # picks their own rather than inheriting whatever Google's address implies.
    request.session["pending_google"] = {
        "sub": sub,
        "email": email,
        "email_verified": verified,
        "name": claims.get("name"),
        "picture": claims.get("picture"),
        "next": destination,
    }
    return RedirectResponse(url="/auth/google/finish", status_code=303)


def _google_error(request: Request, db: Session, message: str):
    """Send the user back to the login screen with an explanation."""
    return templates.TemplateResponse(
        request,
        "auth/login.html",
        {
            **base_context(request, db, get_current_user(request, db)),
            "title": "Login",
            "error": message,
        },
        status_code=400,
    )


@router.get("/google/finish", response_class=HTMLResponse)
async def google_finish_form(request: Request, db: Session = Depends(get_db)):
    """Ask a first-time Google visitor to choose their username."""
    _require_google_configured()
    pending = request.session.get("pending_google")
    if not pending:
        return RedirectResponse(url="/auth/login", status_code=303)

    # If an account already holds this address, say so — signing in with Google
    # would otherwise quietly create a second, empty account alongside it.
    duplicate = None
    if pending.get("email"):
        duplicate = db.query(User).filter(
            User.email == pending["email"], User.google_sub.is_(None)
        ).first()

    return templates.TemplateResponse(
        request,
        "auth/google_finish.html",
        {
            **base_context(request, db, None),
            "title": "Choose a username",
            "google_email": pending.get("email"),
            "google_name": pending.get("name"),
            "suggested": _suggest_username(pending, db),
            "duplicate_username": duplicate.username if duplicate else None,
        },
    )


@router.post("/google/finish")
async def google_finish(
    request: Request,
    username: str = Form(...),
    db: Session = Depends(get_db),
):
    """Create the account behind a first-time Google sign-in."""
    _require_google_configured()
    pending = request.session.get("pending_google")
    if not pending:
        return RedirectResponse(url="/auth/login", status_code=303)

    def again(error: str, status: int = 400):
        return templates.TemplateResponse(
            request,
            "auth/google_finish.html",
            {
                **base_context(request, db, None),
                "title": "Choose a username",
                "google_email": pending.get("email"),
                "google_name": pending.get("name"),
                "suggested": username,
                "error": error,
            },
            status_code=status,
        )

    username = username.strip()
    if not USERNAME_RE.match(username):
        return again("Username must be 3–30 characters: letters, numbers, and underscores only.")
    if db.query(User).filter(User.username == username).first():
        return again("That username is already taken. Please choose another.")

    # Re-check the subject: a second tab could have completed the same sign-in
    # while this one sat on the form.
    if db.query(User).filter(User.google_sub == pending["sub"]).first():
        return again("That Google account has already been used to sign up.", status=409)

    user = User(
        username=username,
        account_secret=None,  # Google is this account's only credential.
        google_sub=pending["sub"],
        email=pending.get("email"),
        email_verified=bool(pending.get("email_verified")),
        avatar_url=pending.get("picture"),
        display_name=(pending.get("name") or "").strip() or None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    destination = safe_next(pending.get("next"))
    login_user(request, user)  # clears the session, dropping `pending_google`
    return RedirectResponse(url=destination, status_code=303)


@router.post("/google/unlink")
async def google_unlink(request: Request, db: Session = Depends(get_db)):
    """Detach the Google identity from the signed-in account."""
    user = require_current_user(request, db)
    if not user.google_sub:
        return RedirectResponse(url="/profile/settings", status_code=303)

    user.google_sub = None
    user.email = None
    user.email_verified = False
    user.avatar_url = None

    if user.account_secret:
        db.commit()
        return RedirectResponse(url="/profile/settings", status_code=303)

    # Google was the account's only credential. Disconnecting without issuing a
    # replacement would lock the owner out of their own clubs, so mint a secret
    # and show it once — the same one-time reveal registration uses.
    secret = secrets.token_urlsafe(36)
    user.account_secret = secret
    db.commit()

    request.session['new_account_secret'] = secret
    request.session['new_account_username'] = user.username
    request.session['new_account_heading'] = "Google disconnected"
    return RedirectResponse(url="/auth/register/success", status_code=303)


# ---------------------------------------------------------------------------
# Pocket ID sign-in
# ---------------------------------------------------------------------------

def _require_pocketid_configured():
    if not pocketid_enabled():
        raise HTTPException(status_code=404, detail="Pocket ID sign-in is not configured")


def _suggest_pocketid_username(claims: dict, db: Session) -> str:
    """A free username derived from the Pocket ID account, for the picker to prefill."""
    raw = (claims.get("preferred_username") or claims.get("name") or "").strip()
    base = re.sub(r"[^a-zA-Z0-9_]", "", raw)[:30]
    if not base:
        base = re.sub(r"[^a-zA-Z0-9_]", "", (claims.get("email") or "").split("@")[0])[:30]
    base = base or "reader"
    while len(base) < 3:
        base += "0"
    candidate, n = base, 1
    while db.query(User).filter(User.username == candidate).first():
        suffix = str(n)
        candidate = base[:30 - len(suffix)] + suffix
        n += 1
    return candidate


@router.get("/pocketid/login")
async def pocketid_login(request: Request, next: str = "/"):
    _require_pocketid_configured()
    request.session["pocketid_intent"] = "login"
    request.session["pocketid_next"] = safe_next(next)
    return await oauth.pocketid.authorize_redirect(request, pocketid_redirect_uri(request))


@router.post("/pocketid/link")
async def pocketid_link_start(request: Request, db: Session = Depends(get_db)):
    _require_pocketid_configured()
    user = require_current_user(request, db)
    request.session["pocketid_intent"] = "link"
    request.session["pocketid_link_uid"] = user.id
    request.session["pocketid_next"] = "/profile/settings"
    return await oauth.pocketid.authorize_redirect(request, pocketid_redirect_uri(request))


@router.get("/pocketid/callback", name="pocketid_callback")
async def pocketid_callback(request: Request, db: Session = Depends(get_db)):
    _require_pocketid_configured()

    intent = request.session.pop("pocketid_intent", "login")
    link_uid = request.session.pop("pocketid_link_uid", None)
    destination = safe_next(request.session.pop("pocketid_next", None))

    try:
        token = await oauth.pocketid.authorize_access_token(request)
    except OAuthError as exc:
        logger.warning(
            "Pocket ID callback rejected: error=%s description=%s host=%s "
            "redirect_uri=%s session_keys=%s",
            exc.error, getattr(exc, "description", None), request.headers.get("host"),
            pocketid_redirect_uri(request), sorted(request.session.keys()),
        )
        return _pocketid_error(request, db, f"Pocket ID sign-in failed: {exc.error}")

    claims = token.get("userinfo") or {}
    sub = claims.get("sub")
    if not sub:
        return _pocketid_error(request, db, "Pocket ID did not return an account identifier.")

    verified = bool(claims.get("email_verified"))
    email = claims.get("email") if verified else None
    name = (claims.get("name") or claims.get("preferred_username") or "").strip() or None

    existing = db.query(User).filter(User.pocketid_sub == sub).first()

    if intent == "link":
        user = db.query(User).filter(User.id == link_uid).first() if link_uid else None
        if not user:
            return _pocketid_error(request, db, "Your session expired before linking finished.")
        if existing and existing.id != user.id:
            return _pocketid_error(
                request, db,
                f"That Pocket ID account is already connected to “{existing.username}”."
            )
        user.pocketid_sub = sub
        user.email = email
        user.email_verified = verified
        user.avatar_url = claims.get("picture")
        if name and not user.display_name:
            user.display_name = name
        db.commit()
        return RedirectResponse(url=destination or "/profile/settings", status_code=303)

    if existing:
        existing.email = email
        existing.email_verified = verified
        existing.avatar_url = claims.get("picture")
        db.commit()
        login_user(request, existing)
        return RedirectResponse(url=destination, status_code=303)

    request.session["pending_pocketid"] = {
        "sub": sub,
        "email": email,
        "email_verified": verified,
        "name": name,
        "preferred_username": claims.get("preferred_username"),
        "picture": claims.get("picture"),
        "next": destination,
    }
    return RedirectResponse(url="/auth/pocketid/finish", status_code=303)


def _pocketid_error(request: Request, db: Session, message: str):
    return templates.TemplateResponse(
        request, "auth/login.html",
        {
            **base_context(request, db, get_current_user(request, db)),
            "title": "Login",
            "error": message,
        },
        status_code=400,
    )


@router.get("/pocketid/finish", response_class=HTMLResponse)
async def pocketid_finish_form(request: Request, db: Session = Depends(get_db)):
    _require_pocketid_configured()
    pending = request.session.get("pending_pocketid")
    if not pending:
        return RedirectResponse(url="/auth/login", status_code=303)

    duplicate = None
    if pending.get("email"):
        duplicate = db.query(User).filter(
            User.email == pending["email"], User.pocketid_sub.is_(None)
        ).first()

    return templates.TemplateResponse(
        request, "auth/pocketid_finish.html",
        {
            **base_context(request, db, None),
            "title": "Choose a username",
            "pocketid_email": pending.get("email"),
            "pocketid_name": pending.get("name"),
            "suggested": _suggest_pocketid_username(pending, db),
            "duplicate_username": duplicate.username if duplicate else None,
        },
    )


@router.post("/pocketid/finish")
async def pocketid_finish(
    request: Request,
    username: str = Form(...),
    db: Session = Depends(get_db),
):
    _require_pocketid_configured()
    pending = request.session.get("pending_pocketid")
    if not pending:
        return RedirectResponse(url="/auth/login", status_code=303)

    def again(error: str, status: int = 400):
        return templates.TemplateResponse(
            request, "auth/pocketid_finish.html",
            {
                **base_context(request, db, None),
                "title": "Choose a username",
                "pocketid_email": pending.get("email"),
                "pocketid_name": pending.get("name"),
                "suggested": username,
                "error": error,
            },
            status_code=status,
        )

    username = username.strip()
    if not USERNAME_RE.match(username):
        return again("Username must be 3–30 characters: letters, numbers, and underscores only.")
    if db.query(User).filter(User.username == username).first():
        return again("That username is already taken. Please choose another.")
    if db.query(User).filter(User.pocketid_sub == pending["sub"]).first():
        return again("That Pocket ID account has already been used to sign up.", status=409)

    user = User(
        username=username,
        account_secret=None,  # Pocket ID is this account's only credential.
        pocketid_sub=pending["sub"],
        email=pending.get("email"),
        email_verified=bool(pending.get("email_verified")),
        avatar_url=pending.get("picture"),
        display_name=(pending.get("name") or "").strip() or None,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    destination = safe_next(pending.get("next"))
    login_user(request, user)
    return RedirectResponse(url=destination, status_code=303)


@router.post("/pocketid/unlink")
async def pocketid_unlink(request: Request, db: Session = Depends(get_db)):
    user = require_current_user(request, db)
    if not user.pocketid_sub:
        return RedirectResponse(url="/profile/settings", status_code=303)

    user.pocketid_sub = None
    user.email = None
    user.email_verified = False
    user.avatar_url = None

    if user.account_secret or user.google_sub:
        db.commit()
        return RedirectResponse(url="/profile/settings", status_code=303)

    secret = secrets.token_urlsafe(36)
    user.account_secret = secret
    db.commit()

    request.session["new_account_secret"] = secret
    request.session["new_account_username"] = user.username
    request.session["new_account_heading"] = "Pocket ID disconnected"
    return RedirectResponse(url="/auth/register/success", status_code=303)
