# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
"""Pocket ID sign-in via OpenID Connect.

The mirror image of `google_oauth`: Authlib does discovery, the `state`/`nonce`
round trip and ID-token validation, and this module only carries configuration
plus the one deployment-specific detail — which callback URI to hand the
provider.

Pocket ID is self-hosted, so the issuer is configuration rather than a constant.
With no `POCKETID_CLIENT_ID` (or no `POCKETID_BASE_URL`) the client is never
registered and `pocketid_enabled()` is False, which keeps every Pocket ID
affordance out of the UI — the same behaviour the Google path has for a
deployment with no Google project.
"""
import os

from fastapi import Request

# One Authlib registry for the whole app, shared with Google sign-in.
from .google_oauth import oauth

# Pocket ID's default scopes already include the claims we want; overridable so
# a deployment can ask for more without editing code.
POCKETID_SCOPES = "openid email profile"


def _env(name: str) -> str:
    return (os.getenv(name) or "").strip()


def pocketid_base_url() -> str:
    """The issuer address, without a trailing slash."""
    return _env("POCKETID_BASE_URL").rstrip("/")


# The secret is optional: Pocket ID issues a client secret for confidential
# clients, but a public client + PKCE is equally valid, so neither a missing
# secret nor a present one is an error. What is not optional is a client id and
# something to discover metadata from.
_ENABLED = bool(_env("POCKETID_CLIENT_ID") and pocketid_base_url())


def pocketid_enabled() -> bool:
    """True when this deployment has a Pocket ID OIDC client configured."""
    return _ENABLED


if _ENABLED:
    oauth.register(
        name="pocketid",
        client_id=_env("POCKETID_CLIENT_ID"),
        # None rather than "" — Authlib treats an empty secret as a configured
        # confidential client and will attempt a secret-bearing exchange that
        # Pocket ID rejects for a public client.
        client_secret=_env("POCKETID_CLIENT_SECRET") or None,
        server_metadata_url=f"{pocketid_base_url()}/.well-known/openid-configuration",
        client_kwargs={
            "scope": _env("POCKETID_SCOPES") or POCKETID_SCOPES,
            # Not on by default in Authlib. We're usually a public client here,
            # so PKCE is what stops a leaked authorization code from being
            # redeemed by anyone else; it is harmless for a confidential one.
            "code_challenge_method": "S256",
            # Authlib would otherwise inherit httpx's 5s default. Discovery and
            # the token exchange both go through here, so an explicit bound
            # keeps a half-dead Pocket ID from pinning the request (and the
            # operator's browser tab) indefinitely.
            "timeout": 10.0,
        },
    )


def pocketid_redirect_uri(request: Request) -> str:
    """The callback URI to send Pocket ID, which must match a registered one exactly.

    This is the *app's* address, never the provider's: `POCKETID_BASE_URL` says
    where the identity provider lives, and the code comes back here. Behind a
    reverse proxy the app usually sees plain HTTP on an internal host, so
    deriving this from the request alone produces `http://127.0.0.1:8000/...`
    — which Pocket ID rejects. `PUBLIC_BASE_URL` overrides it with the address
    users actually type.
    """
    base = _env("PUBLIC_BASE_URL")
    if base:
        return f"{base.rstrip('/')}/auth/pocketid/callback"
    return str(request.url_for("pocketid_callback"))
