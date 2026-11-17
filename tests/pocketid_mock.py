# SPDX-License-Identifier: GPL-3.0-or-later
# Copyright (C) 2026 Domatron22
"""A stand-in Pocket ID provider for the Pocket ID sign-in tests.

The real provider is reached over HTTPS by a browser, so the end-to-end path
cannot be exercised against it from a test suite. This speaks just enough
OAuth 2.0 / OIDC — discovery, authorize, token, JWKS, userinfo — to run the
whole round trip in-process: ``/auth/pocketid/login`` hands off to here, here
redirects back to the app's callback, and the app mints the session exactly as
it would against Pocket ID.

It is imported only by ``conftest`` when ``POCKETID_E2E=1`` is in the
environment, so the ordinary suite never opens a socket.

Deliberate simplifications, all of them harmless for what is being tested:
codes are single-use and short-lived rather than cryptographically bound to the
user agent, the "logged in user" is whoever ``claims`` says it is, and TLS,
consent screens and refresh tokens are omitted. Everything the relying party
validates — issuer, audience, signature, expiry, nonce, PKCE — is real.
"""
import base64
import hashlib
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlencode, urlparse

from authlib.jose import RSAKey, jwt

# How long an authorization code stays redeemable, in seconds.
CODE_TTL = 300


class MockIdP:
    """An in-process OpenID Provider on 127.0.0.1."""

    def __init__(self, client_id="coverbound-test", redirect_uri=None,
                 claims=None, scopes="openid email profile"):
        self.client_id = client_id
        self.redirect_uri = redirect_uri or "http://testserver/auth/pocketid/callback"
        self.requested_scopes = scopes

        self.key = RSAKey.generate_key(2048, {"kid": "mock-key-1"}, is_private=True)
        self.claims = {
            "sub": "pid-0001",
            "email": "reader@example.com",
            "email_verified": True,
            "name": "Reader One",
            "preferred_username": "reader1",
            "picture": None,
        }
        if claims:
            self.claims.update(claims)
        # A test may rewrite a claim to exercise a branch; the fixture restores
        # these afterwards so one test cannot quietly change the next.
        self._default_claims = dict(self.claims)

        # ``code -> {challenge, nonce, redirect_uri, claims}``. Pocket ID would
        # keep these server-side too; a dict is enough for one test at a time.
        self.codes = {}
        self.used_codes = set()
        self.token_requests = []
        self.authorize_requests = []

        # Fault switches, so the negative tests do not need a second server.
        self.authorize_fault = None
        self.token_fault = None

        handler_cls = type(
            "BoundProviderHandler", (_ProviderHandler,), {"mock": self}
        )
        self._server = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self._thread = threading.Thread(
            target=self._server.serve_forever, name="mock-pocketid", daemon=True
        )

    # -- lifecycle ---------------------------------------------------------

    @property
    def base_url(self):
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def reset(self):
        """Forget issued codes and recorded requests between tests."""
        self.codes.clear()
        self.used_codes.clear()
        self.token_requests.clear()
        self.authorize_requests.clear()
        self.authorize_fault = None
        self.token_fault = None
        self.claims = dict(self._default_claims)

    # -- protocol ---------------------------------------------------------

    def discovery(self):
        base = self.base_url
        return {
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "userinfo_endpoint": f"{base}/userinfo",
            "jwks_uri": f"{base}/jwks",
            "scopes_supported": self.requested_scopes.split(),
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
            "token_endpoint_auth_methods_supported": [
                "none", "client_secret_basic", "client_secret_post"
            ],
            "claims_supported": list(self.claims),
            "code_challenge_methods_supported": ["S256"],
        }

    def jwks(self):
        # ``as_dict`` filters the private exponents and keeps the ``kid``, so
        # the metadata stays in step with the key the tokens are signed with.
        return {"keys": [self.key.as_dict(is_private=False)]}

    def handle_authorize(self, handler, query):
        self.authorize_requests.append(query)

        problem = None
        if query.get("response_type", [""])[0] != "code":
            problem = "unsupported_response_type"
        elif query.get("client_id", [""])[0] != self.client_id:
            problem = "invalid_client"
        elif query.get("redirect_uri", [""])[0] != self.redirect_uri:
            # Pocket ID rejects a redirect it was not told about, and so must
            # the app's configured base URL match what the provider knows.
            problem = "invalid_request"
        elif "openid" not in query.get("scope", [""])[0].split():
            problem = "invalid_scope"

        if problem:
            return _respond(handler, 400, {"error": problem})

        state = query.get("state", [""])[0]
        if not state:
            return _respond(handler, 400, {"error": "invalid_request"})

        code = "mock-code-" + hashlib.sha256(state.encode()).hexdigest()[:16]
        self.codes[code] = {
            "challenge": query.get("code_challenge", [""])[0],
            "method": query.get("code_challenge_method", [""])[0],
            "nonce": query.get("nonce", [""])[0],
            "redirect_uri": query["redirect_uri"][0],
            "expires": time.time() + CODE_TTL,
            "claims": dict(self.claims),
        }

        params = {"code": code}
        if self.authorize_fault != "drop_state":
            params["state"] = state
        return _redirect(handler, self.redirect_uri, params)

    def handle_token(self, handler, form):
        self.token_requests.append({k: v[0] for k, v in form.items()})

        def error(code, description):
            return _respond(
                handler, 400,
                {"error": code, "error_description": description},
                cache=False,
            )

        if self.token_fault == "reject_grant":
            return error("invalid_grant", "fault injected by the test")

        if form.get("grant_type", [""])[0] != "authorization_code":
            return error("unsupported_grant_type", "expected authorization_code")

        code = form.get("code", [""])[0]
        entry = self.codes.get(code)
        if entry is None or code in self.used_codes:
            return error("invalid_grant", "unknown or already-used code")
        if time.time() > entry["expires"]:
            return error("invalid_grant", "code expired")

        if form.get("redirect_uri", [""])[0] != entry["redirect_uri"]:
            return error("invalid_grant", "redirect_uri does not match")

        verifier = form.get("code_verifier", [""])[0]
        if entry["challenge"]:
            if entry["method"] != "S256" or not verifier:
                return error("invalid_grant", "PKCE challenge not satisfied")
            digest = hashlib.sha256(verifier.encode()).digest()
            expected = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            if expected != entry["challenge"]:
                return error("invalid_grant", "PKCE verifier mismatch")

        # A single-use code, as required by RFC 6749 §4.1.2.
        self.used_codes.add(code)

        now = int(time.time())
        claims = {
            "iss": self.base_url,
            "sub": entry["claims"]["sub"],
            "aud": self.client_id,
            "iat": now,
            "exp": now + 600,
            "email": entry["claims"]["email"],
            "email_verified": entry["claims"]["email_verified"],
            "name": entry["claims"]["name"],
            "preferred_username": entry["claims"]["preferred_username"],
        }
        if entry["claims"].get("picture"):
            claims["picture"] = entry["claims"]["picture"]
        if self.authorize_fault != "drop_nonce":
            claims["nonce"] = entry["nonce"]
        if self.authorize_fault == "stale_id_token":
            claims["exp"] = now - 1

        header = {"alg": "RS256", "kid": "mock-key-1"}
        id_token = jwt.encode(header, claims, self.key).decode()

        return _respond(
            handler, 200,
            {
                "access_token": "mock-access-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "scope": self.requested_scopes,
                "id_token": id_token,
            },
            cache=False,
        )

    def handle_userinfo(self, handler):
        auth = handler.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _respond(handler, 401, {"error": "invalid_token"})
        return _respond(handler, 200, dict(self.claims))


class _ProviderHandler(BaseHTTPRequestHandler):
    """Routes requests to the :class:`MockIdP` bound to this server.

    ``mock`` is set on a per-server subclass rather than on the server object:
    ``socketserver`` servers are plain attributes, but binding it in the class
    keeps a second :class:`MockIdP` from ever seeing the first one's requests.
    """

    mock: "MockIdP"
    protocol_version = "HTTP/1.1"

    def log_message(self, format, *args):  # noqa: A002 - base class spelling
        """Keep the test output readable."""

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's naming
        mock = self.mock
        path = urlparse(self.path).path
        if path == "/.well-known/openid-configuration":
            return _respond(self, 200, mock.discovery())
        if path == "/jwks":
            return _respond(self, 200, mock.jwks())
        if path == "/userinfo":
            return mock.handle_userinfo(self)
        if path == "/authorize":
            return mock.handle_authorize(self, parse_qs(urlparse(self.path).query))
        return _respond(self, 404, {"error": "not_found"})

    def do_POST(self):  # noqa: N802
        mock = self.mock
        if urlparse(self.path).path != "/token":
            return _respond(self, 404, {"error": "not_found"})
        if mock.token_fault == "hang_up":
            # Answer nothing at all and drop the connection. That is what a
            # crashed, still-booting, or mis-addressed Pocket ID looks like from
            # the app's side — an httpx transport error, not an OAuth error.
            self.close_connection = True
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            self.connection.close()
            return
        length = int(self.headers.get("Content-Length") or 0)
        form = parse_qs(self.rfile.read(length).decode())
        return mock.handle_token(self, form)


def _respond(handler, status, payload, cache=True):
    body = json.dumps(payload).encode()
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    if not cache:
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("Pragma", "no-cache")
    handler.end_headers()
    handler.wfile.write(body)


def _redirect(handler, uri, params):
    location = f"{uri}?{urlencode(params)}"
    handler.send_response(302)
    handler.send_header("Location", location)
    handler.send_header("Content-Length", "0")
    handler.end_headers()
