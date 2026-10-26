"""
OAuth 2.1 protection for the Trading 212 MCP server (single user).

Wraps the Starlette app so that every MCP endpoint (/mcp, /sse, /messages)
requires a Bearer token. The server is its own small authorization server, as
the MCP authorization spec allows, so Claude's custom connectors can log in:

  GET  /.well-known/oauth-protected-resource[/mcp]  - resource metadata (RFC 9728)
  GET  /.well-known/oauth-authorization-server       - server metadata (RFC 8414)
  POST /register   - dynamic client registration (RFC 7591)
  GET  /authorize  - login page (one password, the owner's)
  POST /authorize  - checks the password, redirects back with a code
  POST /token      - authorization_code (PKCE S256 required) and refresh_token

Design:
  - Exactly one user. Logging in means typing MCP_LOGIN_PASSWORD.
  - Stateless: client ids, codes and tokens are HMAC-signed, so Cloud Run may
    scale to zero without losing anything. The signing key is derived from
    the password, so changing the password revokes every token at once.
  - Codes are only ever sent to an allow-listed redirect URI (Claude's
    callbacks by default), so a stranger who registers a client still cannot
    receive a code, and without the password there is no code at all.
  - Failed logins are throttled and locked out after repeated failures.

Environment:
  MCP_LOGIN_PASSWORD     - required, at least 20 characters
  MCP_ALLOWED_REDIRECTS  - optional, comma-separated redirect URIs
                           (default: Claude's two OAuth callback URLs)
  MCP_PUBLIC_URL         - optional, e.g. https://xyz.run.app; otherwise
                           derived from the request (https assumed)
"""

import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import threading
import time
from urllib.parse import unquote, urlencode

import anyio

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response

DEFAULT_REDIRECTS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)
MIN_PASSWORD_LENGTH = 20

CODE_TTL = 300                     # 5 minutes
ACCESS_TTL = 3600                  # 1 hour
REFRESH_TTL = 30 * 24 * 3600       # 30 days

MAX_FAILURES = 5                   # failed logins ...
FAILURE_WINDOW = 15 * 60           # ... within this window ...
LOCKOUT = 15 * 60                  # ... lock the login for this long

PROTECTED_PREFIXES = ("/mcp", "/sse", "/messages")
OPEN_PATHS = ("/health",)


# ---------------------------------------------------------------------------
# Signed, self-contained tokens
# ---------------------------------------------------------------------------

def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


class Signer:
    def __init__(self, password: str):
        self._key = hmac.new(password.encode(), b"trading212-mcp-oauth-v1", hashlib.sha256).digest()

    def sign(self, kind: str, ttl: int | None, **claims) -> str:
        payload = {"k": kind, "iat": int(time.time()), "n": secrets.token_urlsafe(8), **claims}
        if ttl is not None:
            payload["exp"] = int(time.time()) + ttl
        body = _b64(json.dumps(payload, separators=(",", ":")).encode())
        mac = _b64(hmac.new(self._key, f"{kind}.{body}".encode(), hashlib.sha256).digest())
        return f"{body}.{mac}"

    def verify(self, kind: str, token: str) -> dict | None:
        try:
            body, mac = token.split(".")
            expected = _b64(hmac.new(self._key, f"{kind}.{body}".encode(), hashlib.sha256).digest())
            if not hmac.compare_digest(mac, expected):
                return None
            payload = json.loads(_unb64(body))
        except Exception:
            return None
        if payload.get("k") != kind:
            return None
        if "exp" in payload and payload["exp"] < time.time():
            return None
        return payload

    def client_secret(self, client_id: str) -> str:
        return _b64(hmac.new(self._key, f"secret.{client_id}".encode(), hashlib.sha256).digest())


# ---------------------------------------------------------------------------
# Login throttling and one-time codes (in memory; one instance is enough)
# ---------------------------------------------------------------------------

class LoginGuard:
    def __init__(self):
        self._lock = threading.Lock()
        self._failures: list[float] = []
        self._locked_until = 0.0

    def locked(self) -> bool:
        with self._lock:
            return time.time() < self._locked_until

    def failure(self) -> None:
        with self._lock:
            now = time.time()
            self._failures = [t for t in self._failures if now - t < FAILURE_WINDOW] + [now]
            if len(self._failures) >= MAX_FAILURES:
                self._locked_until = now + LOCKOUT
                self._failures = []

    def success(self) -> None:
        with self._lock:
            self._failures = []


class UsedCodes:
    def __init__(self):
        self._lock = threading.Lock()
        self._seen: dict[str, float] = {}

    def claim(self, nonce: str, exp: float) -> bool:
        with self._lock:
            now = time.time()
            self._seen = {n: e for n, e in self._seen.items() if e > now}
            if nonce in self._seen:
                return False
            self._seen[nonce] = exp
            return True


# ---------------------------------------------------------------------------
# The middleware
# ---------------------------------------------------------------------------

LOGIN_PAGE = """<!doctype html>
<html lang="de"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Trading 212 MCP – Anmeldung</title>
<style>
 body{{font-family:system-ui,sans-serif;background:#f4f4f5;margin:0;display:grid;place-items:center;min-height:100vh}}
 form{{background:#fff;padding:28px;border-radius:12px;box-shadow:0 2px 12px #0002;width:min(360px,90vw)}}
 h1{{font-size:1.2rem;margin:0 0 6px}} p{{color:#555;font-size:.9rem;margin:0 0 18px}}
 input[type=password]{{width:100%;box-sizing:border-box;padding:10px;font-size:1rem;border:1px solid #ccc;border-radius:8px}}
 button{{margin-top:14px;width:100%;padding:10px;font-size:1rem;border:0;border-radius:8px;background:#111;color:#fff;cursor:pointer}}
 .err{{color:#b00020;margin:0 0 12px}}
</style></head><body>
<form method="post" action="/authorize">
 <h1>Trading 212 MCP</h1>
 <p>Zugriff für Claude freigeben ({env}).</p>
 {error}
 {hidden}
 <input type="password" name="password" placeholder="Passwort" autofocus required>
 <button type="submit">Freigeben</button>
</form></body></html>"""

AUTH_FIELDS = ("client_id", "redirect_uri", "state", "code_challenge",
               "code_challenge_method", "scope", "resource", "response_type")


class OAuthProtect:
    def __init__(self, app, password: str | None = None, allowed_redirects=None,
                 public_url: str | None = None, environment_label: str = "Demo"):
        password = password if password is not None else os.environ.get("MCP_LOGIN_PASSWORD", "")
        if len(password) < MIN_PASSWORD_LENGTH:
            raise RuntimeError(
                f"MCP_LOGIN_PASSWORD must be set and at least {MIN_PASSWORD_LENGTH} characters long; "
                "refusing to start an unprotected server."
            )
        if allowed_redirects is None:
            env = os.environ.get("MCP_ALLOWED_REDIRECTS", "")
            allowed_redirects = [u.strip() for u in env.split(",") if u.strip()] or list(DEFAULT_REDIRECTS)
        self.app = app
        self.password = password
        self.signer = Signer(password)
        self.allowed_redirects = set(allowed_redirects)
        self.public_url = (public_url or os.environ.get("MCP_PUBLIC_URL", "")).rstrip("/") or None
        self.env_label = environment_label
        self.guard = LoginGuard()
        self.used_codes = UsedCodes()

    # -- ASGI entry -----------------------------------------------------------
    async def __call__(self, scope, receive, send):
        if scope["type"] == "lifespan":
            return await self.app(scope, receive, send)
        if scope["type"] != "http":
            # No websockets or other protocols: nothing here needs them.
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            return

        path = scope.get("path", "")
        request = Request(scope, receive)
        handler = {
            "/.well-known/oauth-protected-resource": self.resource_metadata,
            "/.well-known/oauth-protected-resource/mcp": self.resource_metadata,
            "/.well-known/oauth-authorization-server": self.server_metadata,
            "/.well-known/openid-configuration": self.server_metadata,
            "/register": self.register,
            "/authorize": self.authorize,
            "/token": self.token,
        }.get(path)
        if handler is not None:
            response = await handler(request)
            return await response(scope, receive, send)

        if path in OPEN_PATHS:
            return await self.app(scope, receive, send)

        if path.startswith(PROTECTED_PREFIXES) and self._bearer_ok(request):
            return await self.app(scope, receive, send)

        # Everything else (including unknown paths) is closed without a token.
        response = JSONResponse(
            {"error": "invalid_token", "error_description": "Missing or invalid access token"},
            status_code=401,
            headers={"WWW-Authenticate":
                     f'Bearer resource_metadata="{self._base(request)}/.well-known/oauth-protected-resource"'},
        )
        return await response(scope, receive, send)

    # -- helpers --------------------------------------------------------------
    def _base(self, request: Request) -> str:
        if self.public_url:
            return self.public_url
        host = request.headers.get("host", "localhost")
        local = host.startswith(("localhost", "127.0.0.1"))
        proto = request.headers.get("x-forwarded-proto") or ("http" if local else "https")
        return f"{proto}://{host}"

    def _bearer_ok(self, request: Request) -> bool:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            return False
        return self.signer.verify("access", header[7:].strip()) is not None

    @staticmethod
    def _error(error: str, description: str, status: int = 400) -> JSONResponse:
        return JSONResponse({"error": error, "error_description": description}, status_code=status,
                            headers={"Cache-Control": "no-store"})

    def _client(self, client_id: str | None) -> dict | None:
        if not client_id:
            return None
        return self.signer.verify("client", client_id)

    # -- metadata -------------------------------------------------------------
    async def resource_metadata(self, request: Request) -> Response:
        base = self._base(request)
        return JSONResponse({
            "resource": f"{base}/mcp",
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
        })

    async def server_metadata(self, request: Request) -> Response:
        base = self._base(request)
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "client_secret_post", "client_secret_basic"],
            "scopes_supported": ["trading212"],
        })

    # -- dynamic client registration -----------------------------------------
    async def register(self, request: Request) -> Response:
        if request.method != "POST":
            return self._error("invalid_request", "POST required", 405)
        try:
            meta = await request.json()
        except Exception:
            return self._error("invalid_client_metadata", "Body must be JSON")
        redirects = meta.get("redirect_uris") or []
        if not isinstance(redirects, list) or not redirects:
            return self._error("invalid_redirect_uri", "redirect_uris required")
        bad = [u for u in redirects if u not in self.allowed_redirects]
        if bad:
            return self._error("invalid_redirect_uri", f"Redirect URI not allowed: {bad[0]}")
        method = meta.get("token_endpoint_auth_method", "none")
        if method not in ("none", "client_secret_post", "client_secret_basic"):
            method = "none"
        client_id = self.signer.sign("client", None, ru=redirects, am=method)
        result = {
            "client_id": client_id,
            "client_id_issued_at": int(time.time()),
            "client_name": meta.get("client_name", "MCP client"),
            "redirect_uris": redirects,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": method,
        }
        if method != "none":
            result["client_secret"] = self.signer.client_secret(client_id)
            result["client_secret_expires_at"] = 0
        return JSONResponse(result, status_code=201)

    # -- authorization ---------------------------------------------------------
    def _check_authorize_params(self, p: dict) -> str | None:
        client = self._client(p.get("client_id"))
        if client is None:
            return "Unbekannter Client."
        if p.get("redirect_uri") not in client["ru"] or p.get("redirect_uri") not in self.allowed_redirects:
            return "Ungültige Weiterleitungsadresse."
        if p.get("response_type") != "code":
            return "Nur response_type=code wird unterstützt."
        if not p.get("code_challenge") or p.get("code_challenge_method") != "S256":
            return "PKCE (S256) ist Pflicht."
        return None

    def _login_page(self, p: dict, error: str = "", status: int = 200) -> HTMLResponse:
        hidden = "\n ".join(
            f'<input type="hidden" name="{f}" value="{html.escape(p.get(f) or "", quote=True)}">'
            for f in AUTH_FIELDS
        )
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        return HTMLResponse(
            LOGIN_PAGE.format(env=html.escape(self.env_label), error=err, hidden=hidden),
            status_code=status,
            headers={"Cache-Control": "no-store", "X-Frame-Options": "DENY",
                     "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:"},
        )

    async def authorize(self, request: Request) -> Response:
        if request.method == "GET":
            p = dict(request.query_params)
            problem = self._check_authorize_params(p)
            if problem:
                return HTMLResponse(f"<p>{html.escape(problem)}</p>", status_code=400)
            return self._login_page(p)

        if request.method != "POST":
            return self._error("invalid_request", "GET or POST required", 405)

        form = await request.form()
        p = {f: form.get(f) for f in AUTH_FIELDS}
        problem = self._check_authorize_params(p)
        if problem:
            return HTMLResponse(f"<p>{html.escape(problem)}</p>", status_code=400)

        if self.guard.locked():
            return self._login_page(p, "Zu viele Fehlversuche. Bitte 15 Minuten warten.", 429)

        given = str(form.get("password") or "")
        if not hmac.compare_digest(given.encode(), self.password.encode()):
            self.guard.failure()
            await anyio.sleep(1)
            return self._login_page(p, "Falsches Passwort.", 401)
        self.guard.success()

        code = self.signer.sign(
            "code", CODE_TTL,
            cid=p["client_id"], ru=p["redirect_uri"], cc=p["code_challenge"], res=p.get("resource") or "",
        )
        query = {"code": code}
        if p.get("state"):
            query["state"] = p["state"]
        return RedirectResponse(f'{p["redirect_uri"]}?{urlencode(query)}', status_code=302)

    # -- token endpoint ---------------------------------------------------------
    def _authenticate_client(self, request: Request, form) -> tuple[str | None, str | None]:
        """Returns (client_id, error)."""
        client_id = form.get("client_id")
        secret = form.get("client_secret")
        header = request.headers.get("authorization", "")
        if header.lower().startswith("basic "):
            try:
                cid, _, sec = base64.b64decode(header[6:]).decode().partition(":")
                client_id, secret = unquote(cid), unquote(sec)
            except Exception:
                return None, "Malformed Basic auth"
        client = self._client(client_id)
        if client is None:
            return None, "Unknown client"
        if client.get("am", "none") != "none":
            if not secret or not hmac.compare_digest(secret, self.signer.client_secret(client_id)):
                return None, "Client authentication failed"
        return client_id, None

    def _issue(self, client_id: str, resource: str) -> JSONResponse:
        return JSONResponse({
            "access_token": self.signer.sign("access", ACCESS_TTL, cid=client_id, res=resource),
            "token_type": "Bearer",
            "expires_in": ACCESS_TTL,
            "refresh_token": self.signer.sign("refresh", REFRESH_TTL, cid=client_id, res=resource),
            "scope": "trading212",
        }, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})

    async def token(self, request: Request) -> Response:
        if request.method != "POST":
            return self._error("invalid_request", "POST required", 405)
        form = await request.form()
        client_id, err = self._authenticate_client(request, form)
        if err:
            return self._error("invalid_client", err, 401)

        grant = form.get("grant_type")
        if grant == "authorization_code":
            code = self.signer.verify("code", form.get("code") or "")
            if code is None:
                return self._error("invalid_grant", "Invalid or expired code")
            if code["cid"] != client_id or code["ru"] != form.get("redirect_uri"):
                return self._error("invalid_grant", "Code does not belong to this client/redirect")
            verifier = form.get("code_verifier") or ""
            challenge = _b64(hashlib.sha256(verifier.encode()).digest())
            if not verifier or not hmac.compare_digest(challenge, code["cc"]):
                return self._error("invalid_grant", "PKCE verification failed")
            if not self.used_codes.claim(code["n"], code["exp"]):
                return self._error("invalid_grant", "Code already used")
            return self._issue(client_id, code.get("res", ""))

        if grant == "refresh_token":
            rt = self.signer.verify("refresh", form.get("refresh_token") or "")
            if rt is None or rt["cid"] != client_id:
                return self._error("invalid_grant", "Invalid or expired refresh token")
            return self._issue(client_id, rt.get("res", ""))

        return self._error("unsupported_grant_type", f"Unsupported grant_type: {grant}")


def protect(app, **kwargs) -> OAuthProtect:
    return OAuthProtect(app, **kwargs)
