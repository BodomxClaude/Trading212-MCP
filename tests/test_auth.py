"""Tests for auth.py — the OAuth layer in front of the MCP endpoints."""

import base64
import hashlib
import secrets
from urllib.parse import parse_qs, urlparse

import pytest
from starlette.testclient import TestClient

import auth
import server

PASSWORD = "correct-horse-battery-staple-42"
CALLBACK = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def client():
    app = auth.protect(server.build_app("0.0.0.0"), password=PASSWORD)
    with TestClient(app, base_url="https://testserver") as c:
        yield c


def pkce():
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    return verifier, challenge


def register(c, method="none", redirect=CALLBACK):
    r = c.post("/register", json={"redirect_uris": [redirect], "client_name": "Claude",
                                  "token_endpoint_auth_method": method})
    return r


def login(c, client_id, challenge, password=PASSWORD, state="xyz"):
    return c.post("/authorize", data={
        "client_id": client_id, "redirect_uri": CALLBACK, "state": state,
        "code_challenge": challenge, "code_challenge_method": "S256",
        "response_type": "code", "resource": "https://testserver/mcp", "password": password,
    }, follow_redirects=False)


def full_flow(c, method="none"):
    reg = register(c, method).json()
    verifier, challenge = pkce()
    r = login(c, reg["client_id"], challenge)
    assert r.status_code == 302
    q = parse_qs(urlparse(r.headers["location"]).query)
    assert q["state"] == ["xyz"]
    data = {"grant_type": "authorization_code", "code": q["code"][0], "redirect_uri": CALLBACK,
            "client_id": reg["client_id"], "code_verifier": verifier}
    if method == "client_secret_post":
        data["client_secret"] = reg["client_secret"]
    return reg, q["code"][0], verifier, c.post("/token", data=data)


class TestStartup:
    def test_refuses_without_password(self, monkeypatch):
        monkeypatch.delenv("MCP_LOGIN_PASSWORD", raising=False)
        with pytest.raises(RuntimeError):
            auth.protect(server.build_app("0.0.0.0"))

    def test_refuses_short_password(self):
        with pytest.raises(RuntimeError):
            auth.protect(server.build_app("0.0.0.0"), password="short")


class TestProtection:
    @pytest.mark.parametrize("path", ["/mcp", "/sse", "/messages/", "/anything"])
    def test_blocks_without_token(self, client, path):
        r = client.post(path, json={})
        assert r.status_code == 401
        assert 'resource_metadata="https://testserver/.well-known/oauth-protected-resource"' in r.headers["www-authenticate"]

    def test_blocks_forged_token(self, client):
        r = client.post("/mcp", headers={"Authorization": "Bearer abc.def"}, json={})
        assert r.status_code == 401

    def test_token_from_other_password_rejected(self, client):
        other = auth.Signer("another-password-that-is-long-enough").sign("access", 3600, cid="x")
        r = client.post("/mcp", headers={"Authorization": f"Bearer {other}"}, json={})
        assert r.status_code == 401

    def test_health_stays_open(self, client):
        assert client.get("/health").status_code == 200


class TestMetadata:
    def test_resource_metadata(self, client):
        m = client.get("/.well-known/oauth-protected-resource").json()
        assert m["resource"] == "https://testserver/mcp"
        assert m["authorization_servers"] == ["https://testserver"]

    def test_server_metadata(self, client):
        m = client.get("/.well-known/oauth-authorization-server").json()
        assert m["token_endpoint"] == "https://testserver/token"
        assert m["code_challenge_methods_supported"] == ["S256"]


class TestRegistration:
    def test_foreign_redirect_rejected(self, client):
        r = register(client, redirect="https://evil.example/cb")
        assert r.status_code == 400

    def test_registration_ok(self, client):
        r = register(client)
        assert r.status_code == 201
        assert r.json()["redirect_uris"] == [CALLBACK]


class TestLogin:
    def test_login_page_shown(self, client):
        reg = register(client).json()
        _, challenge = pkce()
        r = client.get("/authorize", params={
            "client_id": reg["client_id"], "redirect_uri": CALLBACK, "response_type": "code",
            "code_challenge": challenge, "code_challenge_method": "S256", "state": "s"})
        assert r.status_code == 200
        assert 'type="password"' in r.text

    def test_pkce_required(self, client):
        reg = register(client).json()
        r = client.get("/authorize", params={"client_id": reg["client_id"], "redirect_uri": CALLBACK,
                                             "response_type": "code"})
        assert r.status_code == 400

    def test_wrong_password(self, client):
        reg = register(client).json()
        _, challenge = pkce()
        r = login(client, reg["client_id"], challenge, password="wrong")
        assert r.status_code == 401
        assert "location" not in r.headers

    def test_lockout_after_failures(self, client):
        reg = register(client).json()
        _, challenge = pkce()
        for _ in range(auth.MAX_FAILURES):
            login(client, reg["client_id"], challenge, password="wrong")
        r = login(client, reg["client_id"], challenge)  # even the right password
        assert r.status_code == 429


class TestTokens:
    def test_full_flow_reaches_mcp(self, client):
        _, _, _, r = full_flow(client)
        assert r.status_code == 200
        token = r.json()["access_token"]
        mcp = client.post("/mcp", headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }, json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}})
        assert mcp.status_code == 200
        assert "get_positions" in mcp.text

    def test_confidential_client(self, client):
        _, _, _, r = full_flow(client, method="client_secret_post")
        assert r.status_code == 200

    def test_code_single_use(self, client):
        reg, code, verifier, r = full_flow(client)
        assert r.status_code == 200
        again = client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                            "redirect_uri": CALLBACK, "client_id": reg["client_id"],
                                            "code_verifier": verifier})
        assert again.status_code == 400

    def test_wrong_verifier(self, client):
        reg = register(client).json()
        _, challenge = pkce()
        r = login(client, reg["client_id"], challenge)
        code = parse_qs(urlparse(r.headers["location"]).query)["code"][0]
        t = client.post("/token", data={"grant_type": "authorization_code", "code": code,
                                        "redirect_uri": CALLBACK, "client_id": reg["client_id"],
                                        "code_verifier": "not-the-verifier"})
        assert t.status_code == 400

    def test_refresh(self, client):
        reg, _, _, r = full_flow(client)
        t = client.post("/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                        "refresh_token": r.json()["refresh_token"]})
        assert t.status_code == 200
        assert t.json()["access_token"]

    def test_access_token_not_usable_as_refresh(self, client):
        reg, _, _, r = full_flow(client)
        t = client.post("/token", data={"grant_type": "refresh_token", "client_id": reg["client_id"],
                                        "refresh_token": r.json()["access_token"]})
        assert t.status_code == 400
