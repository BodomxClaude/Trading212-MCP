"""Tests for server.py — MCP handler wiring against the installed SDK.

These guard the SDK integration itself: the rest of the suite never imports
server.py, so an API break in the mcp package (handler signatures, result
types, transport) would otherwise only surface at runtime.
"""

import json
import threading
from unittest.mock import patch

import mcp.types as types
import pytest
from starlette.testclient import TestClient

import server
import tools


class TestRoutes:
    def test_expected_routes(self):
        paths = {getattr(r, "path", None) for r in server.app.routes}
        assert {"/mcp", "/sse", "/messages", "/health"} <= paths


class TestListTools:
    async def test_returns_full_registry(self):
        result = await server.list_tools(None, None)
        assert isinstance(result, types.ListToolsResult)
        assert [t.name for t in result.tools] == [t.name for t in tools.ALL_TOOLS]


class TestCallTool:
    async def test_success_serializes_result(self):
        params = types.CallToolRequestParams(name="get_positions", arguments={})
        with patch.object(tools, "dispatch", return_value={"ok": True}) as disp:
            result = await server.call_tool(None, params)
        disp.assert_called_once_with("get_positions", {})
        assert result.is_error is False
        assert result.content[0].text == '{\n  "ok": true\n}'

    async def test_missing_arguments_defaults_to_empty_dict(self):
        params = types.CallToolRequestParams(name="get_positions")
        with patch.object(tools, "dispatch", return_value={}) as disp:
            await server.call_tool(None, params)
        disp.assert_called_once_with("get_positions", {})

    async def test_dispatch_runs_off_the_event_loop(self):
        """Rate-limit waits are blocking, so dispatch must not run on the loop."""
        loop_thread = threading.get_ident()
        seen = {}

        def spy(name, args):
            seen["thread"] = threading.get_ident()
            return {}

        params = types.CallToolRequestParams(name="get_positions", arguments={})
        with patch.object(tools, "dispatch", spy):
            await server.call_tool(None, params)
        assert seen["thread"] != loop_thread

    async def test_unknown_tool_is_error(self):
        params = types.CallToolRequestParams(name="nope", arguments={})
        result = await server.call_tool(None, params)
        assert result.is_error is True
        assert "Unknown tool" in result.content[0].text


def _json_rpc(response):
    """Read a JSON-RPC payload from either a JSON or an SSE-framed body."""
    if "data:" in response.text:
        for line in response.text.splitlines():
            if line.startswith("data:"):
                return json.loads(line[5:].strip())
    return json.loads(response.text)


@pytest.fixture
def client():
    # A fresh app per test: the SDK's session manager refuses to run twice on
    # one instance, so sharing the module-level app breaks the second test.
    with TestClient(server.build_app("0.0.0.0")) as c:
        yield c


class TestStatelessStreamableHttp:
    """The /mcp endpoint must answer without an initialize handshake.

    Obot's vMCP gateway (v0.27.0+) reaches components over Streamable HTTP
    only; a POST to the SSE endpoint gets 405, so this endpoint is the
    contract, not an implementation detail.
    """

    def _post(self, client, payload):
        return client.post(
            "/mcp",
            json=payload,
            headers={
                "Accept": "application/json, text/event-stream",
                "Content-Type": "application/json",
            },
        )

    def test_tools_list_without_initialize(self, client):
        response = self._post(
            client, {"jsonrpc": "2.0", "id": "x", "method": "tools/list", "params": {}}
        )
        assert response.status_code == 200
        returned = _json_rpc(response)["result"]["tools"]
        assert [t["name"] for t in returned] == [t.name for t in tools.ALL_TOOLS]

    def test_no_session_is_issued(self, client):
        response = self._post(
            client, {"jsonrpc": "2.0", "id": "x", "method": "tools/list", "params": {}}
        )
        assert response.headers.get("mcp-session-id") is None

    def test_initialize_is_accepted(self, client):
        response = self._post(
            client,
            {
                "jsonrpc": "2.0",
                "id": "1",
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "test", "version": "0"},
                },
            },
        )
        assert response.status_code == 200
        assert _json_rpc(response)["result"]["serverInfo"]["name"] == "trading212"

    def test_tools_call_without_initialize(self, client):
        with patch.object(tools, "dispatch", return_value={"ok": True}) as dispatch:
            response = self._post(
                client,
                {
                    "jsonrpc": "2.0",
                    "id": "1",
                    "method": "tools/call",
                    "params": {"name": "get_positions", "arguments": {}},
                },
            )
        assert response.status_code == 200
        dispatch.assert_called_once_with("get_positions", {})
        result = _json_rpc(response)["result"]
        assert result["isError"] is False


class TestBuildApp:
    def test_forwards_bind_host_so_localhost_rebinding_guard_stays_off(self):
        """The SDK only allows localhost Host headers when host is its default.

        Obot reaches this server by container IP, so the bind host has to be
        passed through or every proxied request is rejected.
        """
        app = server.build_app("0.0.0.0")
        assert {getattr(r, "path", None) for r in app.routes} >= {"/mcp", "/health"}
