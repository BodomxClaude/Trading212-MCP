#!/usr/bin/env python3
"""
Trading 212 MCP Server — Docker-hosted.

Exposes:
  POST /mcp        — MCP Streamable HTTP endpoint, stateless
  GET  /sse        — MCP SSE connection endpoint (legacy transport)
  POST /messages/  — MCP message endpoint (used by SSE transport internally)
  GET  /health     — liveness check

Configuration:
  Mount /config/config.json  OR  set TRADING212_API_KEY / TRADING212_API_SECRET /
  TRADING212_LIVE env vars. See client.py for details.
"""

import functools
import json
import os

import anyio.to_thread
import httpx
import mcp.types as types
import uvicorn
from mcp.server import Server, ServerRequestContext
from mcp.server.sse import SseServerTransport
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

import client
import tools

# ---------------------------------------------------------------------------
# MCP server
# ---------------------------------------------------------------------------

async def list_tools(
    ctx: ServerRequestContext,
    params: types.PaginatedRequestParams | None,
) -> types.ListToolsResult:
    return types.ListToolsResult(tools=tools.ALL_TOOLS)


async def call_tool(
    ctx: ServerRequestContext,
    params: types.CallToolRequestParams,
) -> types.CallToolResult:
    try:
        # dispatch() is blocking and may sit in the rate limiter's queue for a
        # while, so keep it off the event loop and out of the way of other
        # requests.
        result = await anyio.to_thread.run_sync(
            functools.partial(tools.dispatch, params.name, params.arguments or {})
        )
        text = json.dumps(result, indent=2)
        is_error = False
    except httpx.HTTPStatusError as e:
        text = f"HTTP {e.response.status_code}: {e.response.text}"
        is_error = True
    except Exception as e:
        text = f"Error: {e}"
        is_error = True
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)],
        isError=is_error,
    )


mcp_server = Server(
    "trading212",
    version="1.0.0",
    on_list_tools=list_tools,
    on_call_tool=call_tool,
)


# ---------------------------------------------------------------------------
# SSE transport + Starlette app
# ---------------------------------------------------------------------------

sse = SseServerTransport("/messages/")


async def handle_sse(request: Request):
    async with sse.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp_server.run(
            streams[0], streams[1],
            mcp_server.create_initialization_options(),
        )
    # SSE response is already sent by connect_sse; Starlette still wants a Response.
    return Response()


async def health(request: Request):
    return JSONResponse({"status": "ok", "environment": "live" if client.LIVE else "demo"})


SERVER_HOST = os.environ.get("SERVER_HOST", "0.0.0.0")


def build_app(host: str = SERVER_HOST) -> Starlette:
    # stateless_http drops session tracking, so a client may POST tools/list or
    # tools/call without an initialize handshake and without Mcp-Session-Id.
    #
    # host is forwarded because the SDK auto-enables DNS-rebinding protection
    # when it is left at the 127.0.0.1 default, which allows only localhost
    # Host headers and rejects every request that arrives by container IP.
    return mcp_server.streamable_http_app(
        stateless_http=True,
        host=host,
        custom_starlette_routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages", app=sse.handle_post_message),
            Route("/health", endpoint=health),
        ],
    )


app = build_app()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("SERVER_PORT", "8000"))
    uvicorn.run(app, host=SERVER_HOST, port=port)
