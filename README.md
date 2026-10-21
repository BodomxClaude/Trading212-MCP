# Trading 212 MCP Server

An MCP (Model Context Protocol) server for the [Trading 212 Public API](https://docs.trading212.com/api),
packaged as a Docker container for hosting on [Obot](https://obot.ai) or any MCP host
that speaks Streamable HTTP or SSE.

It exposes the account, instruments, orders, history and pies endpoints as MCP tools.

> ⚠️ **This server can place and cancel real orders.** It targets the **demo / paper**
> environment by default. Only set `TRADING212_LIVE=true` once you understand the risk.

## Environments

Trading 212 runs two fully separate environments, each with its own credentials:

| `TRADING212_LIVE` | Base URL | Money |
|---|---|---|
| _unset / `false`_ (default) | `https://demo.trading212.com/api/v0` | Paper |
| `true` | `https://live.trading212.com/api/v0` | **Real** |

## Authentication

The Public API uses **HTTP Basic auth** — `Base64("API_KEY:API_SECRET")`.
Generate the key and secret in the Trading 212 app under **Settings > API**; the secret
is shown only once.

## Configuration

Provide config one of two ways (env vars are the simplest):

### Environment variables

| Variable | Required | Description |
|---|---|---|
| `TRADING212_API_KEY` | yes | API key from the Trading 212 app |
| `TRADING212_API_SECRET` | yes | API secret (shown once at generation) |
| `TRADING212_LIVE` | no | `true` for the live/real-money environment; default uses demo/paper |
| `SERVER_HOST` | no | Bind host (default `0.0.0.0`) |
| `SERVER_PORT` | no | Bind port (default `8000`) |

### Config file (Docker volume)

Mount a JSON file at `/config/config.json` (takes priority over env vars):

```json
{
  "api_key": "your-api-key-here",
  "api_secret": "your-api-secret-here",
  "live": false
}
```

## Running

### docker-compose

```bash
cp .env.example .env   # then edit values
docker compose up --build
```

### docker

```bash
docker build -t trading212-mcp .
docker run -p 8000:8000 \
  -e TRADING212_API_KEY=... \
  -e TRADING212_API_SECRET=... \
  -e TRADING212_LIVE=false \
  trading212-mcp
```

The server then exposes:

- `POST /mcp` — MCP Streamable HTTP endpoint, stateless: no `initialize` handshake and no
  `Mcp-Session-Id` needed (point your MCP host here; Obot v0.27.0+ requires it)
- `GET /sse` — MCP SSE connection endpoint (legacy transport, still served)
- `POST /messages/` — MCP message endpoint (used internally by the SSE transport)
- `GET /health` — liveness check (reports the active environment)

## Deploying to Obot

1. Build & push the image (the included GitHub Actions workflow publishes
   `ghcr.io/nigelvanhattum/trading212-mcp:latest` on push to `main`).
2. The Obot catalog entry lives in the `obot-mcp-repository` repo as `trading212.yaml`.
3. In Obot, add the server and set `TRADING212_API_KEY`, `TRADING212_API_SECRET`, and
   optionally `TRADING212_LIVE`.

## Tools

| Module | Tools |
|---|---|
| **account** | `get_account_summary`, `get_positions` |
| **instruments** | `list_instruments`, `list_exchanges` |
| **orders** | `list_orders`, `get_order`, `cancel_order`, `place_market_order`, `place_limit_order`, `place_stop_order`, `place_stop_limit_order` |
| **history** | `get_historical_orders`, `get_dividends`, `get_transactions`, `list_exports`, `request_export` |

**Order convention:** a **positive** quantity buys, a **negative** quantity sells (e.g. `-10.5`).
Orders execute only in the account's main currency.

### Searching instruments

The upstream `/metadata/instruments` endpoint takes no parameters — it returns
the entire catalogue (~15k instruments, several MB), which is not something to
hand an agent. `list_instruments` fetches that list once, caches it for 10
minutes, and searches it locally:

| Argument | Match |
|---|---|
| `trading212Id` | Trading 212 instrument ID, e.g. `AAPL_US_EQ`. Exact, prefix (`AAPL`) or substring, ranked in that order |
| `isin` | Exact, case-insensitive |
| `name` | Case-insensitive substring |
| `type` | One of `STOCK`, `ETF`, `CRYPTOCURRENCY`, … |
| `limit` | Result cap (default 20, max 100) |

Filters combine with AND. Responses carry `total` (all matches), `returned`,
`limit` and `truncated`, so a search that is too broad reports how much it left
out instead of silently dropping it.

`trading212Id` is the API's `ticker` field — the value the order tools take as
their `ticker` argument. It is named separately here because it is a Trading 212
identifier (`AAPL_US_EQ`), not a market ticker (`AAPL`).

## Rate limiting

Every Trading 212 endpoint has its own limit and they apply **per account**, so a
burst from this server counts against the same budget as anything else the
account is doing. `ratelimit.py` holds the published limit for each endpoint and
puts every outgoing call through a single queue: calls go out one at a time, in
the order they arrived, and each waits out its own endpoint's window first.

Consequences worth knowing:

- A tool call can block for a while — `list_instruments` is 1 req / 50s, so a
  second call to it waits nearly a minute. Nothing is dropped or rejected; it
  waits its turn.
- Because the queue is strictly in order, a slow call holds up the ones behind
  it. Fine at this server's traffic; it is the trade-off that makes the
  guarantee simple.
- Waits happen on a worker thread, so other requests and `/health` stay
  responsive throughout.
- A `429` that slips through anyway (another client on the same account) holds
  that endpoint back for the interval in `Retry-After` / `x-ratelimit-reset` and
  is retried once.

## Development

```bash
pip install -e ".[dev]"
pytest
```

The Docker build runs the test suite as a build stage — a failing test fails the image build.

## API reference

- Key concepts: https://docs.trading212.com/api/section/general-information/key-concepts
- Environments: https://docs.trading212.com/api/section/general-information/api-environments
- Full API: https://docs.trading212.com/api
