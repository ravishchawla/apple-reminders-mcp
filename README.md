# apple-reminders-mcp

A small, generic Model Context Protocol server that exposes the macOS Reminders app over HTTP(S). Drop it into Claude Desktop / Cowork, an IDE plugin, or any MCP-aware agent and you get a clean, programmatic interface to your reminders without scraping the UI.

## Why this exists

There's no first-party Apple Reminders MCP. AppleScript and JXA can talk to Reminders fine, but most MCP setups run in sandboxes or remote machines that can't shell out to `osascript` directly. This server runs locally on the Mac, wraps Reminders via JXA, and speaks MCP over HTTPS — so any client that can hit an HTTPS endpoint can use it.

The tool surface is intentionally generic: list, read, create, update, complete, delete, move. No opinions about how you use it.

## Tools

| Tool | Description |
| --- | --- |
| `list_lists` | List every Reminders list (folder). |
| `list_reminders` | List reminders, with optional filters: list name, completion state, substring search, limit. |
| `get_reminder` | Fetch one reminder by id. |
| `create_reminder` | Create a reminder (title, list, body, due date, alarm, priority). |
| `update_reminder` | Update any field. Pass `"null"` for date fields or `""` for body to clear. |
| `complete_reminder` | Mark a reminder done (or un-done with `completed=false`). |
| `delete_reminder` | Permanently delete a reminder. |
| `move_reminder` | Move a reminder to a different list. |

Every reminder is serialized with: `id`, `name`, `body`, `completed`, `completionDate`, `creationDate`, `modificationDate`, `dueDate`, `remindMeDate`, `priority`, `list`. Dates are ISO 8601; priority is `0` (none), `1` (high), `5` (medium), or `9` (low) — that's how Reminders itself stores it.

## Prerequisites

- macOS (Reminders ships with the OS; the server uses `osascript`).
- Python 3.10 or newer. The system Python at `/usr/bin/python3` may be too old — use Homebrew (`brew install python@3.12`), `pyenv`, or `uv`.
- Permission for your terminal (or whatever launches the server) to control the Reminders app. macOS prompts the first time you run it; approve in **System Settings → Privacy & Security → Automation**.

## Auth model

Two independent mechanisms, both optional:

- **`REMINDERS_API_KEY`** — static bearer token. Clients send `Authorization: Bearer <key>`. Fine for curl, custom scripts, and any MCP client that lets you add an Authorization header.
- **`REMINDERS_OAUTH=1`** — OAuth 2.1 shim with Dynamic Client Registration. The server advertises RFC 9728 / RFC 8414 metadata, auto-approves `/authorize`, hands out tokens on `/token`. **Required for Claude Desktop / Cowork**, whose custom-connector UI only supports OAuth flows (no manual headers). It's a rubber stamp — the shim issues tokens to any caller who completes the dance.

You can enable both, either, or neither. If neither is set, the server runs unauthenticated, but the safety check refuses to bind to anything except loopback in that case.

Which one should you use:

| Client | Use |
| --- | --- |
| Claude Desktop / Cowork | `REMINDERS_OAUTH=1` |
| `curl`, scripts, custom agents | `REMINDERS_API_KEY=<key>` |
| Mixed | Set both |
| Localhost-only quick test | Neither |

## Quick start (Cowork / Claude Desktop — HTTPS + OAuth shim)

This is the path that works with Claude Desktop and Cowork. The server runs on `https://localhost:8765/mcp` with HTTPS via mkcert and the OAuth shim enabled, so Cowork's connector UI can complete its OAuth discovery dance.

```bash
# 1. Get the code and set up a virtualenv
git clone <your-repo-url> apple-reminders-mcp
cd apple-reminders-mcp
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Generate a locally-trusted TLS cert with mkcert
brew install mkcert nss
mkcert -install                       # installs a local CA into the system trust store
mkcert localhost 127.0.0.1 ::1        # produces localhost+2.pem and localhost+2-key.pem

# 3. Tell Electron / Node-based apps to trust the mkcert CA
#    (the macOS Keychain trust isn't enough — Node uses its own CA list)
launchctl setenv NODE_EXTRA_CA_CERTS "$(mkcert -CAROOT)/rootCA.pem"

# 4. Configure
cp .env.example .env
# Open .env and set:
#   REMINDERS_OAUTH=1
#   REMINDERS_SSL_KEYFILE=<absolute path>/localhost+2-key.pem
#   REMINDERS_SSL_CERTFILE=<absolute path>/localhost+2.pem

# 5. Fully quit Claude / Cowork (cmd+Q — not just close the window) and reopen.

# 6. Run the server
python server.py
```

You should see:

```
Apple Reminders MCP listening on https://127.0.0.1:8765
  MCP endpoint: https://127.0.0.1:8765/mcp
  Health check: https://127.0.0.1:8765/health
  Auth:         OAuth shim (auto-approve; clients get a token via /authorize)
  Discovery:    https://127.0.0.1:8765/.well-known/oauth-protected-resource
```

Verify it's up:

```bash
curl https://localhost:8765/health
# → ok
```

Then in **Settings → Connectors → Add custom connector** in Claude Desktop / Cowork:

- URL: `https://localhost:8765/mcp`
- Save and enable.

Cowork will hit `/.well-known/oauth-protected-resource`, register, walk through `/authorize` and `/token`, then call `/mcp` with the issued bearer token — all automatic. The eight tools should show up under the connector. Try `list_lists` to confirm.

## Quick start (with auth, for clients that support bearer tokens)

```bash
# steps 1 and 2 same as above

# 3. Generate an API key and save it
cp .env.example .env
python3 -c 'import secrets; print("REMINDERS_API_KEY=" + secrets.token_urlsafe(32))' >> .env
# (delete the placeholder line in .env)
# Also set REMINDERS_SSL_KEYFILE and REMINDERS_SSL_CERTFILE as above.

# 4. Run
python server.py
```

Client config: URL as above, plus an `Authorization: Bearer <key>` header.

## Quick start (public tunnel)

If you need access from off-Mac (e.g. a CI runner, a different machine, a remote agent), use Cloudflare Tunnel — it gives you a stable HTTPS URL without you owning a cert.

```bash
brew install cloudflared
cloudflared tunnel --url http://127.0.0.1:8765
```

It prints `https://<random>.trycloudflare.com`. Run the server in HTTP mode (no SSL env vars), with `REMINDERS_API_KEY` set **and `REMINDERS_ALLOWED_HOSTS=*`**, then point your client at `https://<random>.trycloudflare.com/mcp` with the bearer token. The tunnel terminates TLS for you and the token gates access.

> **Why `REMINDERS_ALLOWED_HOSTS=*`:** FastMCP's DNS-rebinding-protection middleware rejects any `Host:` header that isn't a localhost variant (HTTP 421 `Invalid Host header`), so requests arriving via the tunnel get blocked before reaching any tool. Disabling the check is safe here because the `/mcp` endpoint is still gated by the bearer token. For a named tunnel with a stable hostname, set `REMINDERS_ALLOWED_HOSTS=mcp.your-domain.com` instead of `*`.

For long-lived setups, use a named tunnel on your own domain and put Cloudflare Access OAuth in front of it.

## Running it 24/7 (launchd)

If you want the server up whenever you're logged in, the repo includes `com.user.apple-reminders-mcp.plist`. Edit the paths to match your setup, then:

```bash
cp com.user.apple-reminders-mcp.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.user.apple-reminders-mcp.plist
```

Logs go to `/tmp/apple-reminders-mcp.log` by default. To stop and unload:

```bash
launchctl unload ~/Library/LaunchAgents/com.user.apple-reminders-mcp.plist
```

## Security notes

- **Loopback-only is the right default.** Anything on your Mac can reach localhost — including web pages, in theory, via JS fetch. CORS isn't configured to allow cross-origin browser requests, so a random tab can't query your reminders. But any native process running as your user can.
- **The token is the only thing gating access when you expose this off-Mac.** Treat it like a password. Long, random, stored in `.env`, never committed.
- **`delete_reminder` is destructive and irreversible.** If you're worried about an agent going off the rails, remove the `@mcp.tool()` decorator from `delete_reminder` in `server.py` to hide it from clients.
- **No rate limiting, no audit logging, no per-tool scoping.** Single-user, single-trust-boundary design. Add a reverse proxy if you need more.

## Troubleshooting

**"Application 'Reminders' got an error: Not authorized to send Apple events to Reminders."**
First-time permission prompt was denied. **System Settings → Privacy & Security → Automation**, find the process running `python server.py`, check the "Reminders" box.

**`curl: (60) SSL certificate problem: self signed certificate`**
You ran the server with `mkcert`-generated certs, but the CA isn't trusted. Make sure you ran `mkcert -install` and restarted your terminal. For `curl`, you can also pass `--cacert "$(mkcert -CAROOT)/rootCA.pem"` to test.

**Cowork connector shows "0 tools" or fails to handshake.**
Confirm the URL has the `/mcp` path (not just root) and the scheme matches what you're serving (`https://` if SSL files are set, `http://` otherwise). Check the server logs for what request actually came in.

**`HTTP 421 Invalid Host header` from `/mcp` (only when going through a tunnel / proxy).**
FastMCP's DNS-rebinding-protection middleware allows only localhost `Host:` headers by default. The tunnel sends the public hostname, which gets rejected. Set `REMINDERS_ALLOWED_HOSTS=*` to disable the check (safe because bearer auth still gates `/mcp`), or `REMINDERS_ALLOWED_HOSTS=mcp.your-domain.com` to allow a specific hostname.

**`SystemExit: REMINDERS_HOST is '0.0.0.0' (not localhost) but REMINDERS_API_KEY is unset.`**
The safety check working as designed. Either bind to `127.0.0.1`, or set an API key.

**`SystemExit: Set both REMINDERS_SSL_KEYFILE and REMINDERS_SSL_CERTFILE, or neither.`**
You set one but not the other. Set both for HTTPS, or unset both for HTTP.

## License

MIT. Take it, ship it, modify it.
