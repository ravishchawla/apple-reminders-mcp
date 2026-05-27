#!/usr/bin/env python3
"""
Apple Reminders MCP Server (HTTP transport)

A generic Model Context Protocol server that exposes the macOS Reminders app
to MCP clients (Claude Desktop / Cowork, IDE plugins, custom agents) over HTTP
with bearer-token authentication.

Runs on the user's Mac and shells out to JavaScript for Automation (JXA) via
`osascript`. The tool surface is intentionally generic so the server can be
reused by anyone who wants programmatic access to Reminders.

Tools exposed:
  - list_lists
  - list_reminders
  - get_reminder
  - create_reminder
  - update_reminder
  - complete_reminder
  - delete_reminder
  - move_reminder

Environment variables:
  REMINDERS_API_KEY      (optional) Bearer token clients must send. If unset,
                         and OAuth is also disabled, the server runs without
                         authentication; in that case it refuses to bind to
                         anything other than localhost.
  REMINDERS_OAUTH        (optional) Set to 1/true to enable an OAuth 2.1 shim
                         (DCR + auto-approve /authorize). Required for clients
                         like Claude Desktop / Cowork that only support custom
                         MCP connectors via OAuth discovery.
  REMINDERS_HOST         (optional) Bind host. Default 127.0.0.1.
  REMINDERS_PORT         (optional) Bind port. Default 8765.
  REMINDERS_SSL_KEYFILE  (optional) Path to TLS private key (.pem). Both
  REMINDERS_SSL_CERTFILE (optional) cert + key must be set together to enable
                         HTTPS. Generate with `mkcert localhost 127.0.0.1 ::1`.
  REMINDERS_ALLOWED_HOSTS
                         (optional) Comma-separated extra Host header values
                         to accept (on top of localhost), or "*" to disable
                         host validation entirely. Required when fronting the
                         server with a tunnel / reverse proxy, otherwise
                         FastMCP rejects non-localhost Host headers with
                         HTTP 421.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import time
from typing import Any, Optional
from urllib.parse import urlencode

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, RedirectResponse
from starlette.routing import Route


# --- Configuration -----------------------------------------------------------

API_KEY = (os.environ.get("REMINDERS_API_KEY") or "").strip() or None
HOST = os.environ.get("REMINDERS_HOST", "127.0.0.1")
PORT = int(os.environ.get("REMINDERS_PORT", "8765"))
SSL_KEYFILE = (os.environ.get("REMINDERS_SSL_KEYFILE") or "").strip() or None
SSL_CERTFILE = (os.environ.get("REMINDERS_SSL_CERTFILE") or "").strip() or None
OAUTH_ENABLED = (os.environ.get("REMINDERS_OAUTH") or "").strip().lower() in ("1", "true", "yes")

# Extra Host header values to accept, on top of the localhost defaults FastMCP
# adds automatically. Required when fronting the server with a tunnel /
# reverse proxy (e.g. cloudflared), because MCP's DNS-rebinding-protection
# middleware rejects any Host header not in the allowlist with HTTP 421.
#
# Comma-separated. Bare hostnames (no port) are auto-expanded to "host:*".
# Set to "*" to disable host validation entirely — safe here because the
# /mcp endpoint is still gated by bearer-token / OAuth auth, so a malicious
# webpage can't reach the tools without the token.
ALLOWED_HOSTS_RAW = (os.environ.get("REMINDERS_ALLOWED_HOSTS") or "").strip()

_LOCALHOST_BINDS = {"127.0.0.1", "localhost", "::1"}
IS_LOCALHOST = HOST in _LOCALHOST_BINDS

# Safety guardrail: refuse to run unauthenticated on a non-localhost interface.
# Loopback-only is safe-ish without auth because only same-machine processes can
# reach it. Anything else (0.0.0.0, LAN IP, tunnel) needs a token — either a
# static API key or the OAuth shim (which auto-issues short-lived tokens but
# still requires a Bearer header on /mcp).
if not API_KEY and not OAUTH_ENABLED and not IS_LOCALHOST:
    raise SystemExit(
        f"REMINDERS_HOST is {HOST!r} (not localhost) but no auth is configured.\n"
        "Refusing to start an unauthenticated server on a non-loopback interface.\n"
        "Either bind to 127.0.0.1, set REMINDERS_API_KEY, or set REMINDERS_OAUTH=1.\n"
        "Generate a key with:\n"
        "  python3 -c 'import secrets; print(secrets.token_urlsafe(32))'"
    )

# SSL: either both files or neither.
if bool(SSL_KEYFILE) != bool(SSL_CERTFILE):
    raise SystemExit(
        "Set both REMINDERS_SSL_KEYFILE and REMINDERS_SSL_CERTFILE, or neither."
    )
USE_HTTPS = bool(SSL_KEYFILE and SSL_CERTFILE)


# --- JXA helpers -------------------------------------------------------------

# Shared JXA preamble: defines a serializer and a by-id lookup helper.
# We keep this in one place so every tool returns the same shape.
JXA_PREAMBLE = r"""
function dateToISO(d) { return d ? d.toISOString() : null; }

function serializeReminder(r, listName) {
  return {
    id: r.id(),
    name: r.name(),
    body: r.body() || "",
    completed: r.completed(),
    completionDate: dateToISO(r.completionDate()),
    creationDate: dateToISO(r.creationDate()),
    modificationDate: dateToISO(r.modificationDate()),
    dueDate: dateToISO(r.dueDate()),
    remindMeDate: dateToISO(r.remindMeDate()),
    priority: r.priority(),
    list: listName,
  };
}

function findReminderById(app, id) {
  for (const l of app.lists()) {
    for (const r of l.reminders()) {
      if (r.id() === id) return { reminder: r, list: l };
    }
  }
  return null;
}

function findListByName(app, name) {
  for (const l of app.lists()) {
    if (l.name() === name) return l;
  }
  return null;
}
"""


def _run_jxa(script: str) -> Any:
    """Run a JXA script via osascript and parse its JSON stdout."""
    try:
        result = subprocess.run(
            ["osascript", "-l", "JavaScript", "-e", script],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except FileNotFoundError:
        raise RuntimeError(
            "osascript not found. This server must run on macOS."
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError("osascript timed out after 30s")

    if result.returncode != 0:
        raise RuntimeError(
            f"osascript error: {result.stderr.strip() or 'unknown failure'}"
        )

    out = result.stdout.strip()
    if not out:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        # Some JXA expressions return bare strings/numbers without
        # JSON.stringify; surface them as raw output for debugging.
        return out


# --- MCP server --------------------------------------------------------------

# Transport security: by default FastMCP's DNS-rebinding-protection middleware
# only accepts Host headers matching localhost variants. Behind a tunnel or
# reverse proxy the upstream Host header is the public hostname, so we need
# to either add it to the allowlist or disable the check.
if ALLOWED_HOSTS_RAW == "*":
    _transport_security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
elif ALLOWED_HOSTS_RAW:
    extra = [h.strip() for h in ALLOWED_HOSTS_RAW.split(",") if h.strip()]
    expanded = []
    for h in extra:
        expanded.append(h)
        if ":" not in h:
            # Bare hostname → also accept with any port (matches FastMCP's
            # "localhost:*" wildcard convention).
            expanded.append(f"{h}:*")
    _transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=["127.0.0.1:*", "localhost:*", "[::1]:*", *expanded],
    )
else:
    _transport_security = None  # FastMCP picks its localhost-only default.

mcp = FastMCP("apple-reminders", transport_security=_transport_security)


@mcp.tool()
def list_lists() -> list[dict]:
    """List every Reminders list (folder).

    Returns:
        A list of objects with keys `id` and `name`.
    """
    script = JXA_PREAMBLE + r"""
        const app = Application('Reminders');
        const out = app.lists().map(l => ({ id: l.id(), name: l.name() }));
        JSON.stringify(out);
    """
    return _run_jxa(script) or []


@mcp.tool()
def list_reminders(
    list_name: Optional[str] = None,
    completed: Optional[bool] = None,
    search: Optional[str] = None,
    limit: Optional[int] = None,
) -> list[dict]:
    """Return reminders, optionally filtered.

    Args:
        list_name: Only include reminders from this list (exact match on name).
        completed: True for completed only, False for uncompleted only,
            None (default) for both.
        search: Case-insensitive substring search across title and body.
        limit: Cap on the number of reminders returned.

    Returns:
        Reminder objects with keys: id, name, body, completed, completionDate,
        creationDate, modificationDate, dueDate, remindMeDate, priority, list.
    """
    args = json.dumps({
        "listName": list_name,
        "completed": completed,
        "search": search.lower() if search else None,
        "limit": limit,
    })
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const out = [];
        outer: for (const l of app.lists()) {{
            if (args.listName !== null && l.name() !== args.listName) continue;
            for (const r of l.reminders()) {{
                if (args.completed !== null && r.completed() !== args.completed) continue;
                const s = serializeReminder(r, l.name());
                if (args.search !== null) {{
                    const hay = (s.name + ' ' + s.body).toLowerCase();
                    if (!hay.includes(args.search)) continue;
                }}
                out.push(s);
                if (args.limit !== null && out.length >= args.limit) break outer;
            }}
        }}
        JSON.stringify(out);
    """
    return _run_jxa(script) or []


@mcp.tool()
def get_reminder(id: str) -> Optional[dict]:
    """Fetch a single reminder by its unique id.

    Args:
        id: The reminder's `id` field as returned by other tools.

    Returns:
        The reminder object, or null if not found.
    """
    args = json.dumps({"id": id})
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const found = findReminderById(app, args.id);
        JSON.stringify(found ? serializeReminder(found.reminder, found.list.name()) : null);
    """
    return _run_jxa(script)


@mcp.tool()
def create_reminder(
    name: str,
    list_name: Optional[str] = None,
    body: Optional[str] = None,
    due_date: Optional[str] = None,
    remind_me_date: Optional[str] = None,
    priority: Optional[int] = None,
) -> dict:
    """Create a new reminder.

    Args:
        name: Title of the reminder.
        list_name: Name of the list to put it in. Defaults to the user's
            default list if omitted.
        body: Notes / description.
        due_date: ISO 8601 timestamp (e.g. "2026-06-01T15:00:00").
        remind_me_date: ISO 8601 timestamp for the alarm.
        priority: 0 = none, 1 = high, 5 = medium, 9 = low.

    Returns:
        The created reminder, serialized.
    """
    args = json.dumps({
        "name": name,
        "listName": list_name,
        "body": body,
        "dueDate": due_date,
        "remindMeDate": remind_me_date,
        "priority": priority,
    })
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        let targetList;
        if (args.listName !== null) {{
            targetList = findListByName(app, args.listName);
            if (!targetList) throw new Error('List not found: ' + args.listName);
        }} else {{
            targetList = app.defaultList();
        }}
        const props = {{ name: args.name }};
        if (args.body !== null) props.body = args.body;
        if (args.dueDate !== null) props.dueDate = new Date(args.dueDate);
        if (args.remindMeDate !== null) props.remindMeDate = new Date(args.remindMeDate);
        if (args.priority !== null) props.priority = args.priority;
        const r = app.Reminder(props);
        targetList.reminders.push(r);
        JSON.stringify(serializeReminder(r, targetList.name()));
    """
    return _run_jxa(script)


@mcp.tool()
def update_reminder(
    id: str,
    name: Optional[str] = None,
    body: Optional[str] = None,
    due_date: Optional[str] = None,
    remind_me_date: Optional[str] = None,
    priority: Optional[int] = None,
) -> dict:
    """Update fields on an existing reminder.

    Only fields you pass are written; omitted fields are left untouched.
    To clear a date, pass the string "null". To clear the body, pass "".

    Args:
        id: The reminder's id.
        name: New title.
        body: New notes (empty string clears).
        due_date: ISO 8601 timestamp, or "null" to clear.
        remind_me_date: ISO 8601 timestamp, or "null" to clear.
        priority: 0, 1, 5, or 9.

    Returns:
        The updated reminder, serialized.
    """
    args = json.dumps({
        "id": id,
        "name": name,
        "body": body,
        "dueDate": due_date,
        "remindMeDate": remind_me_date,
        "priority": priority,
    })
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const found = findReminderById(app, args.id);
        if (!found) throw new Error('Reminder not found: ' + args.id);
        const r = found.reminder;
        if (args.name !== null) r.name = args.name;
        if (args.body !== null) r.body = args.body;
        if (args.dueDate !== null) {{
            r.dueDate = (args.dueDate === 'null') ? null : new Date(args.dueDate);
        }}
        if (args.remindMeDate !== null) {{
            r.remindMeDate = (args.remindMeDate === 'null') ? null : new Date(args.remindMeDate);
        }}
        if (args.priority !== null) r.priority = args.priority;
        JSON.stringify(serializeReminder(r, found.list.name()));
    """
    return _run_jxa(script)


@mcp.tool()
def complete_reminder(id: str, completed: bool = True) -> dict:
    """Mark a reminder as completed (or un-complete it).

    Args:
        id: The reminder's id.
        completed: True to mark done (default), False to un-mark.

    Returns:
        The updated reminder.
    """
    args = json.dumps({"id": id, "completed": completed})
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const found = findReminderById(app, args.id);
        if (!found) throw new Error('Reminder not found: ' + args.id);
        found.reminder.completed = args.completed;
        JSON.stringify(serializeReminder(found.reminder, found.list.name()));
    """
    return _run_jxa(script)


@mcp.tool()
def delete_reminder(id: str) -> dict:
    """Permanently delete a reminder.

    Args:
        id: The reminder's id.

    Returns:
        `{ deleted: true, id }` on success.
    """
    args = json.dumps({"id": id})
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const found = findReminderById(app, args.id);
        if (!found) throw new Error('Reminder not found: ' + args.id);
        app.delete(found.reminder);
        JSON.stringify({{ deleted: true, id: args.id }});
    """
    return _run_jxa(script)


@mcp.tool()
def move_reminder(id: str, list_name: str) -> dict:
    """Move a reminder to a different list.

    Args:
        id: The reminder's id.
        list_name: Destination list (must already exist).

    Returns:
        The reminder after the move, with `list` set to the new list name.
    """
    args = json.dumps({"id": id, "listName": list_name})
    script = JXA_PREAMBLE + f"""
        const args = {args};
        const app = Application('Reminders');
        const found = findReminderById(app, args.id);
        if (!found) throw new Error('Reminder not found: ' + args.id);
        const target = findListByName(app, args.listName);
        if (!target) throw new Error('List not found: ' + args.listName);
        app.move(found.reminder, {{ to: target }});
        // After moving, the object reference may be stale — look it up again.
        const refreshed = findReminderById(app, args.id);
        JSON.stringify(refreshed ? serializeReminder(refreshed.reminder, refreshed.list.name()) : null);
    """
    return _run_jxa(script)


# --- HTTP transport + auth ---------------------------------------------------

# --- OAuth 2.1 shim ----------------------------------------------------------
#
# Why this exists: some MCP clients (notably Claude Desktop / Cowork) only
# support "custom" connectors via the OAuth 2.1 + Dynamic Client Registration
# discovery flow described in the MCP authorization spec. They probe
# /.well-known/oauth-protected-resource, register a client, walk through
# /authorize and /token, and only then call /mcp with a Bearer token.
#
# For a single-user local server this is theater — there's no real identity to
# verify. So this shim implements just enough of the dance to satisfy those
# clients: it auto-approves /authorize, hands out random tokens at /token, and
# accepts those tokens on /mcp.
#
# Do NOT enable this on an internet-exposed deployment. It's deliberately
# permissive. Loopback only.

_issued_tokens: set[str] = set()
_pending_codes: dict[str, dict] = {}  # code -> {redirect_uri, expires_at, ...}

_OAUTH_BYPASS_PATHS = ("/register", "/authorize", "/token")


def _base_url_for(request: Request) -> str:
    """Externally-visible base URL, honoring reverse-proxy headers."""
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host")
    if host:
        return f"{proto}://{host}"
    return f"{request.url.scheme}://{request.url.netloc}"


async def oauth_protected_resource(request: Request):
    """RFC 9728 — Protected Resource Metadata."""
    base = _base_url_for(request)
    return JSONResponse({
        "resource": base,
        "authorization_servers": [base],
        "bearer_methods_supported": ["header"],
        "scopes_supported": [],
    })


async def oauth_authorization_server(request: Request):
    """RFC 8414 — Authorization Server Metadata."""
    base = _base_url_for(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": f"{base}/authorize",
        "token_endpoint": f"{base}/token",
        "registration_endpoint": f"{base}/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": ["none"],
    })


async def oauth_register(request: Request):
    """RFC 7591 — Dynamic Client Registration. Issues a static client_id."""
    body: dict = {}
    try:
        if (await request.body()):
            body = await request.json()
    except Exception:
        body = {}
    redirect_uris = body.get("redirect_uris", [])
    return JSONResponse({
        "client_id": "apple-reminders-mcp-client",
        "client_id_issued_at": int(time.time()),
        "redirect_uris": redirect_uris,
        "grant_types": ["authorization_code"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
        "application_type": "native",
    })


async def oauth_authorize(request: Request):
    """OAuth 2.1 authorization endpoint — auto-approves, no UI."""
    params = dict(request.query_params)
    redirect_uri = params.get("redirect_uri")
    if not redirect_uri:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "missing redirect_uri"},
            status_code=400,
        )
    code = secrets.token_urlsafe(24)
    _pending_codes[code] = {
        "client_id": params.get("client_id"),
        "redirect_uri": redirect_uri,
        "code_challenge": params.get("code_challenge"),
        "expires_at": time.time() + 300,
    }
    qs = {"code": code}
    if params.get("state"):
        qs["state"] = params["state"]
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(f"{redirect_uri}{sep}{urlencode(qs)}", status_code=302)


async def oauth_token(request: Request):
    """OAuth 2.1 token endpoint — exchanges auth code for access token."""
    form = await request.form()
    grant_type = form.get("grant_type")
    if grant_type != "authorization_code":
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    code = form.get("code")
    if not code or code not in _pending_codes:
        return JSONResponse({"error": "invalid_grant"}, status_code=400)
    entry = _pending_codes.pop(code)
    if entry["expires_at"] < time.time():
        return JSONResponse(
            {"error": "invalid_grant", "error_description": "code expired"},
            status_code=400,
        )
    token = secrets.token_urlsafe(32)
    _issued_tokens.add(token)
    return JSONResponse({
        "access_token": token,
        "token_type": "Bearer",
        "expires_in": 86400,
    })


# --- HTTP transport + auth ---------------------------------------------------

class HealthMiddleware(BaseHTTPMiddleware):
    """Short-circuit /health to a 200 OK, no auth required."""

    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            return PlainTextResponse("ok")
        return await call_next(request)


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Validate Bearer tokens on protected endpoints.

    Accepts:
      - REMINDERS_API_KEY (if set) as a long-lived static token
      - Any token previously issued by the OAuth /token endpoint

    Bypasses auth for /.well-known/* discovery and OAuth flow endpoints
    (/register, /authorize, /token) so the discovery dance can complete.

    On 401, includes a WWW-Authenticate header pointing at the resource
    metadata so OAuth-aware clients know how to start the flow.
    """

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/.well-known/") or path in _OAUTH_BYPASS_PATHS:
            return await call_next(request)

        auth = request.headers.get("authorization", "")
        token = None
        if auth.lower().startswith("bearer "):
            token = auth.split(" ", 1)[1].strip()

        valid = False
        if token:
            if API_KEY and token == API_KEY:
                valid = True
            elif token in _issued_tokens:
                valid = True

        if not valid:
            headers = {}
            if OAUTH_ENABLED:
                base = _base_url_for(request)
                headers["WWW-Authenticate"] = (
                    f'Bearer resource_metadata="{base}/.well-known/oauth-protected-resource"'
                )
            return JSONResponse({"error": "unauthorized"}, status_code=401, headers=headers)

        return await call_next(request)


def build_app():
    app = mcp.streamable_http_app()

    if OAUTH_ENABLED:
        # OAuth metadata + flow endpoints. Inserted at the front of the route
        # list so they take precedence over FastMCP's catch-all.
        oauth_routes = [
            Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
            Route("/.well-known/oauth-protected-resource/mcp", oauth_protected_resource, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server", oauth_authorization_server, methods=["GET"]),
            Route("/.well-known/oauth-authorization-server/mcp", oauth_authorization_server, methods=["GET"]),
            Route("/register", oauth_register, methods=["POST"]),
            Route("/authorize", oauth_authorize, methods=["GET"]),
            Route("/token", oauth_token, methods=["POST"]),
        ]
        for r in reversed(oauth_routes):
            app.router.routes.insert(0, r)

    # Auth is enforced if either API_KEY or OAuth is active.
    if API_KEY or OAUTH_ENABLED:
        app.add_middleware(BearerAuthMiddleware)

    # HealthMiddleware is added last so it runs first (Starlette wraps LIFO).
    app.add_middleware(HealthMiddleware)
    return app


if __name__ == "__main__":
    import uvicorn

    scheme = "https" if USE_HTTPS else "http"
    if OAUTH_ENABLED and API_KEY:
        auth_status = "OAuth shim + static API key (both accepted)"
    elif OAUTH_ENABLED:
        auth_status = "OAuth shim (auto-approve; clients get a token via /authorize)"
    elif API_KEY:
        auth_status = "Bearer token required"
    else:
        auth_status = "DISABLED (no API key, no OAuth)"
    print(f"Apple Reminders MCP listening on {scheme}://{HOST}:{PORT}")
    print(f"  MCP endpoint: {scheme}://{HOST}:{PORT}/mcp")
    print(f"  Health check: {scheme}://{HOST}:{PORT}/health")
    print(f"  Auth:         {auth_status}")
    if OAUTH_ENABLED:
        print(f"  Discovery:    {scheme}://{HOST}:{PORT}/.well-known/oauth-protected-resource")
    if not API_KEY and not OAUTH_ENABLED and IS_LOCALHOST:
        print("  (Loopback-only bind; only same-machine processes can reach this.)")

    uvicorn_kwargs = dict(host=HOST, port=PORT, log_level="info")
    if USE_HTTPS:
        uvicorn_kwargs["ssl_keyfile"] = SSL_KEYFILE
        uvicorn_kwargs["ssl_certfile"] = SSL_CERTFILE
    uvicorn.run(build_app(), **uvicorn_kwargs)
