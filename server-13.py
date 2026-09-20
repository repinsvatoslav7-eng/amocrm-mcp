import asyncio
import base64
import hashlib
import hmac
import html
import json
import os
import secrets
import time
from collections import deque
from typing import Any, Literal
from urllib.parse import parse_qs, urlencode, urlparse

import httpx
from mcp.server import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse

SERVER_NAME = "YaMebel amoCRM MCP"
BASE_URL = os.getenv("AMOCRM_BASE_URL", "").rstrip("/")
ACCESS_TOKEN = os.getenv("AMOCRM_ACCESS_TOKEN", "").strip()
MCP_SECRET = os.getenv("MCP_SECRET", "").strip()
WRITE_ENABLED = os.getenv("WRITE_ENABLED", "true").lower() in {"1", "true", "yes", "on"}
DANGEROUS_WRITE_ENABLED = os.getenv("DANGEROUS_WRITE_ENABLED", "false").lower() in {"1", "true", "yes", "on"}
ALLOW_INSECURE_MCP = os.getenv("ALLOW_INSECURE_MCP", "false").lower() in {"1", "true", "yes", "on"}
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "30"))
MAX_RETRIES = int(os.getenv("MAX_RETRIES", "4"))
RATE_LIMIT_RPS = float(os.getenv("RATE_LIMIT_RPS", "6"))
MAX_RESPONSE_CHARS = int(os.getenv("MAX_RESPONSE_CHARS", "180000"))
OAUTH_ACCESS_TTL = int(os.getenv("OAUTH_ACCESS_TTL", "3600"))
OAUTH_REFRESH_TTL = int(os.getenv("OAUTH_REFRESH_TTL", str(60 * 60 * 24 * 30)))
OAUTH_CODE_TTL = int(os.getenv("OAUTH_CODE_TTL", "300"))

if not BASE_URL:
    raise RuntimeError("AMOCRM_BASE_URL is required, e.g. https://example.amocrm.ru")
if not ACCESS_TOKEN:
    raise RuntimeError("AMOCRM_ACCESS_TOKEN is required")
if not MCP_SECRET and not ALLOW_INSECURE_MCP:
    raise RuntimeError("MCP_SECRET is required unless ALLOW_INSECURE_MCP=true")

parsed_base = urlparse(BASE_URL)
if parsed_base.scheme != "https" or not parsed_base.netloc:
    raise RuntimeError("AMOCRM_BASE_URL must be an https URL")

mcp = MCPServer(
    SERVER_NAME,
    instructions=(
        "Full amoCRM connector for Ya Mebel. Read tools are safe. Write tools mutate CRM data. "
        "Deletion/destructive tools require both DANGEROUS_WRITE_ENABLED=true and confirm=true. "
        "Never expose AMOCRM_ACCESS_TOKEN or MCP_SECRET in tool output."
    ),
)

_AUDIT: deque[dict[str, Any]] = deque(maxlen=500)
_rate_lock = asyncio.Lock()
_last_request_at = 0.0


def _now() -> int:
    return int(time.time())


def _audit(method: str, path: str, status: int | None, duration_ms: int, ok: bool, note: str = "") -> None:
    _AUDIT.append({
        "ts": _now(),
        "method": method,
        "path": path,
        "status": status,
        "duration_ms": duration_ms,
        "ok": ok,
        "note": note[:300],
    })


def _require_write() -> None:
    if not WRITE_ENABLED:
        raise RuntimeError("Writes are disabled. Set WRITE_ENABLED=true on Render.")


def _require_dangerous(confirm: bool) -> None:
    _require_write()
    if not DANGEROUS_WRITE_ENABLED:
        raise RuntimeError("Dangerous writes are disabled. Set DANGEROUS_WRITE_ENABLED=true on Render.")
    if not confirm:
        raise RuntimeError("Destructive operation requires confirm=true.")


def _safe_api_path(path: str) -> str:
    if not isinstance(path, str):
        raise ValueError("path must be a string")
    path = path.strip()
    if not path.startswith("/"):
        path = "/" + path
    if not path.startswith("/api/v4/") and path != "/api/v4/account":
        raise ValueError("Only amoCRM /api/v4/* endpoints are allowed by the generic API tools")
    if "://" in path or ".." in path:
        raise ValueError("Invalid path")
    return path


def _safe_entity_type(entity_type: str) -> str:
    allowed = {"leads", "contacts", "companies", "customers"}
    if entity_type not in allowed:
        raise ValueError(f"entity_type must be one of {sorted(allowed)}")
    return entity_type


def _safe_cf_entity(entity_type: str) -> str:
    allowed = {"leads", "contacts", "companies", "customers"}
    if entity_type not in allowed:
        raise ValueError(f"entity_type must be one of {sorted(allowed)}")
    return entity_type


def _flatten_params(params: dict[str, Any] | None) -> list[tuple[str, str]]:
    if not params:
        return []
    out: list[tuple[str, str]] = []

    def walk(prefix: str, value: Any) -> None:
        if value is None:
            return
        if isinstance(value, bool):
            out.append((prefix, "1" if value else "0"))
        elif isinstance(value, (str, int, float)):
            out.append((prefix, str(value)))
        elif isinstance(value, dict):
            for k, v in value.items():
                key = f"{prefix}[{k}]" if prefix else str(k)
                walk(key, v)
        elif isinstance(value, (list, tuple)):
            for item in value:
                if isinstance(item, dict):
                    # amoCRM accepts indexed nested objects in filters.
                    idx = sum(1 for k, _ in out if k.startswith(prefix + "["))
                    walk(f"{prefix}[{idx}]", item)
                else:
                    walk(prefix + "[]", item)
        else:
            out.append((prefix, str(value)))

    for key, value in params.items():
        walk(str(key), value)
    return out


async def _pace() -> None:
    global _last_request_at
    if RATE_LIMIT_RPS <= 0:
        return
    interval = 1.0 / RATE_LIMIT_RPS
    async with _rate_lock:
        now = time.monotonic()
        wait = interval - (now - _last_request_at)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_request_at = time.monotonic()


def _headers(content_type: str = "application/json") -> dict[str, str]:
    return {
        "Authorization": f"Bearer {ACCESS_TOKEN}",
        "Accept": "application/json",
        "Content-Type": content_type,
        "User-Agent": "YaMebel-amocrm-mcp/1.0",
    }


def _response_payload(resp: httpx.Response) -> Any:
    if resp.status_code == 204 or not resp.content:
        return {"ok": True, "status_code": resp.status_code}
    ctype = resp.headers.get("content-type", "")
    if "json" in ctype:
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
    else:
        data = {"raw": resp.text}
    # Avoid an accidental gigantic tool result.
    encoded = json.dumps(data, ensure_ascii=False, default=str)
    if len(encoded) > MAX_RESPONSE_CHARS:
        return {
            "ok": True,
            "status_code": resp.status_code,
            "truncated": True,
            "preview": encoded[:MAX_RESPONSE_CHARS],
        }
    return data


async def _request(
    method: str,
    path: str,
    *,
    params: dict[str, Any] | None = None,
    json_body: Any = None,
    absolute_url: str | None = None,
    content: bytes | None = None,
    content_type: str = "application/json",
) -> Any:
    method = method.upper()
    url = absolute_url or (BASE_URL + path)
    started = time.monotonic()
    last_error: Exception | None = None

    for attempt in range(MAX_RETRIES + 1):
        await _pace()
        try:
            async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=False) as client:
                resp = await client.request(
                    method,
                    url,
                    params=_flatten_params(params),
                    json=json_body if content is None else None,
                    content=content,
                    headers=_headers(content_type),
                )
            if resp.status_code == 429 and attempt < MAX_RETRIES:
                retry_after = resp.headers.get("Retry-After")
                try:
                    delay = float(retry_after) if retry_after else min(8.0, 0.7 * (2 ** attempt))
                except ValueError:
                    delay = min(8.0, 0.7 * (2 ** attempt))
                await asyncio.sleep(max(delay, 0.5))
                continue
            if resp.status_code >= 500 and attempt < MAX_RETRIES:
                await asyncio.sleep(min(8.0, 0.5 * (2 ** attempt)))
                continue
            if resp.is_error:
                payload = _response_payload(resp)
                duration = int((time.monotonic() - started) * 1000)
                _audit(method, path or urlparse(url).path, resp.status_code, duration, False, str(payload))
                raise RuntimeError(f"amoCRM API {resp.status_code}: {json.dumps(payload, ensure_ascii=False)[:3000]}")
            duration = int((time.monotonic() - started) * 1000)
            _audit(method, path or urlparse(url).path, resp.status_code, duration, True)
            return _response_payload(resp)
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            last_error = exc
            if attempt >= MAX_RETRIES:
                break
            await asyncio.sleep(min(8.0, 0.5 * (2 ** attempt)))

    duration = int((time.monotonic() - started) * 1000)
    _audit(method, path or urlparse(url).path, None, duration, False, repr(last_error))
    raise RuntimeError(f"amoCRM request failed after retries: {last_error!r}")


# -------------------- Health / generic API --------------------

@mcp.tool()
async def amo_health_check() -> dict[str, Any]:
    """Check amoCRM connectivity, account access, write flags and connector status."""
    account = await _request("GET", "/api/v4/account", params={"with": "amojo_id,amojo_rights,users_groups,task_types,version"})
    return {
        "ok": True,
        "server": SERVER_NAME,
        "base_url": BASE_URL,
        "write_enabled": WRITE_ENABLED,
        "dangerous_write_enabled": DANGEROUS_WRITE_ENABLED,
        "account": account,
    }


@mcp.tool()
async def amo_api_get(path: str, params: dict[str, Any] | None = None) -> Any:
    """Universal READ tool for any amoCRM API v4 endpoint under this account."""
    return await _request("GET", _safe_api_path(path), params=params)


@mcp.tool()
async def amo_api_post(path: str, body: Any, params: dict[str, Any] | None = None) -> Any:
    """Universal CREATE/ACTION tool for any amoCRM API v4 endpoint. Mutates CRM data."""
    _require_write()
    return await _request("POST", _safe_api_path(path), params=params, json_body=body)


@mcp.tool()
async def amo_api_patch(path: str, body: Any, params: dict[str, Any] | None = None) -> Any:
    """Universal UPDATE tool for any amoCRM API v4 endpoint. Mutates CRM data."""
    _require_write()
    return await _request("PATCH", _safe_api_path(path), params=params, json_body=body)


@mcp.tool()
async def amo_api_delete(path: str, body: Any | None = None, confirm: bool = False) -> Any:
    """Universal DELETE tool for amoCRM API v4. Requires dangerous writes enabled and confirm=true."""
    _require_dangerous(confirm)
    return await _request("DELETE", _safe_api_path(path), json_body=body)


@mcp.tool()
async def amo_audit_tail(limit: int = 50) -> list[dict[str, Any]]:
    """Return recent connector request metadata. Payloads and secrets are not logged."""
    limit = max(1, min(limit, 500))
    return list(_AUDIT)[-limit:]


# -------------------- Account / users / events --------------------

@mcp.tool()
async def amo_get_account(with_: str | None = None) -> Any:
    """Get amoCRM account properties. Use with_ for optional embedded account data."""
    return await _request("GET", "/api/v4/account", params={"with": with_} if with_ else None)


@mcp.tool()
async def amo_list_users(page: int = 1, limit: int = 250, with_: str | None = None) -> Any:
    """List amoCRM users."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if with_: params["with"] = with_
    return await _request("GET", "/api/v4/users", params=params)


@mcp.tool()
async def amo_get_user(user_id: int) -> Any:
    """Get one amoCRM user by ID."""
    return await _request("GET", f"/api/v4/users/{user_id}")


@mcp.tool()
async def amo_list_events(params: dict[str, Any] | None = None) -> Any:
    """Read CRM event history with amoCRM filters. Pass raw API v4 event query params."""
    return await _request("GET", "/api/v4/events", params=params)


# -------------------- Pipelines --------------------

@mcp.tool()
async def amo_list_pipelines() -> Any:
    """List lead pipelines and their statuses."""
    return await _request("GET", "/api/v4/leads/pipelines")


@mcp.tool()
async def amo_get_pipeline(pipeline_id: int) -> Any:
    """Get one lead pipeline including statuses."""
    return await _request("GET", f"/api/v4/leads/pipelines/{pipeline_id}")


@mcp.tool()
async def amo_create_pipeline(payload: dict[str, Any]) -> Any:
    """Create a lead pipeline. Admin permissions may be required."""
    _require_write()
    return await _request("POST", "/api/v4/leads/pipelines", json_body=[payload])


@mcp.tool()
async def amo_update_pipeline(pipeline_id: int, payload: dict[str, Any]) -> Any:
    """Update a lead pipeline or its embedded settings/statuses per amoCRM API model."""
    _require_write()
    return await _request("PATCH", f"/api/v4/leads/pipelines/{pipeline_id}", json_body=payload)


@mcp.tool()
async def amo_delete_pipeline(pipeline_id: int, confirm: bool = False) -> Any:
    """Delete a lead pipeline. Destructive; requires dangerous writes and confirm=true."""
    _require_dangerous(confirm)
    return await _request("DELETE", f"/api/v4/leads/pipelines/{pipeline_id}")


# -------------------- Leads --------------------

@mcp.tool()
async def amo_list_leads(
    query: str | None = None,
    pipeline_id: int | None = None,
    status_id: int | None = None,
    responsible_user_id: int | None = None,
    page: int = 1,
    limit: int = 250,
    with_: str | None = None,
) -> Any:
    """List/search leads with common filters."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    if with_: params["with"] = with_
    filt: dict[str, Any] = {}
    if pipeline_id is not None: filt["pipeline_id"] = pipeline_id
    if status_id is not None: filt["statuses"] = [{"status_id": status_id, **({"pipeline_id": pipeline_id} if pipeline_id else {})}]
    if responsible_user_id is not None: filt["responsible_user_id"] = responsible_user_id
    if filt: params["filter"] = filt
    return await _request("GET", "/api/v4/leads", params=params)


@mcp.tool()
async def amo_get_lead(lead_id: int, with_: str | None = "contacts,companies,catalog_elements") -> Any:
    """Get a full lead card by ID with optional linked entities."""
    params = {"with": with_} if with_ else None
    return await _request("GET", f"/api/v4/leads/{lead_id}", params=params)


@mcp.tool()
async def amo_create_lead(payload: dict[str, Any]) -> Any:
    """Create one lead. Payload follows amoCRM API v4 lead model."""
    _require_write()
    return await _request("POST", "/api/v4/leads", json_body=[payload])


@mcp.tool()
async def amo_create_leads(payloads: list[dict[str, Any]]) -> Any:
    """Batch-create leads."""
    _require_write()
    return await _request("POST", "/api/v4/leads", json_body=payloads)


@mcp.tool()
async def amo_create_lead_complex(payload: dict[str, Any]) -> Any:
    """Create a lead together with contacts/company using amoCRM complex lead creation."""
    _require_write()
    return await _request("POST", "/api/v4/leads/complex", json_body=[payload])


@mcp.tool()
async def amo_update_lead(lead_id: int, payload: dict[str, Any]) -> Any:
    """Update one lead: name, price, pipeline/status, responsible, custom fields, tags, etc."""
    _require_write()
    return await _request("PATCH", f"/api/v4/leads/{lead_id}", json_body=payload)


@mcp.tool()
async def amo_update_leads(payloads: list[dict[str, Any]]) -> Any:
    """Batch-update leads; each object must contain id."""
    _require_write()
    return await _request("PATCH", "/api/v4/leads", json_body=payloads)


# -------------------- Contacts / companies --------------------

@mcp.tool()
async def amo_list_contacts(query: str | None = None, page: int = 1, limit: int = 250, with_: str | None = None) -> Any:
    """List/search contacts, including search by phone/email where amoCRM query matching supports it."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    if with_: params["with"] = with_
    return await _request("GET", "/api/v4/contacts", params=params)


@mcp.tool()
async def amo_get_contact(contact_id: int, with_: str | None = "leads,companies,customers,catalog_elements") -> Any:
    """Get one contact by ID."""
    return await _request("GET", f"/api/v4/contacts/{contact_id}", params={"with": with_} if with_ else None)


@mcp.tool()
async def amo_create_contact(payload: dict[str, Any]) -> Any:
    """Create one contact."""
    _require_write()
    return await _request("POST", "/api/v4/contacts", json_body=[payload])


@mcp.tool()
async def amo_update_contact(contact_id: int, payload: dict[str, Any]) -> Any:
    """Update one contact, including custom fields such as phone/email."""
    _require_write()
    return await _request("PATCH", f"/api/v4/contacts/{contact_id}", json_body=payload)


@mcp.tool()
async def amo_list_companies(query: str | None = None, page: int = 1, limit: int = 250, with_: str | None = None) -> Any:
    """List/search companies."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    if with_: params["with"] = with_
    return await _request("GET", "/api/v4/companies", params=params)


@mcp.tool()
async def amo_get_company(company_id: int, with_: str | None = "leads,contacts,customers,catalog_elements") -> Any:
    """Get one company by ID."""
    return await _request("GET", f"/api/v4/companies/{company_id}", params={"with": with_} if with_ else None)


@mcp.tool()
async def amo_create_company(payload: dict[str, Any]) -> Any:
    """Create one company."""
    _require_write()
    return await _request("POST", "/api/v4/companies", json_body=[payload])


@mcp.tool()
async def amo_update_company(company_id: int, payload: dict[str, Any]) -> Any:
    """Update one company."""
    _require_write()
    return await _request("PATCH", f"/api/v4/companies/{company_id}", json_body=payload)


# -------------------- Tasks --------------------

@mcp.tool()
async def amo_list_tasks(params: dict[str, Any] | None = None) -> Any:
    """List tasks with raw amoCRM API v4 filters."""
    return await _request("GET", "/api/v4/tasks", params=params)


@mcp.tool()
async def amo_get_task(task_id: int) -> Any:
    """Get one task by ID."""
    return await _request("GET", f"/api/v4/tasks/{task_id}")


@mcp.tool()
async def amo_create_task(payload: dict[str, Any]) -> Any:
    """Create one task. text and complete_till are required by amoCRM."""
    _require_write()
    return await _request("POST", "/api/v4/tasks", json_body=[payload])


@mcp.tool()
async def amo_update_task(task_id: int, payload: dict[str, Any]) -> Any:
    """Update one task."""
    _require_write()
    return await _request("PATCH", f"/api/v4/tasks/{task_id}", json_body=payload)


@mcp.tool()
async def amo_complete_task(task_id: int, result_text: str = "Выполнено") -> Any:
    """Mark a task completed and optionally set result text."""
    _require_write()
    return await _request("PATCH", f"/api/v4/tasks/{task_id}", json_body={"is_completed": True, "result": {"text": result_text}})


# -------------------- Notes / links --------------------

@mcp.tool()
async def amo_list_notes(entity_type: str, entity_id: int | None = None, page: int = 1, limit: int = 250) -> Any:
    """List notes for leads, contacts, companies or customers."""
    entity_type = _safe_entity_type(entity_type)
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if entity_id is not None:
        params["filter"] = {"entity_id": [entity_id]}
    return await _request("GET", f"/api/v4/{entity_type}/notes", params=params)


@mcp.tool()
async def amo_add_note(entity_type: str, entity_id: int, note_type: str, params: dict[str, Any]) -> Any:
    """Add a note to a lead/contact/company/customer. Example note_type=common with params={text: ...}."""
    _require_write()
    entity_type = _safe_entity_type(entity_type)
    body = [{"note_type": note_type, "params": params}]
    return await _request("POST", f"/api/v4/{entity_type}/{entity_id}/notes", json_body=body)


@mcp.tool()
async def amo_list_links(entity_type: str, entity_id: int) -> Any:
    """List entities linked to a lead/contact/company/customer."""
    entity_type = _safe_entity_type(entity_type)
    return await _request("GET", f"/api/v4/{entity_type}/{entity_id}/links")


@mcp.tool()
async def amo_link_entities(entity_type: str, entity_id: int, links: list[dict[str, Any]]) -> Any:
    """Link contacts, companies, leads, customers or catalog elements to an entity."""
    _require_write()
    entity_type = _safe_entity_type(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/{entity_id}/link", json_body=links)


@mcp.tool()
async def amo_unlink_entities(entity_type: str, links: list[dict[str, Any]]) -> Any:
    """Bulk-unlink entities. Each object follows amoCRM unlink model and includes entity_id."""
    _require_write()
    entity_type = _safe_entity_type(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/unlink", json_body=links)


# -------------------- Custom fields / groups / tags --------------------

@mcp.tool()
async def amo_list_custom_fields(entity_type: str, page: int = 1, limit: int = 50) -> Any:
    """List custom fields for leads, contacts, companies or customers."""
    entity_type = _safe_cf_entity(entity_type)
    return await _request("GET", f"/api/v4/{entity_type}/custom_fields", params={"page": page, "limit": min(limit, 50)})


@mcp.tool()
async def amo_get_custom_field(entity_type: str, field_id: int) -> Any:
    """Get one custom field."""
    entity_type = _safe_cf_entity(entity_type)
    return await _request("GET", f"/api/v4/{entity_type}/custom_fields/{field_id}")


@mcp.tool()
async def amo_create_custom_fields(entity_type: str, fields: list[dict[str, Any]]) -> Any:
    """Create custom fields. amoCRM requires administrator rights."""
    _require_write()
    entity_type = _safe_cf_entity(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/custom_fields", json_body=fields)


@mcp.tool()
async def amo_update_custom_field(entity_type: str, field_id: int, payload: dict[str, Any]) -> Any:
    """Update one custom field. Admin rights may be required."""
    _require_write()
    entity_type = _safe_cf_entity(entity_type)
    return await _request("PATCH", f"/api/v4/{entity_type}/custom_fields/{field_id}", json_body=payload)


@mcp.tool()
async def amo_delete_custom_field(entity_type: str, field_id: int, confirm: bool = False) -> Any:
    """Delete a custom field. Destructive; requires dangerous writes and confirm=true."""
    _require_dangerous(confirm)
    entity_type = _safe_cf_entity(entity_type)
    return await _request("DELETE", f"/api/v4/{entity_type}/custom_fields/{field_id}")


@mcp.tool()
async def amo_list_field_groups(entity_type: str) -> Any:
    """List custom-field groups."""
    entity_type = _safe_cf_entity(entity_type)
    return await _request("GET", f"/api/v4/{entity_type}/custom_fields/groups")


@mcp.tool()
async def amo_create_field_groups(entity_type: str, groups: list[dict[str, Any]]) -> Any:
    """Create custom-field groups. Admin rights may be required."""
    _require_write()
    entity_type = _safe_cf_entity(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/custom_fields/groups", json_body=groups)


@mcp.tool()
async def amo_list_tags(entity_type: str, query: str | None = None, page: int = 1, limit: int = 250) -> Any:
    """List tags for leads, contacts, companies or customers."""
    entity_type = _safe_entity_type(entity_type)
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    return await _request("GET", f"/api/v4/{entity_type}/tags", params=params)


@mcp.tool()
async def amo_create_tags(entity_type: str, tags: list[dict[str, Any]]) -> Any:
    """Create tags for leads, contacts, companies or customers."""
    _require_write()
    entity_type = _safe_entity_type(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/tags", json_body=tags)


# -------------------- Webhooks --------------------

@mcp.tool()
async def amo_list_webhooks(destination: str | None = None) -> Any:
    """List installed account webhooks. Admin rights are required by amoCRM."""
    params = {"filter": {"destination": destination}} if destination else None
    return await _request("GET", "/api/v4/webhooks", params=params)


@mcp.tool()
async def amo_subscribe_webhook(destination: str, settings: list[str], sort: int = 10) -> Any:
    """Create or update a webhook subscription. Admin rights are required by amoCRM."""
    _require_write()
    return await _request("POST", "/api/v4/webhooks", json_body={"destination": destination, "settings": settings, "sort": sort})


@mcp.tool()
async def amo_unsubscribe_webhook(destination: str, confirm: bool = False) -> Any:
    """Delete a webhook subscription by exact destination. Destructive."""
    _require_dangerous(confirm)
    return await _request("DELETE", "/api/v4/webhooks", json_body={"destination": destination})


# -------------------- Sources / loss reasons / catalogs / customers / unsorted --------------------

@mcp.tool()
async def amo_list_sources(page: int = 1, limit: int = 250) -> Any:
    """List amoCRM sources available through API v4."""
    return await _request("GET", "/api/v4/sources", params={"page": page, "limit": min(limit, 250)})


@mcp.tool()
async def amo_list_loss_reasons(page: int = 1, limit: int = 250) -> Any:
    """List lead loss reasons."""
    return await _request("GET", "/api/v4/leads/loss_reasons", params={"page": page, "limit": min(limit, 250)})


@mcp.tool()
async def amo_list_catalogs(page: int = 1, limit: int = 250) -> Any:
    """List catalogs/lists."""
    return await _request("GET", "/api/v4/catalogs", params={"page": page, "limit": min(limit, 250)})


@mcp.tool()
async def amo_list_catalog_elements(catalog_id: int, query: str | None = None, page: int = 1, limit: int = 250) -> Any:
    """List/search elements in a catalog."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    return await _request("GET", f"/api/v4/catalogs/{catalog_id}/elements", params=params)


@mcp.tool()
async def amo_create_catalog_elements(catalog_id: int, elements: list[dict[str, Any]]) -> Any:
    """Create catalog elements."""
    _require_write()
    return await _request("POST", f"/api/v4/catalogs/{catalog_id}/elements", json_body=elements)


@mcp.tool()
async def amo_update_catalog_elements(catalog_id: int, elements: list[dict[str, Any]]) -> Any:
    """Batch-update catalog elements."""
    _require_write()
    return await _request("PATCH", f"/api/v4/catalogs/{catalog_id}/elements", json_body=elements)


@mcp.tool()
async def amo_list_customers(query: str | None = None, page: int = 1, limit: int = 250) -> Any:
    """List/search customers."""
    params: dict[str, Any] = {"page": page, "limit": min(limit, 250)}
    if query: params["query"] = query
    return await _request("GET", "/api/v4/customers", params=params)


@mcp.tool()
async def amo_create_customer(payload: dict[str, Any]) -> Any:
    """Create one customer."""
    _require_write()
    return await _request("POST", "/api/v4/customers", json_body=[payload])


@mcp.tool()
async def amo_update_customer(customer_id: int, payload: dict[str, Any]) -> Any:
    """Update one customer."""
    _require_write()
    return await _request("PATCH", f"/api/v4/customers/{customer_id}", json_body=payload)


@mcp.tool()
async def amo_list_unsorted(params: dict[str, Any] | None = None) -> Any:
    """List unsorted leads (incoming unprocessed entities) using raw filters."""
    return await _request("GET", "/api/v4/leads/unsorted", params=params)


@mcp.tool()
async def amo_accept_unsorted(uid: str, user_id: int | None = None, status_id: int | None = None) -> Any:
    """Accept one unsorted item. Optional user/status routing is passed when supplied."""
    _require_write()
    body: dict[str, Any] = {"uid": uid}
    if user_id is not None: body["user_id"] = user_id
    if status_id is not None: body["status_id"] = status_id
    return await _request("POST", f"/api/v4/leads/unsorted/{uid}/accept", json_body={k: v for k, v in body.items() if k != "uid"})


@mcp.tool()
async def amo_decline_unsorted(uid: str, user_id: int | None = None, confirm: bool = False) -> Any:
    """Decline an unsorted item. This discards an incoming item and requires destructive confirmation."""
    _require_dangerous(confirm)
    body = {"user_id": user_id} if user_id is not None else {}
    return await _request("DELETE", f"/api/v4/leads/unsorted/{uid}/decline", json_body=body)


# -------------------- Files API --------------------

async def _drive_url() -> str:
    account = await _request("GET", "/api/v4/account", params={"with": "drive_url"})
    candidates = []
    if isinstance(account, dict):
        candidates.extend([
            account.get("drive_url"),
            (account.get("_embedded") or {}).get("drive_url") if isinstance(account.get("_embedded"), dict) else None,
        ])
    for candidate in candidates:
        if isinstance(candidate, str) and candidate.startswith("https://"):
            return candidate.rstrip("/")
    raise RuntimeError("amoCRM account response did not contain drive_url. Ensure file scope is enabled.")


async def _drive_request(method: str, path: str, *, params: dict[str, Any] | None = None, body: Any = None, content: bytes | None = None, content_type: str = "application/json") -> Any:
    if not path.startswith("/v1.0/") or ".." in path or "://" in path:
        raise ValueError("Drive path must start with /v1.0/")
    drive = await _drive_url()
    return await _request(method, path, params=params, json_body=body, absolute_url=drive + path, content=content, content_type=content_type)


@mcp.tool()
async def amo_list_files(params: dict[str, Any] | None = None) -> Any:
    """List/search files in amoCRM file service. Integration needs file-access scope."""
    return await _drive_request("GET", "/v1.0/files", params=params)


@mcp.tool()
async def amo_get_file(file_uuid: str) -> Any:
    """Get file metadata by UUID."""
    return await _drive_request("GET", f"/v1.0/files/{file_uuid}")


@mcp.tool()
async def amo_upload_file_base64(file_name: str, content_base64: str, content_type: str = "application/octet-stream", with_preview: bool = False, file_uuid: str | None = None) -> Any:
    """Upload a file to amoCRM from base64 using the official chunked file API."""
    _require_write()
    try:
        raw = base64.b64decode(content_base64, validate=True)
    except Exception as exc:
        raise ValueError(f"Invalid base64: {exc}") from exc
    drive = await _drive_url()
    session_payload: dict[str, Any] = {
        "file_name": file_name,
        "file_size": len(raw),
        "content_type": content_type,
        "with_preview": with_preview,
    }
    if file_uuid:
        session_payload["file_uuid"] = file_uuid
    session = await _request("POST", "/v1.0/sessions", absolute_url=drive + "/v1.0/sessions", json_body=session_payload)
    if not isinstance(session, dict) or not session.get("upload_url"):
        raise RuntimeError(f"Unexpected upload-session response: {session}")
    max_part = int(session.get("max_part_size") or 524288)
    upload_url = str(session["upload_url"])
    offset = 0
    last: Any = None
    while offset < len(raw):
        chunk = raw[offset: offset + max_part]
        last = await _request("POST", urlparse(upload_url).path, absolute_url=upload_url, content=chunk, content_type="application/octet-stream")
        offset += len(chunk)
        if offset < len(raw):
            if not isinstance(last, dict) or not last.get("next_url"):
                raise RuntimeError(f"Upload did not return next_url at offset {offset}: {last}")
            upload_url = str(last["next_url"])
    return last


@mcp.tool()
async def amo_delete_files(file_uuids: list[str], confirm: bool = False) -> Any:
    """Move files to trash. Requires delete-files scope plus destructive confirmation."""
    _require_dangerous(confirm)
    return await _drive_request("DELETE", "/v1.0/files", body=[{"uuid": x} for x in file_uuids])


@mcp.tool()
async def amo_restore_files(file_uuids: list[str]) -> Any:
    """Restore trashed files."""
    _require_write()
    return await _drive_request("POST", "/v1.0/files/restore", body=[{"uuid": x} for x in file_uuids])


@mcp.tool()
async def amo_list_entity_files(entity_type: str, entity_id: int, limit: int = 250, before_id: int | None = None) -> Any:
    """List files linked to a lead/contact/company/customer using the CRM entity-files endpoint."""
    entity_type = _safe_entity_type(entity_type)
    params: dict[str, Any] = {"limit": min(limit, 250)}
    if before_id is not None: params["before_id"] = before_id
    return await _request("GET", f"/api/v4/{entity_type}/{entity_id}/files", params=params)


@mcp.tool()
async def amo_link_files_to_entity(entity_type: str, entity_id: int, file_uuids: list[str]) -> Any:
    """Link already uploaded files to a lead/contact/company/customer."""
    _require_write()
    entity_type = _safe_entity_type(entity_type)
    return await _request("POST", f"/api/v4/{entity_type}/{entity_id}/files", json_body=[{"file_uuid": x} for x in file_uuids])


# -------------------- HTTP health, OAuth 2.1 and MCP endpoint --------------------

def _b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _b64u_decode(value: str) -> bytes:
    pad = "=" * ((4 - len(value) % 4) % 4)
    return base64.urlsafe_b64decode(value + pad)


def _oauth_sign(payload: dict[str, Any], token_type: str, ttl: int) -> str:
    now = _now()
    body = dict(payload)
    body.update({"typ": token_type, "iat": now, "exp": now + ttl})
    encoded = _b64u_encode(json.dumps(body, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8"))
    signature = hmac.new(MCP_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
    return encoded + "." + _b64u_encode(signature)


def _oauth_verify(token: str, expected_type: str) -> dict[str, Any] | None:
    try:
        encoded, signature = token.split(".", 1)
        expected = hmac.new(MCP_SECRET.encode("utf-8"), encoded.encode("ascii"), hashlib.sha256).digest()
        actual = _b64u_decode(signature)
        if not hmac.compare_digest(expected, actual):
            return None
        payload = json.loads(_b64u_decode(encoded).decode("utf-8"))
        if payload.get("typ") != expected_type:
            return None
        if int(payload.get("exp", 0)) <= _now():
            return None
        return payload
    except Exception:
        return None


def _request_base(request: Request) -> str:
    forwarded_proto = request.headers.get("x-forwarded-proto")
    scheme = forwarded_proto.split(",", 1)[0].strip() if forwarded_proto else request.url.scheme
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or request.url.netloc
    return f"{scheme}://{host}".rstrip("/")


def _scope_base(scope) -> str:
    headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
    proto = (headers.get("x-forwarded-proto") or scope.get("scheme") or "https").split(",", 1)[0].strip()
    host = headers.get("x-forwarded-host") or headers.get("host") or ""
    return f"{proto}://{host}".rstrip("/")


def _oauth_error_redirect(redirect_uri: str, state: str, error: str, description: str) -> RedirectResponse:
    params = {"error": error, "error_description": description}
    if state:
        params["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(redirect_uri + sep + urlencode(params), status_code=302)


def _validate_client(client_id: str) -> dict[str, Any] | None:
    return _oauth_verify(client_id, "client")


def _validate_authorize_params(params: dict[str, str]) -> tuple[dict[str, Any] | None, str | None]:
    client_id = params.get("client_id", "")
    client = _validate_client(client_id)
    if not client:
        return None, "Unknown or invalid client_id"
    redirect_uri = params.get("redirect_uri", "")
    if redirect_uri not in client.get("redirect_uris", []):
        return None, "redirect_uri does not match the registered client"
    if params.get("response_type") != "code":
        return None, "Only response_type=code is supported"
    if params.get("code_challenge_method", "S256") != "S256" or not params.get("code_challenge"):
        return None, "PKCE with S256 is required"
    return client, None


@mcp.custom_route("/health", methods=["GET"])
async def health_route(request: Request):
    return JSONResponse({
        "ok": True,
        "service": SERVER_NAME,
        "auth_mode": "oauth2.1",
        "write_enabled": WRITE_ENABLED,
        "dangerous_write_enabled": DANGEROUS_WRITE_ENABLED,
    })


@mcp.custom_route("/.well-known/oauth-protected-resource/mcp", methods=["GET"])
async def oauth_protected_resource_mcp(request: Request):
    base = _request_base(request)
    return JSONResponse({
        "resource": base + "/mcp",
        "authorization_servers": [base],
        "scopes_supported": ["mcp", "offline_access"],
        "bearer_methods_supported": ["header"],
    })


@mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
async def oauth_protected_resource_root(request: Request):
    return await oauth_protected_resource_mcp(request)


@mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
async def oauth_authorization_server_metadata(request: Request):
    base = _request_base(request)
    return JSONResponse({
        "issuer": base,
        "authorization_endpoint": base + "/authorize",
        "token_endpoint": base + "/token",
        "registration_endpoint": base + "/register",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["none"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["mcp", "offline_access"],
    })


@mcp.custom_route("/register", methods=["POST"])
async def oauth_register(request: Request):
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({"error": "invalid_client_metadata"}, status_code=400)
    redirect_uris = body.get("redirect_uris") or []
    if not isinstance(redirect_uris, list) or not redirect_uris:
        return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    for uri in redirect_uris:
        parsed = urlparse(str(uri))
        if parsed.scheme not in {"https", "http"} or not parsed.netloc:
            return JSONResponse({"error": "invalid_redirect_uri"}, status_code=400)
    client_payload = {
        "redirect_uris": [str(x) for x in redirect_uris],
        "client_name": str(body.get("client_name") or "ChatGPT MCP Client")[:200],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    client_id = _oauth_sign(client_payload, "client", 60 * 60 * 24 * 3650)
    return JSONResponse({
        **client_payload,
        "client_id": client_id,
        "client_id_issued_at": _now(),
    }, status_code=201)


@mcp.custom_route("/authorize", methods=["GET", "POST"])
async def oauth_authorize(request: Request):
    if request.method == "GET":
        params = {k: v for k, v in request.query_params.items()}
        _, error = _validate_authorize_params(params)
        if error:
            redirect_uri = params.get("redirect_uri", "")
            if redirect_uri and urlparse(redirect_uri).scheme in {"http", "https"}:
                return _oauth_error_redirect(redirect_uri, params.get("state", ""), "invalid_request", error)
            return PlainTextResponse(error, status_code=400)

        # The only credential the user enters here is the MCP_SECRET already stored in Render.
        hidden = "".join(
            f'<input type="hidden" name="{html.escape(k, quote=True)}" value="{html.escape(str(v), quote=True)}">'
            for k, v in params.items()
        )
        page = f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Я Мебель — amoCRM</title>
<style>body{{font-family:system-ui,-apple-system,sans-serif;background:#111;color:#fff;display:grid;place-items:center;min-height:100vh;margin:0}}main{{width:min(92vw,440px);padding:28px;background:#1b1b1b;border:1px solid #444}}h1{{font-size:22px;margin:0 0 12px}}p{{color:#bbb;line-height:1.45}}input{{box-sizing:border-box;width:100%;padding:13px;margin:8px 0 14px;background:#0d0d0d;color:#fff;border:1px solid #555;font-size:16px}}button{{width:100%;padding:13px;border:0;background:#c69b6d;color:#111;font-weight:700;font-size:16px;cursor:pointer}}</style></head>
<body><main><h1>Я Мебель — amoCRM</h1><p>Введите MCP_SECRET, сохранённый в Render, чтобы разрешить ChatGPT доступ к amoCRM.</p>
<form method="post" action="/authorize">{hidden}<input type="password" name="password" autocomplete="current-password" required placeholder="MCP_SECRET"><button type="submit">Разрешить доступ</button></form></main></body></html>"""
        return HTMLResponse(page)

    raw = (await request.body()).decode("utf-8", "replace")
    parsed_form = parse_qs(raw, keep_blank_values=True)
    params = {k: (v[-1] if v else "") for k, v in parsed_form.items()}
    password = params.pop("password", "")
    client, error = _validate_authorize_params(params)
    redirect_uri = params.get("redirect_uri", "")
    state = params.get("state", "")
    if error:
        if redirect_uri:
            return _oauth_error_redirect(redirect_uri, state, "invalid_request", error)
        return PlainTextResponse(error, status_code=400)
    if not hmac.compare_digest(password, MCP_SECRET):
        return PlainTextResponse("Неверный MCP_SECRET. Вернитесь в ChatGPT и повторите подключение.", status_code=403)
    code = _oauth_sign({
        "client_id": params.get("client_id", ""),
        "redirect_uri": redirect_uri,
        "scope": params.get("scope", "mcp offline_access"),
        "resource": params.get("resource", ""),
        "code_challenge": params.get("code_challenge", ""),
    }, "code", OAUTH_CODE_TTL)
    result = {"code": code}
    if state:
        result["state"] = state
    sep = "&" if "?" in redirect_uri else "?"
    return RedirectResponse(redirect_uri + sep + urlencode(result), status_code=302)


@mcp.custom_route("/token", methods=["POST"])
async def oauth_token(request: Request):
    raw = (await request.body()).decode("utf-8", "replace")
    form = {k: (v[-1] if v else "") for k, v in parse_qs(raw, keep_blank_values=True).items()}
    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")
    client = _validate_client(client_id) if client_id else None
    if not client:
        return JSONResponse({"error": "invalid_client"}, status_code=401)

    base = _request_base(request)
    resource = form.get("resource") or (base + "/mcp")

    if grant_type == "authorization_code":
        code_data = _oauth_verify(form.get("code", ""), "code")
        if not code_data:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if code_data.get("client_id") != client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        if code_data.get("redirect_uri") != form.get("redirect_uri", ""):
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        verifier = form.get("code_verifier", "")
        challenge = _b64u_encode(hashlib.sha256(verifier.encode("utf-8")).digest()) if verifier else ""
        if not verifier or not hmac.compare_digest(challenge, str(code_data.get("code_challenge", ""))):
            return JSONResponse({"error": "invalid_grant", "error_description": "PKCE verification failed"}, status_code=400)
        scope = str(code_data.get("scope") or "mcp offline_access")
    elif grant_type == "refresh_token":
        refresh_data = _oauth_verify(form.get("refresh_token", ""), "refresh")
        if not refresh_data or refresh_data.get("client_id") != client_id:
            return JSONResponse({"error": "invalid_grant"}, status_code=400)
        scope = str(refresh_data.get("scope") or "mcp offline_access")
        resource = str(refresh_data.get("resource") or resource)
    else:
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)

    access_token = _oauth_sign({
        "sub": "yam-mebel-owner",
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
    }, "access", OAUTH_ACCESS_TTL)
    refresh_token = _oauth_sign({
        "sub": "yam-mebel-owner",
        "client_id": client_id,
        "scope": scope,
        "resource": resource,
    }, "refresh", OAUTH_REFRESH_TTL)
    return JSONResponse({
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": OAUTH_ACCESS_TTL,
        "refresh_token": refresh_token,
        "scope": scope,
    })


security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
_inner_app = mcp.streamable_http_app(transport_security=security, stateless_http=True)


class OAuthBearerMiddleware:
    """OAuth 2.1 bearer protection for /mcp. OAuth discovery and /health stay public."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        public_paths = {
            "/health",
            "/register",
            "/authorize",
            "/token",
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource",
            "/.well-known/oauth-protected-resource/mcp",
        }
        if path in public_paths or ALLOW_INSECURE_MCP:
            await self.app(scope, receive, send)
            return

        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        auth = headers.get("authorization", "")
        token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
        # Keep the original MCP_SECRET bearer accepted for manual/admin diagnostics.
        valid = bool(token) and (hmac.compare_digest(token, MCP_SECRET) or _oauth_verify(token, "access") is not None)
        if not valid:
            base = _scope_base(scope)
            metadata = base + "/.well-known/oauth-protected-resource/mcp"
            response = JSONResponse(
                {"error": "invalid_token", "error_description": "Authentication required"},
                status_code=401,
                headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'},
            )
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


app = OAuthBearerMiddleware(_inner_app)
