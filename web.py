"""FastAPI web application for MAC Collector."""

from __future__ import annotations

import ipaddress
import os
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

SERVER_TZ = ZoneInfo(os.environ.get("DISPLAY_TZ", "America/New_York"))

from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from fdb_collector import FdbCollector

from auth import (
    COOKIE_NAME,
    SESSION_MAX_AGE,
    create_session_token,
    get_current_user,
    hash_password,
    require_admin,
    require_operator,
    verify_password,
)
from db import Database

# ------------------------------------------------------------------
# Lifespan
# ------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    db = Database()
    await db.connect()
    await db.ensure_partitions(4)
    app.state.db = db
    yield
    await db.close()


app = FastAPI(lifespan=lifespan)
templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))
templates.env.filters["bitand"] = lambda val, mask: int(val) & int(mask)
templates.env.filters["localdt"] = lambda dt: dt.astimezone(SERVER_TZ) if dt and dt.tzinfo else dt

AUDIT_ACTIONS = [
    "login", "logout", "login_failed",
    "add_switch", "edit_switch", "delete_switch",
    "search_mac", "search_ip",
    "view_history",
    "create_user", "disable_user", "set_role", "change_password",
]


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _is_htmx(request: Request) -> bool:
    return request.headers.get("HX-Request") == "true"


async def _log(request: Request, user_id, action: str, detail: dict = None) -> None:
    try:
        await request.app.state.db.log_action(
            user_id=user_id,
            action=action,
            detail=detail or {},
            ip_address=_client_ip(request),
        )
    except Exception:
        pass  # audit failures must not affect business operations


# ------------------------------------------------------------------
# Exception handlers
# ------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    if exc.status_code == 401:
        if _is_htmx(request):
            return Response(
                status_code=200,
                headers={"HX-Redirect": "/login"},
            )
        return RedirectResponse("/login", status_code=302)
    # For other HTTP errors, return a simple HTML page
    return HTMLResponse(
        content=f"<h1>{exc.status_code}</h1><p>{exc.detail}</p>",
        status_code=exc.status_code,
    )


# ------------------------------------------------------------------
# Auth routes
# ------------------------------------------------------------------

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse(
        request, "login.html", {"error": None, "email": None}
    )


@app.post("/login")
async def login_submit(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
):
    db: Database = request.app.state.db
    ip = _client_ip(request)

    user = await db.get_user_by_email(email)
    if user is None or not user["enabled"] or not verify_password(password, user["password_hash"]):
        await db.log_action(
            user_id=user["id"] if user else None,
            action="login_failed",
            detail={"email": email},
            ip_address=ip,
        )
        return templates.TemplateResponse(
            request, "login.html",
            {"error": "Invalid credentials.", "email": email},
            status_code=401,
        )

    token = create_session_token(str(user["id"]))
    response = RedirectResponse("/", status_code=302)
    response.set_cookie(
        key=COOKIE_NAME,
        value=token,
        httponly=True,
        samesite="lax",
        max_age=SESSION_MAX_AGE,
        secure=False,
    )
    await db.log_action(
        user_id=user["id"],
        action="login",
        detail={"email": email},
        ip_address=ip,
    )
    return response


@app.post("/logout")
async def logout(request: Request, user: dict = Depends(get_current_user)):
    await _log(request, user["id"], "logout")
    response = RedirectResponse("/login", status_code=302)
    response.delete_cookie(COOKIE_NAME)
    return response


# ------------------------------------------------------------------
# Search + History (combined)
# ------------------------------------------------------------------

# Preset time ranges: label → timedelta offset from now (None = no limit)
TIME_RANGE_PRESETS: dict[str, timedelta | None] = {
    "1h":  timedelta(hours=1),
    "5h":  timedelta(hours=5),
    "1d":  timedelta(days=1),
    "7d":  timedelta(days=7),
    "1m":  timedelta(days=30),
    "6m":  timedelta(days=182),
    "1y":  timedelta(days=365),
}
TIME_RANGE_DEFAULT = "7d"


def _resolve_time_range(
    preset: str,
    since: str,
    until: str,
) -> tuple[datetime | None, datetime | None, str | None]:
    """Return (since_dt, until_dt, active_preset).

    Priority: explicit since/until → preset → default preset.
    active_preset is the key that matches the selected dropdown option,
    or None when a custom range is in use.
    """
    if since or until:
        since_dt = None
        until_dt = None
        if since:
            try:
                since_dt = datetime.fromisoformat(since).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        if until:
            try:
                until_dt = datetime.fromisoformat(until).replace(tzinfo=timezone.utc)
            except ValueError:
                pass
        return since_dt, until_dt, None

    active = preset if preset in TIME_RANGE_PRESETS else TIME_RANGE_DEFAULT
    delta = TIME_RANGE_PRESETS[active]
    if delta is None:
        return None, None, active
    since_dt = datetime.now(tz=timezone.utc) - delta
    return since_dt, None, active


@app.get("/", response_class=HTMLResponse)
async def search(
    request: Request,
    mac: str = "",
    ip: str = "",
    range: str = "",
    since: str = "",
    until: str = "",
    offset: int = 0,
    limit: int = 50,
    user: dict = Depends(get_current_user),
):
    db: Database = request.app.state.db
    results = None
    mac = mac.strip()
    ip = ip.strip()

    if limit not in HISTORY_PAGE_SIZES:
        limit = 50

    since_dt, until_dt, active_preset = _resolve_time_range(range, since, until)

    if mac:
        results = await db.search_by_mac(mac)
        await _log(request, user["id"], "search_mac", {"query": mac})
    elif ip:
        results = await db.search_by_ip(ip)
        await _log(request, user["id"], "search_ip", {"query": ip})

    history = await db.get_history(
        mac=mac or None,
        switch_ip=ip or None,
        since=since_dt,
        until=until_dt,
        limit=limit + 1,
        offset=offset,
    )
    has_more = len(history) > limit
    history = history[:limit]
    total_hint = offset + len(history) + (1 if has_more else 0)

    if mac or ip:
        await _log(request, user["id"], "view_history", {"mac": mac or None, "ip": ip or None})

    return templates.TemplateResponse(
        request, "dashboard.html",
        {
            "user": user,
            "results": results,
            "q_mac": mac or None,
            "q_ip": ip or None,
            "q_range": active_preset or "",
            "q_since": since or "",
            "q_until": until or "",
            "active_preset": active_preset,
            "history": history,
            "page_sizes": HISTORY_PAGE_SIZES,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "total": total_hint,
        },
    )


def _validate_switch_ip(ip: str) -> str | None:
    """Return error message if ip is invalid, else None."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return f"'{ip}' is not a valid IP address."
    if addr.is_loopback:
        return f"{ip} is a loopback address."
    if addr.is_multicast:
        return f"{ip} is a multicast address."
    if addr.is_reserved:
        return f"{ip} is a reserved address."
    if addr.is_unspecified:
        return f"{ip} is an unspecified address (0.0.0.0)."
    return None


def _switch_hostname(switches, ip: str) -> str | None:
    for sw in switches:
        if str(sw["ip_address"]) == ip:
            return sw["hostname"]
    return None


@app.get("/mac-on-switches", response_class=HTMLResponse)
async def mac_on_switches(
    request: Request,
    user: dict = Depends(get_current_user),
):
    db: Database = request.app.state.db
    switches = await db.get_switches()
    return templates.TemplateResponse(
        request, "mac_on_switches.html",
        {
            "user": user,
            "switches": switches,
            "selected_ip": None,
            "macs": [],
            "switch_hostname": None,
            "error": None,
        },
    )


@app.get("/mac-on-switches/table", response_class=HTMLResponse)
async def mac_on_switches_table(
    request: Request,
    switch_ip: str = "",
    user: dict = Depends(get_current_user),
):
    db: Database = request.app.state.db
    switches = await db.get_switches()
    macs = []
    if switch_ip:
        macs = await db.get_macs_by_switch(switch_ip)
    return templates.TemplateResponse(
        request, "_mac_table.html",
        {
            "user": user,
            "selected_ip": switch_ip or None,
            "switch_hostname": _switch_hostname(switches, switch_ip),
            "macs": macs,
            "error": None,
        },
    )


@app.post("/mac-on-switches/update", response_class=HTMLResponse)
async def mac_on_switches_update(
    request: Request,
    switch_ip: str = Form(""),
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    switches = await db.get_switches()
    error = None

    if switch_ip:
        try:
            collector = FdbCollector(switch_ip)
            entries = await collector.collect_async()
            await db.upsert_macs(entries, switch_ip=switch_ip)
        except Exception as exc:
            error = f"Failed to poll switch {switch_ip}: {exc}"

    macs = await db.get_macs_by_switch(switch_ip) if switch_ip else []
    return templates.TemplateResponse(
        request, "_mac_table.html",
        {
            "user": user,
            "selected_ip": switch_ip or None,
            "switch_hostname": _switch_hostname(switches, switch_ip),
            "macs": macs,
            "error": error,
        },
    )


@app.get("/search")
async def search_redirect(mac: str = "", ip: str = ""):
    params = "&".join(f"{k}={v}" for k, v in [("mac", mac), ("ip", ip)] if v)
    return RedirectResponse(f"/?{params}" if params else "/", status_code=301)


@app.get("/history")
async def history_redirect(mac: str = ""):
    return RedirectResponse(f"/?mac={mac}" if mac else "/", status_code=301)


# ------------------------------------------------------------------
# Switches (operator+)
# ------------------------------------------------------------------

@app.get("/switches", response_class=HTMLResponse)
async def switches_page(
    request: Request,
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    switches = await db.get_switches()
    disabled_switches = await db.get_disabled_switches()
    return templates.TemplateResponse(
        request, "switches.html",
        {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": None, "success": None},
    )


@app.post("/switches", response_class=HTMLResponse)
async def add_switch(
    request: Request,
    ip: str = Form(...),
    hostname: str = Form(""),
    is_core: str = Form(""),
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    ip = ip.strip()
    hostname = hostname.strip() or None
    core = bool(is_core)

    ip_err = _validate_switch_ip(ip)
    if ip_err:
        switches = await db.get_switches()
        disabled_switches = await db.get_disabled_switches()
        return templates.TemplateResponse(
            request, "switches.html",
            {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": ip_err, "success": None},
            status_code=400,
        )

    dup = await db.check_switch_duplicate(ip, hostname)
    if dup:
        switches = await db.get_switches()
        disabled_switches = await db.get_disabled_switches()
        return templates.TemplateResponse(
            request, "switches.html",
            {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": dup, "success": None},
            status_code=400,
        )

    try:
        await db.add_switch(ip, hostname, core)
        await _log(request, user["id"], "add_switch", {"ip": ip, "hostname": hostname})
    except Exception as exc:
        switches = await db.get_switches()
        disabled_switches = await db.get_disabled_switches()
        return templates.TemplateResponse(
            request, "switches.html",
            {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": f"Failed to add switch: {exc}", "success": None},
            status_code=500,
        )

    return RedirectResponse("/switches", status_code=303)


@app.post("/switches/{switch_id}/edit", response_class=HTMLResponse)
async def edit_switch(
    switch_id: str,
    request: Request,
    ip: str = Form(...),
    hostname: str = Form(""),
    is_core: str = Form(""),
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db
    ip = ip.strip()
    hostname = hostname.strip() or None
    core = bool(is_core)

    ip_err = _validate_switch_ip(ip)
    if ip_err:
        switches = await db.get_switches()
        disabled_switches = await db.get_disabled_switches()
        return templates.TemplateResponse(
            request, "switches.html",
            {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": ip_err, "success": None},
            status_code=400,
        )

    dup = await db.check_switch_duplicate(ip, hostname, exclude_id=switch_id)
    if dup:
        switches = await db.get_switches()
        disabled_switches = await db.get_disabled_switches()
        return templates.TemplateResponse(
            request, "switches.html",
            {"user": user, "switches": switches, "disabled_switches": disabled_switches, "error": dup, "success": None},
            status_code=400,
        )

    await db.update_switch(switch_id, ip, hostname, core)
    await _log(request, user["id"], "edit_switch", {"switch_id": switch_id, "ip": ip, "hostname": hostname})
    return RedirectResponse("/switches", status_code=303)


@app.post("/switches/{switch_id}/delete")
async def delete_switch(
    switch_id: str,
    request: Request,
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    await db.delete_switch(switch_id)
    await _log(request, user["id"], "delete_switch", {"switch_id": switch_id})
    return RedirectResponse("/switches", status_code=303)


@app.post("/switches/{switch_id}/enable")
async def enable_switch(
    switch_id: str,
    request: Request,
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    await db.enable_switch(switch_id)
    await _log(request, user["id"], "enable_switch", {"switch_id": switch_id})
    return RedirectResponse("/switches", status_code=303)


# ------------------------------------------------------------------
# Profile (all authenticated users)
# ------------------------------------------------------------------

@app.get("/profile", response_class=HTMLResponse)
async def profile_page(
    request: Request,
    ok: str = "",
    user: dict = Depends(get_current_user),
):
    return templates.TemplateResponse(
        request, "profile.html",
        {
            "user": user,
            "error": None,
            "success": "Password changed successfully." if ok == "1" else None,
        },
    )


@app.post("/profile")
async def profile_change_password(
    request: Request,
    current_password: str = Form(...),
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(get_current_user),
):
    db: Database = request.app.state.db

    def _err(msg: str):
        return templates.TemplateResponse(
            request, "profile.html",
            {"user": user, "error": msg, "success": None},
            status_code=400,
        )

    full_user = await db.get_user_by_id(user["id"])
    if not verify_password(current_password, full_user["password_hash"]):
        return _err("Current password is incorrect.")

    if new_password != confirm_password:
        return _err("New passwords do not match.")

    if len(new_password) < 12:
        return _err("Password must be at least 12 characters.")

    await db.update_password(user["id"], hash_password(new_password))
    await _log(request, user["id"], "change_password", {"target": user["email"]})
    return RedirectResponse("/profile?ok=1", status_code=303)


# ------------------------------------------------------------------
# Users (admin)
# ------------------------------------------------------------------

@app.get("/users", response_class=HTMLResponse)
async def users_page(
    request: Request,
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db
    users = await db.get_users()
    return templates.TemplateResponse(
        request, "users.html",
        {"user": user, "users": users, "error": None, "success": None},
    )


@app.post("/users", response_class=HTMLResponse)
async def create_user(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    role: str = Form(...),
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db
    email = email.strip().lower()

    if len(password) < 12:
        users = await db.get_users()
        return templates.TemplateResponse(
            request, "users.html",
            {
                "user": user,
                "users": users,
                "error": "Password must be at least 12 characters.",
                "success": None,
            },
        )

    if role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    try:
        await db.create_user(email, hash_password(password), role)
        await _log(request, user["id"], "create_user", {"email": email, "role": role})
    except Exception as exc:
        users = await db.get_users()
        return templates.TemplateResponse(
            request, "users.html",
            {
                "user": user,
                "users": users,
                "error": f"Failed to create user: {exc}",
                "success": None,
            },
        )

    return RedirectResponse("/users", status_code=303)


@app.post("/users/{target_id}/disable")
async def disable_user(
    target_id: str,
    request: Request,
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db
    await db.disable_user(target_id)
    await _log(request, user["id"], "disable_user", {"target_id": target_id})
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{target_id}/set-role")
async def set_user_role(
    target_id: str,
    request: Request,
    role: str = Form(...),
    user: dict = Depends(require_admin),
):
    if role not in ("admin", "operator", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    db: Database = request.app.state.db
    await db.set_user_role(target_id, role)
    await _log(request, user["id"], "set_role", {"target_id": target_id, "role": role})
    return RedirectResponse("/users", status_code=303)


@app.post("/users/{target_id}/set-password")
async def admin_set_password(
    target_id: str,
    request: Request,
    new_password: str = Form(...),
    confirm_password: str = Form(...),
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db

    if new_password != confirm_password:
        users = await db.get_users()
        return templates.TemplateResponse(
            request, "users.html",
            {
                "user": user,
                "users": users,
                "error": "Passwords do not match.",
                "success": None,
            },
            status_code=400,
        )

    if len(new_password) < 12:
        users = await db.get_users()
        return templates.TemplateResponse(
            request, "users.html",
            {
                "user": user,
                "users": users,
                "error": "Password must be at least 12 characters.",
                "success": None,
            },
            status_code=400,
        )

    await db.update_password(target_id, hash_password(new_password))
    await _log(request, user["id"], "change_password", {"target_id": target_id})
    return RedirectResponse("/users", status_code=303)


# ------------------------------------------------------------------
# Audit log (admin)
# ------------------------------------------------------------------

COLLECTOR_PAGE_SIZES = [50, 100, 200, 500]
HISTORY_PAGE_SIZES = [50, 100, 200, 500]


@app.get("/collector-logs", response_class=HTMLResponse)
async def collector_logs_page(
    request: Request,
    collector: str = "",
    switch_ip: str = "",
    range: str = "",
    since: str = "",
    until: str = "",
    errors_only: str = "",
    offset: int = 0,
    limit: int = 50,
    user: dict = Depends(require_operator),
):
    db: Database = request.app.state.db
    if limit not in COLLECTOR_PAGE_SIZES:
        limit = 50

    since_dt, until_dt, active_preset = _resolve_time_range(range, since, until)

    entries = await db.get_collection_log(
        collector=collector or None,
        switch_ip=switch_ip.strip() or None,
        since=since_dt,
        until=until_dt,
        errors_only=bool(errors_only),
        limit=limit + 1,
        offset=offset,
    )
    has_more = len(entries) > limit
    entries = entries[:limit]
    total_hint = offset + len(entries) + (1 if has_more else 0)

    return templates.TemplateResponse(
        request, "collector_logs.html",
        {
            "user": user,
            "entries": entries,
            "page_sizes": COLLECTOR_PAGE_SIZES,
            "q_collector": collector or None,
            "q_switch_ip": switch_ip.strip() or None,
            "q_range": active_preset or "",
            "q_since": since or "",
            "q_until": until or "",
            "active_preset": active_preset,
            "q_errors_only": bool(errors_only),
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "total": total_hint,
        },
    )


AUDIT_PAGE_SIZES = [50, 100, 200, 500]


@app.get("/audit", response_class=HTMLResponse)
async def audit_page(
    request: Request,
    action: str = "",
    range: str = "",
    since: str = "",
    until: str = "",
    q: str = "",
    offset: int = 0,
    limit: int = 50,
    user: dict = Depends(require_admin),
):
    db: Database = request.app.state.db
    if limit not in AUDIT_PAGE_SIZES:
        limit = 50

    since_dt, until_dt, active_preset = _resolve_time_range(range, since, until)

    entries = await db.get_audit_log(
        action=action or None,
        since=since_dt,
        until=until_dt,
        search=q.strip() or None,
        limit=limit + 1,
        offset=offset,
    )
    has_more = len(entries) > limit
    entries = entries[:limit]
    total_hint = offset + len(entries) + (1 if has_more else 0)

    return templates.TemplateResponse(
        request, "audit.html",
        {
            "user": user,
            "entries": entries,
            "actions": AUDIT_ACTIONS,
            "page_sizes": AUDIT_PAGE_SIZES,
            "q_action": action or None,
            "q_range": active_preset or "",
            "q_since": since or "",
            "q_until": until or "",
            "active_preset": active_preset,
            "q": q.strip() or None,
            "offset": offset,
            "limit": limit,
            "has_more": has_more,
            "total": total_hint,
        },
    )
