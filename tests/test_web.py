"""Integration tests for web.py routes.

Uses FastAPI TestClient with a mocked Database to avoid real DB.
Run: python -m pytest tests/test_web.py -v
"""

import os
import sys
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

os.environ.setdefault("SESSION_SECRET", "test-secret-for-web-tests-only-32ch")

from fastapi import FastAPI
from fastapi.testclient import TestClient

import auth as auth_module
from auth import create_session_token, hash_password

# Patch lifespan before importing web so no real DB connection is made
import web as web_module

@asynccontextmanager
async def _noop_lifespan(app):
    yield

web_module.app.router.lifespan_context = _noop_lifespan
app = web_module.app


# ------------------------------------------------------------------
# Helpers: build a fake asyncpg-like Record dict
# ------------------------------------------------------------------

def _make_user(
    user_id="aaaaaaaa-0000-7000-8000-000000000001",
    email="admin@test.local",
    role="admin",
    enabled=True,
    password="adminpassword123",
):
    return {
        "id": user_id,
        "email": email,
        "password_hash": hash_password(password),
        "role": role,
        "enabled": enabled,
    }


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

@pytest.fixture
def admin_user():
    return _make_user(role="admin")


@pytest.fixture
def operator_user():
    return _make_user(
        user_id="aaaaaaaa-0000-7000-8000-000000000002",
        email="operator@test.local",
        role="operator",
    )


@pytest.fixture
def viewer_user():
    return _make_user(
        user_id="aaaaaaaa-0000-7000-8000-000000000003",
        email="viewer@test.local",
        role="viewer",
    )


def _make_mock_db(user: dict):
    """Return a mock Database whose get_user_by_id always returns `user`."""
    mock_db = MagicMock()
    mock_db.get_user_by_id = AsyncMock(return_value=user)
    mock_db.get_user_by_email = AsyncMock(return_value=user)
    mock_db.log_action = AsyncMock(return_value=None)
    mock_db.get_switches = AsyncMock(return_value=[])
    mock_db.add_switch = AsyncMock(return_value=None)
    mock_db.delete_switch = AsyncMock(return_value=None)
    mock_db.get_users = AsyncMock(return_value=[])
    mock_db.create_user = AsyncMock(return_value=None)
    mock_db.disable_user = AsyncMock(return_value=None)
    mock_db.update_password = AsyncMock(return_value=None)
    mock_db.get_audit_log = AsyncMock(return_value=[])
    mock_db.search_by_mac = AsyncMock(return_value=[])
    mock_db.search_by_ip = AsyncMock(return_value=[])
    mock_db.get_history = AsyncMock(return_value=[])
    mock_db.update_switch = AsyncMock(return_value=None)
    mock_db.check_switch_duplicate = AsyncMock(return_value=None)
    return mock_db


def _client_with_user(user: dict) -> TestClient:
    """TestClient with app.state.db mocked and a valid session cookie."""
    mock_db = _make_mock_db(user)
    app.state.db = mock_db
    token = create_session_token(str(user["id"]))
    client = TestClient(app, raise_server_exceptions=True)
    client.cookies.set("session", token)
    return client


# ------------------------------------------------------------------
# Login / Logout
# ------------------------------------------------------------------

class TestLogin:
    def test_get_login_page(self):
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.get("/login")
        assert resp.status_code == 200
        assert "Sign in" in resp.text

    def test_post_login_success(self, admin_user):
        mock_db = _make_mock_db(admin_user)
        app.state.db = mock_db
        client = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
        resp = client.post("/login", data={
            "email": admin_user["email"],
            "password": "adminpassword123",
        })
        assert resp.status_code == 302
        assert resp.headers["location"] == "/"
        assert "session" in resp.cookies

    def test_post_login_wrong_password(self, admin_user):
        mock_db = _make_mock_db(admin_user)
        app.state.db = mock_db
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/login", data={
            "email": admin_user["email"],
            "password": "wrongpassword!!",
        })
        assert resp.status_code == 401
        assert "Invalid credentials" in resp.text

    def test_post_login_unknown_email(self):
        mock_db = MagicMock()
        mock_db.get_user_by_email = AsyncMock(return_value=None)
        mock_db.log_action = AsyncMock(return_value=None)
        app.state.db = mock_db
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/login", data={
            "email": "nobody@test.local",
            "password": "somepassword123",
        })
        assert resp.status_code == 401
        assert "Invalid credentials" in resp.text

    def test_post_login_disabled_user(self, admin_user):
        disabled = dict(admin_user, enabled=False)
        mock_db = _make_mock_db(disabled)
        app.state.db = mock_db
        client = TestClient(app, raise_server_exceptions=True)
        resp = client.post("/login", data={
            "email": disabled["email"],
            "password": "adminpassword123",
        })
        assert resp.status_code == 401

    def test_login_audit_logged_on_failure(self, admin_user):
        mock_db = _make_mock_db(admin_user)
        app.state.db = mock_db
        client = TestClient(app, raise_server_exceptions=True)
        client.post("/login", data={
            "email": admin_user["email"],
            "password": "wrongpassword!!",
        })
        mock_db.log_action.assert_called()
        call_kwargs = mock_db.log_action.call_args
        assert call_kwargs.kwargs["action"] == "login_failed"


class TestLogout:
    def test_logout_clears_cookie(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post("/logout", follow_redirects=False)
        assert resp.status_code == 302
        # Starlette's delete_cookie sends Set-Cookie with max-age=0 or empty value
        set_cookie = resp.headers.get("set-cookie", "")
        assert "session" in set_cookie

    def test_logout_unauthenticated_redirects(self):
        app.state.db = _make_mock_db(_make_user())
        client = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
        resp = client.post("/logout")
        assert resp.status_code in (302, 401)


# ------------------------------------------------------------------
# Dashboard / Search
# ------------------------------------------------------------------

class TestDashboard:
    def test_root_requires_auth(self):
        app.state.db = _make_mock_db(_make_user())
        client = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]

    def test_root_with_auth(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.get("/")
        assert resp.status_code == 200
        assert "Search" in resp.text

    def test_search_mac_calls_db(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.get("/search?mac=aa:bb")
        assert resp.status_code == 200
        app.state.db.search_by_mac.assert_called_once_with("aa:bb")

    def test_search_ip_calls_db(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.get("/search?ip=192.168.1")
        assert resp.status_code == 200
        app.state.db.search_by_ip.assert_called_once_with("192.168.1")


# ------------------------------------------------------------------
# Switches
# ------------------------------------------------------------------

class TestSwitches:
    def test_viewer_cannot_access_switches(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.get("/switches", follow_redirects=False)
        assert resp.status_code == 403

    def test_operator_can_access_switches(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.get("/switches")
        assert resp.status_code == 200

    def test_admin_can_access_switches(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.get("/switches")
        assert resp.status_code == 200

    def test_add_switch_calls_db(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.post("/switches", data={"ip": "10.0.0.99", "hostname": "sw-test"})
        assert resp.status_code in (200, 303)
        app.state.db.add_switch.assert_called_once_with("10.0.0.99", "sw-test", False)

    def test_delete_switch_calls_db(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.post("/switches/some-uuid/delete", follow_redirects=False)
        assert resp.status_code == 303
        app.state.db.delete_switch.assert_called_once_with("some-uuid")


# ------------------------------------------------------------------
# Users
# ------------------------------------------------------------------

class TestUsers:
    def test_operator_cannot_access_users(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.get("/users", follow_redirects=False)
        assert resp.status_code == 403

    def test_admin_can_access_users(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.get("/users")
        assert resp.status_code == 200

    def test_create_user_calls_db(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post("/users", data={
            "email": "new@test.local",
            "password": "newpassword1234",
            "role": "viewer",
        }, follow_redirects=False)
        assert resp.status_code == 303
        app.state.db.create_user.assert_called_once()
        args = app.state.db.create_user.call_args[0]
        assert args[0] == "new@test.local"
        assert args[2] == "viewer"

    def test_create_user_short_password(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post("/users", data={
            "email": "new@test.local",
            "password": "short",
            "role": "viewer",
        })
        assert resp.status_code == 200
        assert "12 characters" in resp.text
        app.state.db.create_user.assert_not_called()

    def test_disable_user_calls_db(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post("/users/target-uuid/disable", follow_redirects=False)
        assert resp.status_code == 303
        app.state.db.disable_user.assert_called_once_with("target-uuid")


# ------------------------------------------------------------------
# Audit
# ------------------------------------------------------------------

class TestAudit:
    def test_operator_cannot_access_audit(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.get("/audit", follow_redirects=False)
        assert resp.status_code == 403

    def test_admin_can_access_audit(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.get("/audit")
        assert resp.status_code == 200

    def test_audit_filter_by_action(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.get("/audit?action=login")
        assert resp.status_code == 200
        app.state.db.get_audit_log.assert_called()
        call_kwargs = app.state.db.get_audit_log.call_args.kwargs
        assert call_kwargs["action"] == "login"


# ------------------------------------------------------------------
# HTMX 401 handling
# ------------------------------------------------------------------

class TestHtmx401:
    def test_htmx_request_gets_hx_redirect(self):
        app.state.db = _make_mock_db(_make_user())
        client = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
        resp = client.get("/", headers={"HX-Request": "true"})
        assert resp.status_code == 200
        assert resp.headers.get("HX-Redirect") == "/login"

    def test_normal_request_gets_redirect(self):
        app.state.db = _make_mock_db(_make_user())
        client = TestClient(app, raise_server_exceptions=True, follow_redirects=False)
        resp = client.get("/")
        assert resp.status_code == 302
        assert "/login" in resp.headers["location"]


# ------------------------------------------------------------------
# Change Password
# ------------------------------------------------------------------

class TestChangePassword:
    def test_profile_page_accessible(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.get("/profile")
        assert resp.status_code == 200
        assert "Change Password" in resp.text

    def test_change_own_password_success(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.post("/profile", data={
            "current_password": "adminpassword123",
            "new_password": "newsecurepass123",
            "confirm_password": "newsecurepass123",
        }, follow_redirects=False)
        assert resp.status_code == 303
        assert "/profile" in resp.headers["location"]
        app.state.db.update_password.assert_called_once()

    def test_change_own_password_wrong_current(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.post("/profile", data={
            "current_password": "wrongpassword!!!",
            "new_password": "newsecurepass123",
            "confirm_password": "newsecurepass123",
        })
        assert resp.status_code == 400
        assert "incorrect" in resp.text.lower()
        app.state.db.update_password.assert_not_called()

    def test_change_own_password_mismatch(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.post("/profile", data={
            "current_password": "adminpassword123",
            "new_password": "newsecurepass123",
            "confirm_password": "different_pass123",
        })
        assert resp.status_code == 400
        assert "match" in resp.text.lower()
        app.state.db.update_password.assert_not_called()

    def test_change_own_password_too_short(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.post("/profile", data={
            "current_password": "adminpassword123",
            "new_password": "short",
            "confirm_password": "short",
        })
        assert resp.status_code == 400
        assert "12 characters" in resp.text
        app.state.db.update_password.assert_not_called()

    def test_admin_set_password_success(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post("/users/target-uuid/set-password", data={
            "new_password": "newadminpass123",
            "confirm_password": "newadminpass123",
        }, follow_redirects=False)
        assert resp.status_code == 303
        app.state.db.update_password.assert_called_once_with(
            "target-uuid", app.state.db.update_password.call_args[0][1]
        )

    def test_non_admin_cannot_set_others_password(self, viewer_user):
        client = _client_with_user(viewer_user)
        resp = client.post("/users/target-uuid/set-password", data={
            "new_password": "newadminpass123",
            "confirm_password": "newadminpass123",
        }, follow_redirects=False)
        assert resp.status_code == 403


# ------------------------------------------------------------------
# Switch Edit
# ------------------------------------------------------------------

class TestSwitchEdit:
    SWITCH_ID = "bbbbbbbb-0000-7000-8000-000000000001"

    def test_admin_can_edit_switch(self, admin_user):
        client = _client_with_user(admin_user)
        resp = client.post(
            f"/switches/{self.SWITCH_ID}/edit",
            data={"ip": "10.0.0.1", "hostname": "sw-core-01", "is_core": "1"},
            follow_redirects=False,
        )
        assert resp.status_code == 303
        app.state.db.update_switch.assert_called_once_with(
            self.SWITCH_ID, "10.0.0.1", "sw-core-01", True
        )

    def test_edit_duplicate_ip(self, admin_user):
        client = _client_with_user(admin_user)
        app.state.db.check_switch_duplicate = AsyncMock(
            return_value="IP address 10.0.0.1 is already used by another switch."
        )
        resp = client.post(
            f"/switches/{self.SWITCH_ID}/edit",
            data={"ip": "10.0.0.1", "hostname": ""},
        )
        assert resp.status_code == 400
        assert "10.0.0.1" in resp.text
        app.state.db.update_switch.assert_not_called()

    def test_operator_cannot_edit_switch(self, operator_user):
        client = _client_with_user(operator_user)
        resp = client.post(
            f"/switches/{self.SWITCH_ID}/edit",
            data={"ip": "10.0.0.1", "hostname": ""},
            follow_redirects=False,
        )
        assert resp.status_code == 403

    def test_add_switch_duplicate_ip(self, operator_user):
        client = _client_with_user(operator_user)
        app.state.db.check_switch_duplicate = AsyncMock(
            return_value="IP address 10.0.0.2 is already used by another switch."
        )
        resp = client.post(
            "/switches",
            data={"ip": "10.0.0.2", "hostname": ""},
        )
        assert resp.status_code == 400
        assert "10.0.0.2" in resp.text
        app.state.db.add_switch.assert_not_called()
