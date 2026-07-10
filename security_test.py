"""
Security test suite — same "break-and-fix" CI loop as before, applied to
security bugs instead of a plain logic bug. Each test corresponds to one
injected vulnerability in app.py.
"""

import pytest
from app import app


@pytest.fixture
def client():
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def test_login_rejects_sql_injection(client):
    """BUG 1: SQL Injection via unparameterized login query."""
    payload = {"username": "' OR '1'='1' -- ", "password": "anything"}
    resp = client.post("/login", data=payload)
    assert resp.status_code == 401, (
        "SQL injection payload logged in successfully — "
        "the login query is not parameterized"
    )


def test_admin_endpoint_requires_real_session(client):
    """BUG 2: Broken auth — trusting a client-supplied header."""
    resp = client.get("/admin/stats", headers={"X-Role": "admin"})
    assert resp.status_code == 403, (
        "Admin endpoint trusted a client-supplied X-Role header "
        "instead of a verified server-side session"
    )


def test_search_escapes_user_input(client):
    """BUG 3: Reflected XSS — raw input echoed into HTML."""
    payload = "<script>alert(1)</script>"
    resp = client.get("/search", query_string={"q": payload})
    assert b"<script>" not in resp.data, (
        "Raw <script> tag reflected unescaped in the response — XSS vulnerability"
    )


def test_account_enforces_ownership(client):
    """BUG 4: Broken access control / IDOR."""
    # Log in as a low-privilege user (guest, id=3)...
    client.post("/login", data={"username": "guest", "password": "guestpass"})
    # ...then try to read another user's account (admin, id=1) directly by ID.
    resp = client.get("/account/1")
    assert resp.status_code == 403, (
        "A logged-in guest could read another user's account data "
        "by guessing the ID — broken access control / IDOR"
    )


def test_calc_handles_bad_input_gracefully(client):
    """BUG 5: System crash on invalid input (e.g. divide by zero)."""
    resp = client.get("/calc", query_string={"a": "10", "b": "0"})
    assert resp.status_code == 400, (
        f"Expected a graceful 400 for invalid input, got {resp.status_code} "
        f"(likely an unhandled exception / server crash)"
    )
