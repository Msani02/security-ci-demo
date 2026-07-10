"""
Tiny 'Stedi-AI'-style demo, extended to security testing.

*** VULNERABLE BASELINE — v1 ***
This version intentionally contains 5 bugs, used as a baseline so a
security scanner (or your STEDi-AI audit tool) has real findings to
detect before we push the fixed version on top and confirm they clear.

  1. SQL Injection      - /login builds a raw SQL string
  2. Broken Auth        - /admin/stats trusts a client-supplied header
  3. Reflected XSS       - /search reflects raw input into HTML
  4. Broken Access Ctrl - /account/<id> has no ownership check (IDOR)
  5. System Crash       - /calc has no input validation / exception handling

Also running in debug=True at the bottom, which is itself a 6th real
finding (matches the "Insecure Configuration / debug mode enabled"
result your scanner already flagged) — see NOTE at the bottom.
"""

from flask import Flask, request, session, jsonify
import sqlite3

app = Flask(__name__)
app.secret_key = "dev-only-secret"  # fine for a local demo

# --- In-memory "database", seeded once at startup ---
DB = sqlite3.connect(":memory:", check_same_thread=False)
DB.row_factory = sqlite3.Row
DB.execute(
    "CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, "
    "password TEXT, role TEXT, balance REAL)"
)
DB.executemany(
    "INSERT INTO users (id, username, password, role, balance) VALUES (?,?,?,?,?)",
    [
        (1, "admin", "S3cureAdminPass!", "admin", 500000.0),
        (2, "msani", "hunter2", "user", 1200.0),
        (3, "guest", "guestpass", "user", 50.0),
    ],
)
DB.commit()


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")

    # BUG 1 (SQL Injection): building the query with string formatting
    # instead of parameter binding.
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    user = DB.execute(query).fetchone()

    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"ok": True, "user_id": user["id"], "role": user["role"]})
    return jsonify({"ok": False}), 401


@app.route("/admin/stats")
def admin_stats():
    # BUG 2 (Broken Auth): trusts a client-supplied header instead of the
    # server-verified session role.
    if request.headers.get("X-Role") == "admin":
        return jsonify({"ok": True, "secret": "total company balance revealed"})
    return jsonify({"ok": False}), 403


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # BUG 3 (Reflected XSS): raw string concatenation, no escaping.
    html = f"<html><body><h2>Results for: {q}</h2><p>No results found.</p></body></html>"
    return html


@app.route("/account/<int:user_id>")
def account(user_id):
    # BUG 4 (Broken Access Control / IDOR): no check that the logged-in
    # user actually owns this account id.
    row = DB.execute(
        "SELECT id, username, balance FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify({"ok": False}), 404
    return jsonify({"ok": True, "username": row["username"], "balance": row["balance"]})


@app.route("/calc")
def calc():
    # BUG 5 (System Crash): no input validation or exception handling.
    a = float(request.args.get("a"))
    b = float(request.args.get("b"))
    result = a / b  # ZeroDivisionError / ValueError crash the request
    return jsonify({"ok": True, "result": result})


if __name__ == "__main__":
    # NOTE: debug=True is ALSO an intentional finding here (matches your
    # scanner's "Insecure Configuration / debug mode enabled" result).
    # In production this leaks stack traces and internals to end users.
    app.run(debug=True)