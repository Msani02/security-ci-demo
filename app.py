"""
Tiny 'Stedi-AI'-style demo, extended to security testing.

This app is INTENTIONALLY vulnerable (v1). It contains five injected bugs:
  1. SQL Injection      - /login builds a raw SQL string
  2. Broken Auth        - /admin/stats trusts a client-supplied header
  3. Reflected XSS       - /search reflects raw input into HTML
  4. Broken Access Ctrl - /account/<id> has no ownership check (IDOR)
  5. System Crash       - /calc has no input validation / exception handling

security_test.py is written to catch all five. Run it against this file
to see the failures, then compare with the fixed version.
"""

from flask import Flask, request, session, jsonify
from markupsafe import escape
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

    # FIX 1: parameterized query — user input is bound as data, never
    # concatenated into the SQL string.
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    user = DB.execute(query, (username, password)).fetchone()

    if user:
        session["user_id"] = user["id"]
        session["role"] = user["role"]
        return jsonify({"ok": True, "user_id": user["id"], "role": user["role"]})
    return jsonify({"ok": False}), 401


@app.route("/admin/stats")
def admin_stats():
    # FIX 2: check the verified server-side session, not a client-supplied
    # header (which anyone can set to whatever they want).
    if session.get("role") == "admin":
        return jsonify({"ok": True, "secret": "total company balance revealed"})
    return jsonify({"ok": False}), 403


@app.route("/search")
def search():
    q = request.args.get("q", "")
    # FIX 3: escape user input before embedding it in HTML.
    safe_q = escape(q)
    html = f"<html><body><h2>Results for: {safe_q}</h2><p>No results found.</p></body></html>"
    return html


@app.route("/account/<int:user_id>")
def account(user_id):
    # FIX 4: only the account owner (or an admin) may view this account.
    if session.get("user_id") != user_id and session.get("role") != "admin":
        return jsonify({"ok": False}), 403

    row = DB.execute(
        "SELECT id, username, balance FROM users WHERE id = ?", (user_id,)
    ).fetchone()
    if row is None:
        return jsonify({"ok": False}), 404
    return jsonify({"ok": True, "username": row["username"], "balance": row["balance"]})


@app.route("/calc")
def calc():
    # FIX 5: validate input and handle errors gracefully instead of
    # letting an unhandled exception crash the request.
    try:
        a = float(request.args.get("a"))
        b = float(request.args.get("b"))
        result = a / b
    except (TypeError, ValueError, ZeroDivisionError):
        return jsonify({"ok": False, "error": "invalid input"}), 400
    return jsonify({"ok": True, "result": result})


if __name__ == "__main__":
    app.run(debug=True)
