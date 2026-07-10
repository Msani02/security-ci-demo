# Security Break-and-Fix Demo

Extends the earlier Stedi-AI break-and-fix pattern from plain logic bugs
to **security bugs**: 4 classic vulnerability classes + 1 system-crash bug,
each injected on purpose, each caught by an automated test, each fixed.

## Files

- `app.py` — a tiny Flask app (login, admin stats, search, account lookup,
  a calculator endpoint). Currently contains the **fixed** version.
- `security_test.py` — one test per vulnerability class.
- `run_security_ci.sh` — runs the suite and reports PASS/FAIL.
- `run1_vulnerable_output.txt` / `run2_fixed_output.txt` — real pytest
  output from before and after the fixes.

## The 5 bugs, what caught them, and the fix

| # | Bug class | Where | How the test caught it | Fix |
|---|-----------|-------|------------------------|-----|
| 1 | SQL Injection | `/login` | `' OR '1'='1' --` as username logged in with *any* password | Parameterized query (`?` placeholders) instead of string formatting |
| 2 | Broken Authentication | `/admin/stats` | Setting an `X-Role: admin` header (something any client can fake) granted admin access | Check `session["role"]`, set server-side at login, not a client header |
| 3 | Reflected XSS | `/search` | A `<script>` payload in `?q=` came back unescaped in the HTML | Escape user input with `markupsafe.escape()` before embedding in HTML |
| 4 | Broken Access Control (IDOR) | `/account/<id>` | A logged-in low-privilege user could read another user's account by just changing the ID in the URL | Check the requested ID matches the logged-in session's user (or role is admin) |
| 5 | Unhandled exception / crash | `/calc` | `b=0` (or non-numeric input) threw an unhandled `ZeroDivisionError`, returning a raw 500 | Wrap in `try/except`, return a clean `400` for bad input |

## Run it yourself

```bash
pip install flask pytest markupsafe
./run_security_ci.sh
```

## Notes on scope (for your research writeup)

This is deliberately small and self-contained so the CI loop is easy to see
end to end. A few things worth calling out if you extend this toward your
STEDi-AI security-technical-debt work:

- **Passwords are stored in plaintext** in this demo for simplicity. A real
  system should hash them (e.g. bcrypt/argon2) — that's a 6th bug class
  (insecure credential storage) you could add a test for.
- **Session secret** (`app.secret_key`) is hardcoded here; in production it
  should come from an env var / secrets manager, matching the "Managed
  Secrets" point in your Stedi-AI notes.
- This uses Flask's in-process test client rather than a live HTTP server,
  so it runs fast in CI with no network/port dependencies — same idea as
  the "spin up a temporary namespace, push a synthetic payload" step in
  your Stedi-AI doc, just scoped down to function calls.
- Good next step for your research: wire `run_security_ci.sh` into a
  GitHub Actions workflow (`on: push`) so every commit gets scanned before
  merge — that turns this from a manual demo into an actual CI gate.
