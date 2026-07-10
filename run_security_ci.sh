#!/usr/bin/env bash
# Security "break-and-fix" CI loop.
#   1. Run the security test suite against app.py
#   2. Any FAIL = a real vulnerability is present — do not deploy
#   3. Fix the flagged code, re-run this script to confirm

set -e
echo "==> Security CI: running test suite against app.py"
echo ""

if python -m pytest security_test.py -v; then
    echo ""
    echo "✅ SECURITY CI PASSED — no known vulnerabilities detected."
    exit 0
else
    echo ""
    echo "❌ SECURITY CI FAILED — do not deploy. Fix the flagged issue(s) above, then re-run this script."
    exit 1
fi
