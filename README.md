# secscan: Lightweight AppSec Header, Cookie, and IDOR Scanner

## Why I built this
Whenever I start reviewing a web application, I end up running the same three baseline checks by hand: inspecting response headers and cookie attributes, looking for numeric or UUID identifiers in URLs that might allow Insecure Direct Object Reference (IDOR) access, and collecting query and form parameters for fuzzing.

I built `secscan.py` to run those checks in one pass from the command line. It crawls same-origin links up to a configurable page limit, checks headers and `Set-Cookie` flags, flags endpoints with object references in the path or query string, and dumps a clean parameter wordlist for `ffuf` or Burp Intruder. If it finds any High-severity issue, it exits with code `1` so it can fail a CI build.

> Only scan targets you own or have written permission to test.

## What I implemented in `secscan.py`
1. **Same-origin crawler (`crawl` and `PageParser`)**: Uses Python's `html.parser.HTMLParser` to extract `href`, `src`, and `action` links along with `<input>`, `<textarea>`, and `<select>` parameter names while staying strictly on the target hostname.
2. **Header and cookie audit (`check_headers`)**:
   - Checks for `Content-Security-Policy` (High), `Strict-Transport-Security` (Medium, checked only on HTTPS targets), `X-Content-Type-Options: nosniff` (Medium), `X-Frame-Options` (Medium), `Referrer-Policy` (Low), and `Permissions-Policy` (Low).
   - Flags `unsafe-inline` or `unsafe-eval` directives inside an existing CSP.
   - Flags version-leaking headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).
   - Parses raw `Set-Cookie` headers and flags cookies missing `HttpOnly`, `SameSite`, or `Secure` (over TLS).
3. **IDOR candidate locator (`idor_candidates`)**: Scans URL path segments for integers (`^\d+$`) or UUIDs and checks query parameters against common object-reference names (`id`, `uid`, `user_id`, `account_id`, `order_id`, `doc_id`, `file_id`, `invoice`).
4. **Local vulnerable target (`demo/vuln_target.py`)**: A small HTTP server binding to `127.0.0.1:8000` that intentionally exposes missing headers, `X-Powered-By: PHP/5.6.40`, an unflagged session cookie, `/orders/1001`, `/profile?user_id=7`, and a login form so the scanner can be tested offline.

## Demo scan output
Running `secscan.py` against `demo/vuln_target.py` crawls 5 pages, detects 11 issues (1 High, 6 Medium, 4 Low), and harvests 5 fuzzing parameters (`page`, `password`, `q`, `user_id`, `username`).

![scan](docs/screenshots/01_scan.png)

Sample artifacts generated during the demo run:
- JSON findings report: [docs/report.json](docs/report.json)
- Harvested parameter wordlist: [docs/params.txt](docs/params.txt)

## How to run it
```bash
pip install -r requirements.txt

# 1. Start the local test target on 127.0.0.1:8000
python3 demo/vuln_target.py &

# 2. Run the scanner and export JSON + parameter wordlist
python3 secscan.py http://127.0.0.1:8000 --json docs/report.json --params docs/params.txt

# 3. Run the unit tests
pytest -q tests
```

## Honest limitations
- **IDOR flags are candidates, not confirmed bugs**: For example, `secscan` flags `page=1` on `/search?q=shoes&page=1` because the value is numeric. Confirming a real IDOR requires replaying the request with a second user's session token and comparing the response.
- **No JavaScript execution**: Because `PageParser` uses `HTMLParser` rather than a headless browser, it is fast and lightweight, but it will not see routes rendered client-side by a React or Vue single-page app.
