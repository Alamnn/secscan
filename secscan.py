#!/usr/bin/env python3
"""secscan: lightweight AppSec checker for targets you own or are authorised to test.

Checks:
  1. HTTP security headers + cookie flags + info-leak headers
  2. IDOR-prone URL patterns (numeric/UUID ids in path or query)
  3. Parameter harvesting (query params, form fields, links) written to a fuzz list

Usage:
  python secscan.py http://127.0.0.1:8000 [--json report.json] [--params params.txt]
"""
import argparse
import json
import re
import sys
from html.parser import HTMLParser
from urllib.parse import parse_qsl, urljoin, urlparse

import requests

TIMEOUT = 8

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("high", "Mitigates XSS/data injection"),
    "Strict-Transport-Security": ("medium", "Forces HTTPS (only relevant over TLS)"),
    "X-Content-Type-Options": ("medium", "Should be 'nosniff'"),
    "X-Frame-Options": ("medium", "Clickjacking protection (or CSP frame-ancestors)"),
    "Referrer-Policy": ("low", "Limits referrer leakage"),
    "Permissions-Policy": ("low", "Restricts browser features"),
}
LEAKY_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version"]
IDOR_PARAM = re.compile(r"^(id|uid|user_?id|account_?id|order_?id|doc(ument)?_?id|file_?id|invoice)$", re.I)
NUMERIC_SEG = re.compile(r"^\d+$")
UUID_SEG = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)


class PageParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links, self.inputs = [], []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag in ("a", "form", "script", "img") and (a.get("href") or a.get("src") or a.get("action")):
            self.links.append(a.get("href") or a.get("src") or a.get("action"))
        if tag in ("input", "textarea", "select") and a.get("name"):
            self.inputs.append(a["name"])


def check_headers(resp) -> list[dict]:
    f = []
    h = resp.headers
    is_tls = resp.url.startswith("https")
    for name, (sev, why) in REQUIRED_HEADERS.items():
        if name == "Strict-Transport-Security" and not is_tls:
            continue
        if name not in h:
            f.append({"check": "header", "severity": sev, "title": f"Missing {name}", "detail": why})
    if "X-Content-Type-Options" in h and h["X-Content-Type-Options"].lower() != "nosniff":
        f.append({"check": "header", "severity": "medium", "title": "Weak X-Content-Type-Options",
                  "detail": h["X-Content-Type-Options"]})
    csp = h.get("Content-Security-Policy", "")
    if "unsafe-inline" in csp or "unsafe-eval" in csp:
        f.append({"check": "header", "severity": "medium", "title": "CSP allows unsafe-inline/eval", "detail": csp})
    for name in LEAKY_HEADERS:
        if name in h:
            f.append({"check": "info-leak", "severity": "low", "title": f"{name} discloses technology",
                      "detail": h[name]})
    for c in resp.raw.headers.getlist("Set-Cookie") if hasattr(resp.raw.headers, "getlist") else []:
        name = c.split("=", 1)[0]
        missing = [flag for flag in ("HttpOnly", "SameSite") if flag.lower() not in c.lower()]
        if is_tls and "secure" not in c.lower():
            missing.append("Secure")
        if missing:
            f.append({"check": "cookie", "severity": "medium", "title": f"Cookie '{name}' missing {', '.join(missing)}",
                      "detail": c})
    return f


def idor_candidates(url: str) -> list[dict]:
    p = urlparse(url)
    out = []
    for seg in p.path.split("/"):
        if NUMERIC_SEG.match(seg) or UUID_SEG.match(seg):
            out.append({"check": "idor", "severity": "medium", "title": "Object id in path",
                        "detail": f"{url} (segment '{seg}') - test with another user's id"})
    for k, v in parse_qsl(p.query):
        if IDOR_PARAM.match(k) or NUMERIC_SEG.match(v):
            out.append({"check": "idor", "severity": "medium", "title": f"Object reference parameter '{k}'",
                        "detail": f"{url} - test by changing {k}={v}"})
    return out


def crawl(base: str, max_pages: int = 25):
    seen, queue, pages = set(), [base], []
    host = urlparse(base).netloc
    while queue and len(pages) < max_pages:
        url = queue.pop(0).split("#")[0]
        if url in seen or urlparse(url).netloc != host:
            continue
        seen.add(url)
        try:
            r = requests.get(url, timeout=TIMEOUT)
        except requests.RequestException:
            continue
        pages.append((url, r))
        if "html" in r.headers.get("Content-Type", ""):
            pp = PageParser()
            pp.feed(r.text)
            for l in pp.links:
                queue.append(urljoin(url, l))
            r.inputs = pp.inputs
    return pages


def run(base: str):
    pages = crawl(base)
    if not pages:
        raise SystemExit(f"Could not reach {base}")
    findings, params = [], set()
    findings += [dict(x, url=pages[0][0]) for x in check_headers(pages[0][1])]
    for url, r in pages:
        findings += [dict(x, url=url) for x in idor_candidates(url)]
        params.update(k for k, _ in parse_qsl(urlparse(url).query))
        params.update(getattr(r, "inputs", []))
    seen_f, uniq = set(), []
    for x in findings:
        key = (x["title"], x["detail"])
        if key not in seen_f:
            seen_f.add(key)
            uniq.append(x)
    return uniq, sorted(params), [u for u, _ in pages]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("target")
    ap.add_argument("--json")
    ap.add_argument("--params", help="write harvested parameter names (one per line) for fuzzing")
    a = ap.parse_args()
    findings, params, pages = run(a.target)
    order = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda x: order[x["severity"]])
    print(f"Target: {a.target}   pages crawled: {len(pages)}\n")
    for x in findings:
        print(f"[{x['severity'].upper():6}] {x['check']:9} {x['title']}")
        print(f"           {x['detail']}")
    print(f"\nParameters for fuzzing ({len(params)}): {', '.join(params)}")
    if a.json:
        json.dump({"target": a.target, "findings": findings, "params": params, "pages": pages},
                  open(a.json, "w"), indent=2)
    if a.params:
        open(a.params, "w").write("\n".join(params) + "\n")
    return 1 if any(x["severity"] == "high" for x in findings) else 0


if __name__ == "__main__":
    sys.exit(main())
