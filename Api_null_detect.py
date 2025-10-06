#!/usr/bin/env python3
"""
API Null-Auth & TLS Expiry Auditor (syntax-based input)

- Reads a DSL file: "<METHOD> <URL> [key=value ...]"
- Probes without auth (+ optional bogus Authorization probe)
- Classifies "null auth" vs protected
- Fetches TLS cert (even if invalid) and reports days to expiry
- Strict parsing, line-by-line error handling, JSON output optional
- Works on Linux/macOS/Windows (incl. Git Bash)

Usage:
  python api_audit_syntax.py --input endpoints.txt --json-out report.json
"""

import argparse
import json
import shlex
import sys
import ssl
import socket
import datetime as dt
from dataclasses import dataclass
from typing import Optional, Tuple, List, Dict
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
except ImportError:
    print("This script requires 'requests'. Install with: pip install requests", file=sys.stderr)
    sys.exit(2)


ALLOWED_METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}


@dataclass
class Task:
    line_no: int
    raw: str
    method: str
    url: str
    timeout: int = 10
    insecure: bool = False
    bogus_auth: bool = True
    expect: Optional[str] = None
    name: Optional[str] = None


def parse_bool(val: str) -> bool:
    v = val.strip().lower()
    if v in ("1", "true", "yes", "y"):
        return True
    if v in ("0", "false", "no", "n"):
        return False
    raise ValueError(f"invalid boolean '{val}'")


def parse_expect(expr: str):
    """
    Supported:
      - 'open' | 'protected'
      - '2xx', '3xx', etc.
      - '200' (single)
      - '200-204' (range)
      - 'any'
    Returns a callable predicate(status_code:int, classification:str, redirect_location:str|None) -> bool
    """
    s = expr.strip().lower()
    if s == "any":
        return lambda sc, cls, loc: True
    if s in ("open", "protected"):
        return lambda sc, cls, loc, want=s: cls == want
    if len(s) == 3 and s.endswith("xx") and s[0].isdigit():
        base = int(s[0]) * 100
        return lambda sc, cls, loc, b=base: b <= sc < b + 100
    if "-" in s:
        a, b = s.split("-", 1)
        a = int(a)
        b = int(b)
        return lambda sc, cls, loc, lo=a, hi=b: sc >= lo and sc <= hi
    if s.isdigit():
        code = int(s)
        return lambda sc, cls, loc, c=code: sc == c
    raise ValueError(f"invalid expect '{expr}'")


def classify_auth(status_code: int, headers: dict, location: Optional[str]) -> Tuple[str, str]:
    """
    Heuristic classification of auth:
      - 'open'      => 2xx, or 3xx not to a login path
      - 'protected' => 401/403, or redirect to login/signin/auth
      - 'unknown'   => everything else
    """
    login_hints = ("login", "signin", "sign-in", "auth", "oauth", "sso")
    evidence = f"status={status_code}"

    if status_code in (401, 403):
        wa = headers.get("WWW-Authenticate")
        if wa:
            evidence += f", www-authenticate={wa}"
        return "protected", evidence

    if status_code in (301, 302, 303, 307, 308) and location:
        evidence += f", location={location}"
        if any(h in location.lower() for h in login_hints):
            return "protected", evidence
        return "open", evidence

    if 200 <= status_code < 300:
        return "open", evidence

    return "unknown", evidence


def fetch(url: str, method: str, timeout: int, headers=None, allow_insecure_probe=False):
    headers = headers or {}
    try:
        r = requests.request(method, url, timeout=timeout, allow_redirects=False, headers=headers)
        return r, None
    except requests.exceptions.SSLError as e:
        if allow_insecure_probe:
            try:
                r = requests.request(method, url, timeout=timeout, allow_redirects=False, headers=headers, verify=False)
                return r, f"TLS verify failed, proceeded insecurely: {e}"
            except Exception as e2:
                return None, f"TLS error then insecure probe failed: {e2}"
        return None, f"TLS verification error: {e}"
    except Exception as e:
        return None, f"request error: {e}"


def get_cert_expiry(url: str, timeout: int) -> Dict:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "https":
        return {"tls": False, "note": "non-HTTPS endpoint", "hostname": parsed.hostname}

    host = parsed.hostname
    port = parsed.port or 443
    info = {"tls": True, "hostname": host, "port": port, "not_after": None, "days_to_expiry": None, "error": None}

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter")
        info["not_after"] = not_after_str
        if not_after_str:
            try:
                expires = dt.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
            except ValueError:
                cleaned = " ".join(not_after_str.split())
                expires = dt.datetime.strptime(cleaned, "%b %d %H:%M:%S %Y %Z")
            now = dt.datetime.utcnow()
            info["days_to_expiry"] = int((expires - now).total_seconds() // 86400)
        else:
            info["error"] = "no notAfter in certificate"
    except Exception as e:
        info["error"] = f"cert fetch error: {e}"

    return info


def parse_input(path: str) -> Tuple[List[Task], List[str]]:
    tasks: List[Task] = []
    errors: List[str] = []

    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
    except Exception as e:
        return [], [f"FATAL: failed to read input file '{path}': {e}"]

    for i, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, posix=True)
        except Exception as e:
            errors.append(f"Line {i}: parsing error: {e}")
            continue

        if len(tokens) < 2:
            errors.append(f"Line {i}: expected '<METHOD> <URL> [key=value...]'")
            continue

        method = tokens[0].upper()
        if method not in ALLOWED_METHODS:
            errors.append(f"Line {i}: unsupported METHOD '{method}'")
            continue

        url = tokens[1]
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            errors.append(f"Line {i}: invalid URL '{url}'")
            continue

        # defaults
        timeout = 10
        insecure = False
        bogus_auth = True
        expect = None
        name = None

        # parse key=value pairs
        for kv in tokens[2:]:
            if "=" not in kv:
                errors.append(f"Line {i}: invalid token '{kv}', expected key=value")
                continue
            k, v = kv.split("=", 1)
            k = k.strip().lower()
            v = v.strip()
            try:
                if k == "timeout":
                    timeout = int(v)
                    if timeout <= 0:
                        raise ValueError("timeout must be > 0")
                elif k == "insecure":
                    insecure = parse_bool(v)
                elif k == "bogus_auth":
                    bogus_auth = parse_bool(v)
                elif k == "expect":
                    # validate now so we fail fast
                    _ = parse_expect(v)
                    expect = v
                elif k == "name":
                    name = v
                else:
                    errors.append(f"Line {i}: unknown key '{k}'")
            except Exception as e:
                errors.append(f"Line {i}: bad '{k}': {e}")

        tasks.append(Task(
            line_no=i, raw=raw.rstrip("\n"),
            method=method, url=url,
            timeout=timeout, insecure=insecure,
            bogus_auth=bogus_auth, expect=expect, name=name
        ))

    return tasks, errors


def audit_task(t: Task) -> Dict:
    result = {
        "line_no": t.line_no,
        "name": t.name,
        "url": t.url,
        "method": t.method,
        "http_status": None,
        "http_reason": None,
        "redirect_location": None,
        "null_auth": "unknown",
        "auth_evidence": None,
        "bogus_auth_2xx": None,
        "notes": [],
        "tls": get_cert_expiry(t.url, t.timeout),
        "expect": t.expect,
        "expect_pass": None,
        "severity": "info",
    }

    # Probe no-auth
    r0, err0 = fetch(t.url, t.method, t.timeout, headers=None, allow_insecure_probe=t.insecure)
    if err0:
        result["notes"].append(err0)
    if r0 is not None:
        result["http_status"] = r0.status_code
        result["http_reason"] = r0.reason
        loc = r0.headers.get("Location")
        result["redirect_location"] = loc
        cls, evidence = classify_auth(r0.status_code, r0.headers, loc)
        result["null_auth"] = cls
        result["auth_evidence"] = evidence

    # Probe bogus auth if requested
    if t.bogus_auth:
        r1, err1 = fetch(t.url, t.method, t.timeout,
                         headers={"Authorization": "Bearer obviously_invalid_token_123"},
                         allow_insecure_probe=t.insecure)
        if err1:
            result["notes"].append(err1)
        if r1 is not None:
            result["bogus_auth_2xx"] = 200 <= r1.status_code < 300

    # Expectation check
    if t.expect and result["http_status"] is not None:
        try:
            pred = parse_expect(t.expect)
            result["expect_pass"] = bool(pred(result["http_status"], result["null_auth"], result["redirect_location"]))
        except Exception as e:
            result["expect_pass"] = False
            result["notes"].append(f"expect parse error: {e}")

    # Severity hint
    sev = "info"
    if result["null_auth"] == "open" and (result["http_status"] and 200 <= result["http_status"] < 300):
        sev = "high"
    tls_dte = result["tls"].get("days_to_expiry")
    if tls_dte is not None and tls_dte <= 30:
        sev = "medium" if sev != "high" else "high"
    result["severity"] = sev

    return result


def main():
    ap = argparse.ArgumentParser(description="Audit endpoints from a syntax file for null-auth and TLS expiry.")
    ap.add_argument("--input", required=True, help="Path to DSL file.")
    ap.add_argument("--json-out", help="Write JSON report to this file.")
    ap.add_argument("--concurrency", type=int, default=6, help="Parallel workers (default: 6).")
    args = ap.parse_args()

    tasks, parse_errors = parse_input(args.input)

    # Print parse errors but continue with valid tasks
    if parse_errors:
        print("=== Parse Errors ===", file=sys.stderr)
        for e in parse_errors:
            print(e, file=sys.stderr)

    if not tasks:
        print("No valid tasks parsed; exiting.", file=sys.stderr)
        sys.exit(2)

    results: List[Dict] = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futs = {ex.submit(audit_task, t): t for t in tasks}
        for fut in as_completed(futs):
            try:
                results.append(fut.result())
            except Exception as e:
                t = futs[fut]
                results.append({
                    "line_no": t.line_no, "name": t.name, "url": t.url, "method": t.method,
                    "error": f"unhandled error: {e}"
                })

    # Order by line number
    results.sort(key=lambda r: r.get("line_no", 0))

    # Pretty output
    print("\n=== API Null-Auth & TLS Expiry Report ===")
    for r in results:
        prefix = f"[{r.get('line_no')}]"
        if "error" in r:
            print(f"{prefix} {r['url']}: ERROR -> {r['error']}")
            continue

        name = f" ({r['name']})" if r.get("name") else ""
        tls = r["tls"]
        if tls.get("tls"):
            dte = tls.get("days_to_expiry")
            if dte is None:
                tls_str = f"TLS: unknown expiry ({tls.get('error') or 'no notAfter'})"
            else:
                tls_str = f"TLS: expires in {dte} days (notAfter={tls.get('not_after')})"
        else:
            tls_str = "HTTP (no TLS)"

        print(f"\n{prefix}{name} {r['method']} {r['url']}")
        print(f"  HTTP Status:     {r.get('http_status')} {r.get('http_reason') or ''}".rstrip())
        if r.get("redirect_location"):
            print(f"  Redirect To:     {r['redirect_location']}")
        print(f"  Null-Auth:       {r['null_auth']}  ({r.get('auth_evidence')})")
        if r.get("bogus_auth_2xx") is not None:
            print(f"  Bogus-Auth 2xx:  {r['bogus_auth_2xx']}")
        print(f"  {tls_str}")
        if r.get("expect") is not None:
            print(f"  Expect:          {r['expect']} → pass={r['expect_pass']}")
        if r.get("notes"):
            for n in r["notes"]:
                print(f"  Note:            {n}")
        print(f"  Severity:        {r['severity']}")

    # JSON output (optional)
    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(results, f, indent=2)
            print(f"\n[wrote JSON] {args.json_out}")
        except Exception as e:
            print(f"\n[!] failed to write JSON report: {e}", file=sys.stderr)

    # Exit code: 0 ok, 1 if any high severity OR parse errors, 2 fatal parse/IO
    exit_code = 0
    if any(r.get("severity") == "high" for r in results if "error" not in r) or parse_errors:
        exit_code = 1
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
