#!/usr/bin/env python3
"""
fetch-fast-json-updated.py

- Fast multi-source downloader+analyzer (curl backend default), JSON logging (pretty by default), progress table, sha256 ON by default.
- Git clones are analyzed: deterministic tree SHA256 for directories if --sha256.
- Resume, retries, exponential backoff, graceful SIGINT/SIGTERM cleanup.
- Stdlib only (curl & git binaries required for best performance).
"""
from __future__ import annotations
import argparse
import os
import sys
import time
import json
import signal
import shutil
import subprocess
import threading
import hashlib
import mimetypes
import socket
from urllib import request, parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from pathlib import Path

# tuning
CHUNK = 256 * 1024
POLL_INTERVAL = 0.5
DEFAULT_CONCURRENCY = 3

# global state
_interrupt = threading.Event()
_log_lock = threading.Lock()
_incomplete_lock = threading.Lock()
_incomplete = set()
_status_lock = threading.Lock()
_status = {}  # source -> status dict

def now_iso():
    return datetime.utcnow().isoformat() + "Z"

# -------------------------
# Logging (thread-safe). pretty by default but can be disabled with --no-pretty
# -------------------------
def write_json_event(path: str, obj: dict, pretty: bool = True):
    s = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2 if pretty else None)
    with _log_lock:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(s)
            fh.write("\n")
            if pretty:
                fh.write("\n")  # blank line between pretty records for readability

def log_event(logpath: str, event: str, details: dict, pretty: bool):
    rec = {"ts": now_iso(), "event": event, "details": details}
    try:
        write_json_event(logpath, rec, pretty=pretty)
    except Exception as e:
        # do not crash on logging failure
        print(f"[logerr] failed to write log: {e}", file=sys.stderr)

# -------------------------
# housekeeping helpers
# -------------------------
def install_signal_handlers():
    def handler(sig, frame):
        _interrupt.set()
    signal.signal(signal.SIGINT, handler)
    signal.signal(signal.SIGTERM, handler)

def register_incomplete(path: str):
    with _incomplete_lock:
        _incomplete.add(path)

def unregister_incomplete(path: str):
    with _incomplete_lock:
        _incomplete.discard(path)

def cleanup_incomplete():
    with _incomplete_lock:
        files = list(_incomplete)
        _incomplete.clear()
    for p in files:
        try:
            if os.path.exists(p):
                os.remove(p)
        except Exception:
            pass

# -------------------------
# helpers: head info, sha256, analyze
# -------------------------
def head_info(url: str, timeout: int = 6):
    try:
        req = request.Request(url, method="HEAD")
        with request.urlopen(req, timeout=timeout) as resp:
            return {k.lower(): v for k, v in resp.getheaders()}
    except Exception:
        return None

def sha256_file(path: str, block_size: int = 4 * 1024 * 1024):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            while True:
                chunk = fh.read(block_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def tree_sha256(path: str, block_size: int = 4 * 1024 * 1024) -> Optional[str]:
    """Deterministic tree SHA256 for directories: walks files sorted, updates hash with relpath, size, and file bytes."""
    h = hashlib.sha256()
    try:
        files = []
        for root, _, fnames in os.walk(path):
            for fn in fnames:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, start=path).replace(os.sep, "/")
                files.append((rel, full))
        files.sort(key=lambda x: x[0])
        for rel, full in files:
            try:
                st = os.stat(full)
                size = str(st.st_size).encode("utf-8")
                h.update(rel.encode("utf-8"))
                h.update(b"\x00")
                h.update(size)
                h.update(b"\x00")
                with open(full, "rb") as fh:
                    while True:
                        chunk = fh.read(block_size)
                        if not chunk:
                            break
                        h.update(chunk)
            except Exception:
                h.update(b"__ERR__")
        return h.hexdigest()
    except Exception:
        return None

def analyze_path(path: str, compute_sha256: bool, logpath: str, pretty: bool):
    info = {"path": path, "is_dir": False, "size": None, "kind": None, "subtype": None, "executable": False, "mime": None, "sha256": None}
    try:
        if os.path.isdir(path):
            info["is_dir"] = True
            if os.path.exists(os.path.join(path, ".git")):
                info["kind"] = "repo"; info["subtype"] = "git"
            else:
                info["kind"] = "dir"
            # cheap size: top-level files sum
            total = 0
            try:
                for entry in os.scandir(path):
                    if entry.is_file(follow_symlinks=False):
                        try:
                            total += entry.stat().st_size
                        except Exception:
                            pass
            except Exception:
                pass
            info["size"] = total
            if compute_sha256:
                info["sha256"] = tree_sha256(path)
        else:
            try:
                st = os.stat(path)
                info["size"] = st.st_size
                info["executable"] = bool(st.st_mode & 0o111)
            except Exception:
                pass
            head = b""
            try:
                with open(path, "rb") as fh:
                    head = fh.read(8192)
            except Exception:
                head = b""
            if head.startswith(b"\x1f\x8b\x08"):
                info.update({"kind":"archive","subtype":"gzip"})
            elif head.startswith(b"PK\x03\x04"):
                info.update({"kind":"archive","subtype":"zip"})
            elif head.startswith(b"%PDF-"):
                info.update({"kind":"document","subtype":"pdf"})
            elif head.startswith(b"\x89PNG\r\n\x1a\n"):
                info.update({"kind":"image","subtype":"png"})
            elif head.startswith(b"\xff\xd8\xff"):
                info.update({"kind":"image","subtype":"jpeg"})
            elif head.startswith(b"\x7fELF"):
                info.update({"kind":"binary","subtype":"elf"})
            else:
                try:
                    head.decode("utf-8")
                    info.update({"kind":"text","subtype":"text"})
                except Exception:
                    info.update({"kind":"binary","subtype":"unknown"})
            m, _ = mimetypes.guess_type(path)
            if m:
                info["mime"] = m
            if compute_sha256:
                info["sha256"] = sha256_file(path)
    except Exception:
        pass
    # log the analysis event
    event = {"ts": now_iso(), "event": "file_analysis", "details": info}
    try:
        write_json_event(logpath, event, pretty)
    except Exception:
        pass
    return info

# -------------------------
# curl backend (polling file for progress)
# -------------------------
def run_curl_download(url: str, dest: str, logpath: str, pretty: bool, max_bytes: Optional[int], retries: int, timeout: int):
    dest_tmp = dest + ".incomplete"
    register_incomplete(dest_tmp)
    # basic curl command; --continue-at - resumes, --silent suppresses progress but we poll file
    cmd = ["curl", "--fail", "--location", "--silent", "--show-error",
           "--output", dest_tmp, "--continue-at", "-", "--retry", str(retries), "--retry-delay", "1", "--max-time", str(max(10, timeout))]
    proc = subprocess.Popen(cmd + [url], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        headers = head_info(url, timeout=4)
        total = None
        if headers:
            cl = headers.get("content-length")
            if cl and cl.isdigit():
                total = int(cl)
        if max_bytes and total and total > max_bytes:
            try:
                proc.kill()
            except Exception:
                pass
            unregister_incomplete(dest_tmp)
            cleanup_incomplete()
            return {"ok": False, "error": "remote too large", "bytes": 0}
        last_bytes = 0
        last_time = time.time()
        speeds = []
        while True:
            if _interrupt.is_set():
                try:
                    proc.terminate()
                except Exception:
                    pass
                log_event(logpath, "interrupted", {"url": url}, pretty)
                unregister_incomplete(dest_tmp)
                cleanup_incomplete()
                return {"ok": False, "error": "interrupted"}
            rc = proc.poll()
            cur_bytes = 0
            if os.path.exists(dest_tmp):
                try:
                    cur_bytes = os.path.getsize(dest_tmp)
                except Exception:
                    cur_bytes = cur_bytes
            now = time.time()
            delta_b = cur_bytes - last_bytes
            delta_t = max(1e-6, now - last_time)
            speed = delta_b / delta_t if delta_t > 0 else 0.0
            speeds.append(speed)
            if len(speeds) > 10:
                speeds.pop(0)
            avg_speed = sum(speeds)/len(speeds) if speeds else 0.0
            with _status_lock:
                _status[url].update({"status":"downloading", "bytes":cur_bytes, "total": total, "speed": avg_speed})
            last_bytes = cur_bytes
            last_time = now
            if rc is not None:
                out, err = proc.communicate(timeout=1)
                if rc != 0:
                    unregister_incomplete(dest_tmp)
                    log_event(logpath, "curl_error", {"url": url, "rc": rc, "stderr": err.decode(errors="ignore") if err else ""}, pretty)
                    return {"ok": False, "error": f"curl rc={rc}", "bytes": cur_bytes}
                try:
                    os.replace(dest_tmp, dest)
                except Exception as e:
                    unregister_incomplete(dest_tmp)
                    return {"ok": False, "error": f"rename failed: {e}"}
                unregister_incomplete(dest_tmp)
                return {"ok": True, "bytes": cur_bytes}
            time.sleep(POLL_INTERVAL)
    except Exception as e:
        try:
            proc.kill()
        except Exception:
            pass
        unregister_incomplete(dest_tmp)
        return {"ok": False, "error": str(e)}
    finally:
        pass

# -------------------------
# Python fallback downloader (simple streaming)
# -------------------------
def py_download(url: str, dest:str, logpath:str, pretty:bool, max_bytes:Optional[int], retries:int, timeout:int):
    tmp = dest + ".incomplete"
    register_incomplete(tmp)
    attempt = 0
    last_exc = None
    while attempt <= retries and not _interrupt.is_set():
        attempt += 1
        try:
            req = request.Request(url, method="GET")
            with request.urlopen(req, timeout=timeout) as resp:
                cl = resp.getheader("Content-Length")
                expected = int(cl) if cl and cl.isdigit() else None
                if max_bytes and expected and expected > max_bytes:
                    unregister_incomplete(tmp)
                    cleanup_incomplete()
                    return {"ok": False, "error": "remote too large"}
                with open(tmp, "ab") as fh:
                    while True:
                        if _interrupt.is_set():
                            unregister_incomplete(tmp)
                            cleanup_incomplete()
                            return {"ok": False, "error": "interrupted"}
                        chunk = resp.read(CHUNK)
                        if not chunk:
                            break
                        fh.write(chunk)
                os.replace(tmp, dest)
                unregister_incomplete(tmp)
                return {"ok": True, "bytes": os.path.getsize(dest)}
        except Exception as e:
            last_exc = e
            time.sleep(min(5, 2 ** attempt))
    unregister_incomplete(tmp)
    cleanup_incomplete()
    return {"ok": False, "error": str(last_exc) if last_exc else "unknown"}

# -------------------------
# git clone (uses git)
# -------------------------
def git_clone(url: str, dest_dir: str, logpath: str, pretty: bool, depth:int=1, timeout:int=600):
    tmp = dest_dir + ".tmp"
    try:
        cmd = ["git", "clone", "--depth", str(depth), url, tmp]
        log_event(logpath, "git_clone_cmd", {"cmd": " ".join(cmd)}, pretty)
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
        if p.returncode != 0:
            log_event(logpath, "git_clone_error", {"stderr": p.stderr}, pretty)
            p2 = subprocess.run(["git", "clone", url, tmp], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=timeout)
            if p2.returncode != 0:
                log_event(logpath, "git_clone_error_retry", {"stderr": p2.stderr}, pretty)
                return {"ok": False, "error": p2.stderr.strip() or p.stderr.strip()}
        if os.path.exists(dest_dir):
            shutil.rmtree(dest_dir)
        os.replace(tmp, dest_dir)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}

# -------------------------
# worker for a single source
# -------------------------
def process_source(src: str, args) -> dict:
    parsed = parse.urlsplit(src)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    base = args.name or os.path.basename(parsed.path.rstrip("/")) or "download"
    dest_base = os.path.join(args.out, f"{base}_{ts}")

    # detect type
    is_git=False; is_http=False; is_ftp=False
    if src.startswith("git@") or src.endswith(".git") or src.startswith("git://") or (src.startswith("ssh://") and "git" in src):
        is_git = True
    else:
        scheme = parsed.scheme.lower()
        if scheme in ("http","https"):
            is_http = True
        elif scheme == "ftp":
            is_ftp = True
        else:
            if "@" in src and ":" in src and not scheme:
                is_git = True

    log_event(args.log, "start", {"source": src, "is_git": is_git, "is_http": is_http, "is_ftp": is_ftp, "dest_base": dest_base}, args.pretty)

    with _status_lock:
        _status[src] = {"status":"queued","bytes":0,"total":None,"speed":0.0}

    if is_http or is_ftp:
        ext = os.path.splitext(parsed.path)[1] or ""
        dest = dest_base + ext
        headers = head_info(src, timeout=min(4, args.timeout))
        total = None
        if headers:
            cl = headers.get("content-length")
            if cl and cl.isdigit():
                total = int(cl)
        with _status_lock:
            _status[src].update({"total": total, "status":"starting"})
        if args.max_bytes and total and total > args.max_bytes:
            log_event(args.log, "abort", {"source": src, "reason":"remote_too_large", "content_length": total}, args.pretty)
            with _status_lock:
                _status[src]["status"] = "error"
            return {"ok": False, "error": "remote too large"}

        # pick backend
        if args.use_curl and shutil.which("curl"):
            log_event(args.log, "curl_start", {"source": src}, args.pretty)
            res = run_curl_download(src, dest, args.log, args.pretty, args.max_bytes if args.max_bytes else None, retries=args.retries, timeout=args.timeout)
        else:
            log_event(args.log, "py_download_start", {"source": src}, args.pretty)
            res = py_download(src, dest, args.log, args.pretty, args.max_bytes if args.max_bytes else None, retries=args.retries, timeout=args.timeout)

        if not res.get("ok"):
            log_event(args.log, "download_failed", {"source": src, "error": res.get("error")}, args.pretty)
            with _status_lock:
                _status[src]["status"] = "error"
            return {"ok": False, "error": res.get("error")}

        with _status_lock:
            _status[src].update({"status":"verifying", "bytes": res.get("bytes", None)})
        sha = None
        if args.sha256:
            sha = sha256_file(dest)
        log_event(args.log, "download_complete", {"source": src, "path": dest, "bytes": res.get("bytes"), "sha256": sha}, args.pretty)
        analyze = analyze_path(dest, args.sha256, args.log, args.pretty)
        with _status_lock:
            _status[src].update({"status":"done", "bytes": res.get("bytes", None)})
        return {"ok": True, "path": dest, "sha256": sha, "analysis": analyze}

    if is_git:
        dest_dir = dest_base + "_repo"
        with _status_lock:
            _status[src].update({"status":"cloning"})
        res = git_clone(src, dest_dir, args.log, args.pretty, depth=args.git_depth, timeout=max(60, args.timeout*2))
        if not res.get("ok"):
            log_event(args.log, "git_clone_failed", {"source": src, "error": res.get("error")}, args.pretty)
            with _status_lock:
                _status[src]["status"] = "error"
            return {"ok": False, "error": res.get("error")}

        # approximate size
        total = 0
        for root, _, files in os.walk(dest_dir):
            for f in files:
                try:
                    total += os.path.getsize(os.path.join(root, f))
                except Exception:
                    pass

        sha = None
        if args.sha256:
            log_event(args.log, "tree_sha_start", {"source": src, "path": dest_dir}, args.pretty)
            sha = tree_sha256(dest_dir)
            log_event(args.log, "tree_sha_done", {"source": src, "path": dest_dir, "sha256": sha}, args.pretty)

        log_event(args.log, "git_clone_complete", {"source": src, "path": dest_dir, "approx_size_bytes": total, "sha256": sha}, args.pretty)
        analyze = analyze_path(dest_dir, args.sha256, args.log, args.pretty)
        with _status_lock:
            _status[src].update({"status":"done", "bytes": total})
        return {"ok": True, "path": dest_dir, "analysis": analyze, "sha256": sha}

    log_event(args.log, "unsupported", {"source": src}, args.pretty)
    with _status_lock:
        _status[src]["status"] = "error"
    return {"ok": False, "error": "unsupported"}

# -------------------------
# Progress table printer
# -------------------------
def human(n):
    for u in ("B","KiB","MiB","GiB","TiB"):
        if n < 1024:
            return f"{n:.1f}{u}"
        n /= 1024
    return f"{n:.1f}PiB"

def print_table(sources, quiet=False):
    while True:
        if _interrupt.is_set():
            break
        all_done = True
        lines = []
        with _status_lock:
            for src in sources:
                st = _status.get(src, {"status":"queued","bytes":0,"total":None,"speed":0.0})
                status = st.get("status","")
                bytes_ = st.get("bytes") or 0
                total = st.get("total")
                speed = st.get("speed") or 0.0
                pct = "-"
                eta = ""
                if total:
                    pct_val = min(100.0, (bytes_/total*100.0)) if total>0 else 0.0
                    pct = f"{pct_val:5.1f}%"
                    if speed > 0 and bytes_>0:
                        remaining = max(0, total - bytes_)
                        eta = f"{int(remaining / speed)}s"
                all_done = all_done and (status in ("done","error"))
                lines.append((src, status, pct, human(bytes_), human(speed) + "/s" if speed>0 else "-", eta))
        if not quiet:
            print("\x1b[2J\x1b[H", end="")  # clear screen + home
            print(f"{'SOURCE':45} {'STATUS':12} {'PROG':7} {'BYTES':10} {'SPEED':12} {'ETA':6}")
            print("-"*95)
            for src,status,pct,bytes_s,speed_s,eta in lines:
                s = (src[:42] + '...') if len(src)>45 else src.ljust(45)
                print(f"{s} {status:12} {pct:7} {bytes_s:10} {speed_s:12} {eta:6}")
            print("\nPress Ctrl+C to abort.")
        if all_done:
            break
        time.sleep(0.7)

# -------------------------
# CLI and orchestrator
# -------------------------
def main():
    install_signal_handlers()
    ap = argparse.ArgumentParser(description="fetch-fast-json-updated: curl-backed downloader + analyzer (pretty JSON logs)")
    ap.add_argument("sources", nargs="+", help="URLs or git specs")
    ap.add_argument("--out", "-o", default=".", help="output dir")
    ap.add_argument("--log", "-l", required=True, help="log file (JSON)")
    ap.add_argument("--concurrency", type=int, default=DEFAULT_CONCURRENCY)
    ap.add_argument("--no-curl", action="store_true", help="do not use curl (use python fallback)")
    ap.add_argument("--no-sha256", action="store_true", help="do NOT compute sha256 (default: compute)")
    ap.add_argument("--max-bytes", type=int, default=0, help="abort if remote bigger than this (bytes); 0=disabled")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--timeout", type=int, default=60)
    ap.add_argument("--git-depth", type=int, default=1)
    ap.add_argument("--name", default=None, help="force base name for all outputs")
    ap.add_argument("--quiet", action="store_true", help="minimal terminal output")
    ap.add_argument("--no-pretty", action="store_true", help="write compact JSON lines instead of pretty multi-line JSON (default is pretty)")
    args = ap.parse_args()

    args.use_curl = not args.no_curl
    args.sha256 = not args.no_sha256
    args.out = os.path.abspath(args.out)
    args.log = os.path.abspath(args.log)
    args.pretty = not args.no_pretty
    args.name = args.name
    os.makedirs(args.out, exist_ok=True)

    log_event(args.log, "session_start", {"count": len(args.sources), "concurrency": args.concurrency, "timestamp": now_iso()}, args.pretty)

    with _status_lock:
        for s in args.sources:
            _status[s] = {"status":"queued","bytes":0,"total":None,"speed":0.0}

    printer = threading.Thread(target=print_table, args=(args.sources, args.quiet), daemon=True)
    printer.start()

    failures = []
    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as ex:
        futures = {ex.submit(process_source, src, args): src for src in args.sources}
        try:
            for fut in as_completed(futures):
                src = futures[fut]
                if _interrupt.is_set():
                    break
                try:
                    res = fut.result()
                    if not res.get("ok"):
                        failures.append({"source": src, "error": res.get("error")})
                        print(f"[ERROR] {src} -> {res.get('error')}", file=sys.stderr)
                except Exception as e:
                    failures.append({"source": src, "error": str(e)})
        except KeyboardInterrupt:
            _interrupt.set()
            log_event(args.log, "interrupted_main", {"timestamp": now_iso()}, args.pretty)
            cleanup_incomplete()
        finally:
            pass

    time.sleep(0.5)
    log_event(args.log, "session_end", {"failures": len(failures), "timestamp": now_iso()}, args.pretty)
    if failures:
        print(f"[DONE] completed with {len(failures)} failures. See {args.log}", file=sys.stderr)
        sys.exit(2)
    print(f"[DONE] all done. See {args.log}")
    sys.exit(0)

if __name__ == "__main__":
    main()
