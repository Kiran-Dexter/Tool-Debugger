#!/usr/bin/env python3
"""
analyze-crawl.py

Crawl one or more paths (file or directory). For each found item emit a JSONL event to --log or STDOUT.
For archive files (.tar, .tgz, .tar.gz, .tar.bz2, .zip, .gz) it lists members without extracting.

One JSON object per line (JSONL). Use --pretty to write multi-line pretty JSON blocks (still newline separated).

This variant includes an improved analyze_single_file() with shebang, file/python-magic, extension,
and content heuristics detection plus strong error handling.
"""
from __future__ import annotations
import argparse
import os
import sys
import json
import time
import tarfile
import zipfile
import struct
import mimetypes
import hashlib
import socket
import shutil
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any, List

# defaults
DEFAULT_MAX_MEMBERS = 1000  # per-archive members listing cap
READ_HEAD_BYTES = 16384     # amount to read from file head for heuristics

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

def session_id() -> str:
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def write_jsonl(path: Optional[str], obj: dict, pretty: bool, to_stdout: bool):
    try:
        s = json.dumps(obj, ensure_ascii=False, sort_keys=True, indent=2 if pretty else None)
    except Exception:
        # fallback: ensure we can always stringify something
        s = json.dumps({"_dump_error": "jsonify_failed", "obj_repr": repr(obj)})
    if to_stdout:
        try:
            sys.stdout.write(s)
            sys.stdout.write("\n\n" if pretty else "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"[write_err] stdout write failed: {e}\n")
        return
    try:
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(s)
            fh.write("\n\n" if pretty else "\n")
    except Exception as e:
        # If logging fails, fallback to stderr and stdout so user sees events
        sys.stderr.write(f"[logerr] failed writing to {path}: {e}\n")
        try:
            sys.stdout.write(s)
            sys.stdout.write("\n\n" if pretty else "\n")
            sys.stdout.flush()
        except Exception:
            pass

def safe_stat(path: str):
    try:
        return os.stat(path, follow_symlinks=False)
    except Exception:
        return None

def human_mode(mode: int) -> str:
    return oct(mode & 0o7777)

def guess_mime(path: str) -> Optional[str]:
    try:
        m, _ = mimetypes.guess_type(path)
        return m
    except Exception:
        return None

def read_gzip_header_original_name(path: str) -> Optional[str]:
    try:
        with open(path, "rb") as fh:
            hdr = fh.read(10)
            if len(hdr) < 10:
                return None
            flg = hdr[3]
            if (flg & 0x08) == 0:
                return None
            name_bytes = bytearray()
            while True:
                b = fh.read(1)
                if not b or b == b'\x00':
                    break
                name_bytes += b
            try:
                return name_bytes.decode("utf-8", errors="replace")
            except Exception:
                return name_bytes.decode("latin-1", errors="replace")
    except Exception:
        return None

def read_gzip_isize(path: str) -> Optional[int]:
    try:
        with open(path, "rb") as fh:
            fh.seek(-4, os.SEEK_END)
            last4 = fh.read(4)
            if len(last4) != 4:
                return None
            (isize,) = struct.unpack("<I", last4)
            return int(isize)
    except Exception:
        return None

def archive_list_tar(path: str, max_members: int, full: bool) -> Dict[str, Any]:
    members = []
    count = 0
    truncated = False
    try:
        with tarfile.open(path, mode="r:*") as tf:
            for ti in tf:
                count += 1
                if not full and len(members) >= max_members:
                    truncated = True
                    continue
                try:
                    member_info = {
                        "name": ti.name,
                        "size": ti.size,
                        "type": "dir" if ti.isdir() else ("link" if ti.issym() else "file"),
                        "mode": ti.mode,
                        "mtime": datetime.utcfromtimestamp(ti.mtime).isoformat() + "Z" if ti.mtime else None,
                    }
                except Exception:
                    member_info = {"name": getattr(ti, "name", "<err>"), "size": getattr(ti, "size", None)}
                members.append(member_info)
        return {"members_count": count, "truncated": truncated, "members_sample": members}
    except Exception as e:
        return {"error": f"tarlist-error: {e}"}

def archive_list_zip(path: str, max_members: int, full: bool) -> Dict[str, Any]:
    members = []
    count = 0
    truncated = False
    try:
        with zipfile.ZipFile(path, "r") as zf:
            for zi in zf.infolist():
                count += 1
                if not full and len(members) >= max_members:
                    truncated = True
                    continue
                try:
                    member_info = {
                        "name": zi.filename,
                        "size": zi.file_size,
                        "compress_size": zi.compress_size,
                        "type": "dir" if zi.is_dir() else "file",
                        "mtime": datetime(*zi.date_time).isoformat() + "Z",
                        "crc": zi.CRC,
                    }
                except Exception:
                    member_info = {"name": getattr(zi, "filename", "<err>")}
                members.append(member_info)
        return {"members_count": count, "truncated": truncated, "members_sample": members}
    except Exception as e:
        return {"error": f"ziplist-error: {e}"}

# -------------------------
# Improved analyzer with multiple heuristics + error handling
# -------------------------
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

def analyze_single_file(path: str, compute_sha: bool=False) -> Dict[str, Any]:
    """
    Robust file analysis:
      - Null-byte heuristic for binary vs text.
      - Shebang parsing -> script subtype.
      - Try python-magic (if installed) for MIME/language detection.
      - Try `file -b --mime-type` if available.
      - Large extension map for many languages.
      - Content heuristics (keywords/snippets) for many languages.
      - Returns: kind (script/text/binary/archive/...), subtype (bash/python/node...), mime, mode, mode_octal, sha256 (optional), confidence (0..1)
    """
    rec: Dict[str, Any] = {
        "path": path,
        "is_dir": False,
        "size": None,
        "executable": False,
        "mode": None,
        "mode_octal": None,
        "mime": None,
        "kind": None,
        "subtype": None,
        "confidence": 0.0,
    }

    try:
        st = safe_stat(path)
        if st:
            rec["size"] = st.st_size
            rec["executable"] = bool(st.st_mode & 0o111)
            rec["mode"] = human_mode(st.st_mode)
            rec["mode_octal"] = st.st_mode & 0o777
    except Exception:
        # keep going, we'll report limited metadata
        pass

    # read a bounded head
    head = b""
    try:
        with open(path, "rb") as fh:
            head = fh.read(READ_HEAD_BYTES)
    except Exception:
        head = b""

    # quick binary detection (null byte heuristic)
    try:
        if b'\x00' in head:
            subtype_guess = "elf" if head.startswith(b"\x7fELF") else "binary"
            rec.update({"kind": "binary", "subtype": subtype_guess, "confidence": 0.9})
            if shutil.which("file"):
                try:
                    out = subprocess.run(["file","-b","--mime-type", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
                    if out.returncode == 0:
                        rec["mime"] = out.stdout.strip()
                except Exception:
                    pass
            if compute_sha:
                rec["sha256"] = sha256_file(path)
            return rec
    except Exception:
        # if something odd happens with the head, continue cautiously
        pass

    # helpers: shebang parse
    shebang = None
    firstline = ""
    try:
        firstline = head.splitlines()[0].decode("utf-8", errors="ignore") if head else ""
        if firstline.startswith("#!"):
            shebang = firstline[2:].strip()
    except Exception:
        shebang = None

    def map_interpreter_to_subtype(interp: str):
        parts = interp.split()
        interpreter = parts[0] if parts else interp
        if interpreter.endswith("env") and len(parts) > 1:
            interpreter = parts[1]
        base = os.path.basename(interpreter).lower()
        mapping = {
            "bash":"bash","sh":"sh","dash":"sh","ksh":"ksh","zsh":"zsh",
            "python":"python","python2":"python","python3":"python",
            "perl":"perl","ruby":"ruby","php":"php","node":"node","nodejs":"node",
            "awk":"awk","gawk":"awk","mawk":"awk","tcl":"tcl","lua":"lua",
            "pwsh":"powershell","powershell":"powershell",
            "r":"r","groovy":"groovy","scala":"scala","java":"java",
        }
        for k,v in mapping.items():
            if base.startswith(k):
                return v
        return base or None

    # large extension map (expanded)
    ext_map = {
        ".sh":("script","sh"), ".bash":("script","bash"), ".zsh":("script","zsh"), ".ksh":("script","ksh"),
        ".csh":("script","csh"), ".tcsh":("script","csh"), ".ps1":("script","powershell"),
        ".py":("script","python"), ".pyw":("script","python"),
        ".rb":("script","ruby"), ".pl":("script","perl"), ".pm":("script","perl"),
        ".php":("script","php"), ".phtml":("script","php"),
        ".js":("script","node"), ".mjs":("script","node"), ".cjs":("script","node"),
        ".ts":("script","typescript"),
        ".c":("source","c"), ".h":("source","c"), ".cpp":("source","cpp"), ".cc":("source","cpp"), ".hpp":("source","cpp"),
        ".java":("source","java"), ".scala":("source","scala"),
        ".go":("source","go"), ".rs":("source","rust"),
        ".awk":("script","awk"), ".sed":("script","sed"), ".lua":("script","lua"), ".r":("script","r"),
        ".xml":("markup","xml"), ".html":("markup","html"), ".htm":("markup","html"),
        ".json":("data","json"), ".yml":("data","yaml"), ".yaml":("data","yaml"),
        ".tar":("archive","tar"), ".tgz":("archive","tar"), ".tar.gz":("archive","tar"),
        ".zip":("archive","zip"), ".gz":("archive","gzip"), ".bz2":("archive","bzip2"),
        ".pdf":("document","pdf"), ".md":("document","markdown"), ".markdown":("document","markdown"),
        ".png":("image","png"), ".jpg":("image","jpeg"), ".jpeg":("image","jpeg"),
        ".exe":("binary","exe"),
    }

    # 1) Shebang -> strong detection
    try:
        if shebang:
            subtype = map_interpreter_to_subtype(shebang)
            if subtype:
                rec["kind"] = "script"
                rec["subtype"] = subtype
                rec["confidence"] = 1.0
                if shutil.which("file"):
                    try:
                        out = subprocess.run(["file","-b","--mime-type", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
                        if out.returncode == 0:
                            rec["mime"] = out.stdout.strip()
                    except Exception:
                        pass
                if compute_sha:
                    rec["sha256"] = sha256_file(path)
                return rec
    except Exception:
        # continue if shebang parsing fails
        pass

    # 2) try python-magic if installed (best MIME)
    try:
        import magic as _magic  # python-magic
        try:
            m = _magic.Magic(mime=True)
            mm = m.from_buffer(head) or None
            if mm:
                rec["mime"] = mm
        except Exception:
            try:
                mm = _magic.from_buffer(head)
                if mm:
                    rec["mime"] = mm
            except Exception:
                pass
    except Exception:
        pass

    # 3) try 'file' binary if available (useful hint)
    if not rec.get("mime") and shutil.which("file"):
        try:
            out = subprocess.run(["file","-b","--mime-type", path], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=2)
            if out.returncode == 0:
                rec["mime"] = out.stdout.strip()
        except Exception:
            pass

    # 4) extension-based fallback
    try:
        _, ext = os.path.splitext(path.lower())
        if ext in ext_map and not rec.get("kind"):
            rec["kind"], rec["subtype"] = ext_map[ext]
            rec["confidence"] = max(rec["confidence"], 0.6)
    except Exception:
        pass

    # 5) content heuristics: search head for signatures / keywords
    content = ""
    try:
        content = head.decode("utf-8", errors="ignore").lower()
    except Exception:
        content = ""
    heuristics = [
        ("python", ["def ", "import ", "if __name__ == '__main__'", "print("]),
        ("perl", ["use strict", "use warnings", "perl -e", "sub "]),
        ("ruby", ["require '", "def ", "end", "puts "]),
        ("php", ["<?php", "echo ", "$_get", "$_post"]),
        ("node", ["require(", "console.log", "module.exports", "exports.", "process.argv"]),
        ("java", ["public class ", "import java.", "package "]),
        ("c", ["#include <", "int main(", "printf("]),
        ("cpp", ["#include <", "std::", "int main("]),
        ("go", ["package main", "func main()", "import ("]),
        ("rust", ["fn main()", "extern crate", "use std::"]),
        ("bash", ["#!/bin/bash", "bash -c", "set -e", "sudo "]),
        ("sh", ["#!/bin/sh", "sh -c"]),
        ("powershell", ["param(", "write-host", "get-childitem", "powershell"]),
        ("awk", ["awk '", "BEGIN {", "print $0"]),
        ("xml", ["<?xml", "<!--"]),
        ("html", ["<!doctype html", "<html", "<head>"]),
        ("json", ["{", '":', '"key"']),
    ]
    try:
        for lang, tokens in heuristics:
            for t in tokens:
                if t in content:
                    if not rec.get("kind"):
                        if lang in ("bash","sh","powershell","awk","php","node","python","perl","ruby"):
                            rec["kind"] = "script"
                        elif lang in ("xml","html"):
                            rec["kind"] = "markup"
                        elif lang == "json":
                            rec["kind"] = "data"
                        else:
                            rec["kind"] = "source"
                    rec["subtype"] = rec.get("subtype") or lang
                    rec["confidence"] = max(rec["confidence"], 0.8 if lang in ("python","bash","php","node","perl","ruby") else 0.6)
                    break
            if rec.get("subtype") == lang:
                break
    except Exception:
        pass

    # 6) final fallback: if still nothing, default to text
    try:
        if not rec.get("kind"):
            rec["kind"] = "text"
            rec["subtype"] = "text"
            rec["confidence"] = max(rec["confidence"], 0.4)
    except Exception:
        rec["kind"] = "unknown"
        rec["subtype"] = "unknown"
        rec["confidence"] = 0.0

    # 7) final mime guess via mimetypes if still empty
    try:
        if not rec.get("mime"):
            m, _ = mimetypes.guess_type(path)
            if m:
                rec["mime"] = m
    except Exception:
        pass

    # sha if requested
    try:
        if compute_sha:
            rec["sha256"] = sha256_file(path)
    except Exception:
        rec["sha256"] = None

    return rec

# -------------------------
# Core processing (unchanged flow, robust error handling)
# -------------------------
def process_root(root_path: str, logpath: Optional[str], max_members:int, full_archive:bool, pretty:bool, compute_sha:bool, to_stdout:bool, max_file_size:Optional[int], sessid:str):
    host = None
    try:
        host = socket.gethostname()
    except Exception:
        host = "unknown"
    start_event = {"ts": now_iso(), "event": "session_start", "details":{"root": root_path, "session_id": sessid, "host": host}}
    write_jsonl(logpath, start_event, pretty, to_stdout)

    to_process: List[str] = []
    if os.path.isdir(root_path):
        for dirpath, dirnames, filenames in os.walk(root_path):
            dirnames.sort()
            filenames.sort()
            dirinfo = {"path": dirpath, "is_dir": True, "entries_count": len(dirnames) + len(filenames)}
            write_jsonl(logpath, {"ts": now_iso(), "event": "path_discovered", "details": dirinfo}, pretty, to_stdout)
            for fn in filenames:
                try:
                    to_process.append(os.path.join(dirpath, fn))
                except Exception:
                    continue
    elif os.path.isfile(root_path):
        to_process.append(root_path)
    else:
        write_jsonl(logpath, {"ts": now_iso(), "event": "error", "details": {"path": root_path, "error": "not found or unsupported"}}, pretty, to_stdout)
        return

    processed = 0
    for p in sorted(to_process):
        processed += 1
        try:
            st = safe_stat(p)
            if max_file_size and st and st.st_size and st.st_size > max_file_size:
                write_jsonl(logpath, {"ts": now_iso(), "event": "skipped_large_file", "details": {"path": p, "size": st.st_size}}, pretty, to_stdout)
                continue

            write_jsonl(logpath, {"ts": now_iso(), "event": "file_entry", "details": {"path": p}}, pretty, to_stdout)
            meta = analyze_single_file(p, compute_sha=False)
            write_jsonl(logpath, {"ts": now_iso(), "event": "file_metadata", "details": meta}, pretty, to_stdout)

            lowered = p.lower()
            if tarfile.is_tarfile(p):
                listed = archive_list_tar(p, max_members=max_members, full=full_archive)
                write_jsonl(logpath, {"ts": now_iso(), "event": "archive_listing", "details": {"path": p, "format":"tar", **listed}}, pretty, to_stdout)
            elif zipfile.is_zipfile(p):
                listed = archive_list_zip(p, max_members=max_members, full=full_archive)
                write_jsonl(logpath, {"ts": now_iso(), "event": "archive_listing", "details": {"path": p, "format":"zip", **listed}}, pretty, to_stdout)
            elif lowered.endswith(".gz"):
                gname = read_gzip_header_original_name(p)
                gisize = read_gzip_isize(p)
                write_jsonl(logpath, {"ts": now_iso(), "event": "gzip_info", "details": {"path": p, "original_name": gname, "isize_mod_2_32": gisize}}, pretty, to_stdout)

            if compute_sha:
                meta_sha = analyze_single_file(p, compute_sha=True)
                write_jsonl(logpath, {"ts": now_iso(), "event": "file_sha", "details": {"path": p, "sha256": meta_sha.get("sha256")}}, pretty, to_stdout)

        except Exception as e:
            # per-file failure should not stop the whole crawl
            write_jsonl(logpath, {"ts": now_iso(), "event": "file_error", "details": {"path": p, "error": str(e)}}, pretty, to_stdout)
            continue

    write_jsonl(logpath, {"ts": now_iso(), "event": "session_end", "details": {"root": root_path, "processed": processed, "session_id": sessid, "processed_at": now_iso()}}, pretty, to_stdout)

# -------------------------
# CLI
# -------------------------
def parse_args():
    ap = argparse.ArgumentParser(description="Crawl path(s) and list files + archive contents (no extraction). Emits JSONL.")
    ap.add_argument("paths", nargs="+", help="file(s) or directory(ies) to crawl")
    ap.add_argument("--log", "-l", required=False, help="output JSONL log file (append mode). Omit to use --stdout")
    ap.add_argument("--max-members", type=int, default=DEFAULT_MAX_MEMBERS, help=f"max archive members to include (default {DEFAULT_MAX_MEMBERS})")
    ap.add_argument("--full-archive", action="store_true", help="list full archive members (no cap)")
    ap.add_argument("--pretty", action="store_true", help="pretty-print JSON blocks (multi-line) instead of single-line JSONL")
    ap.add_argument("--sha256", action="store_true", help="compute SHA256 for regular files (may be IO-heavy)")
    ap.add_argument("--stdout", action="store_true", help="write JSONL to STDOUT instead of to --log")
    ap.add_argument("--max-file-size", type=int, default=0, help="skip files bigger than this many bytes (0 = disabled)")
    return ap.parse_args()

def main():
    args = parse_args()
    to_stdout = bool(args.stdout)
    if not to_stdout and not args.log:
        sys.stderr.write("Either --log or --stdout is required.\n")
        sys.exit(2)
    logpath = None if to_stdout else os.path.abspath(args.log)
    if logpath:
        try:
            os.makedirs(os.path.dirname(logpath) or ".", exist_ok=True)
        except Exception:
            pass

    sessid = session_id()
    try:
        for root in args.paths:
            root_path = os.path.abspath(root)
            process_root(root_path, logpath, max_members=args.max_members, full_archive=args.full_archive, pretty=args.pretty, compute_sha=args.sha256, to_stdout=to_stdout, max_file_size=(args.max_file_size or None), sessid=sessid)
    except KeyboardInterrupt:
        write_jsonl(logpath, {"ts": now_iso(), "event": "interrupted", "details": {"session_id": sessid}}, args.pretty, to_stdout)
        sys.stderr.write("Interrupted, exiting.\n")
        sys.exit(130)
    except Exception as e:
        write_jsonl(logpath, {"ts": now_iso(), "event": "fatal_error", "details": {"error": str(e), "session_id": sessid}}, args.pretty, to_stdout)
        sys.stderr.write("Fatal error: " + str(e) + "\n")
        sys.exit(2)

if __name__ == "__main__":
    main()
