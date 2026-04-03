#!/usr/bin/env python3
"""
smart_npm_audit_crawler.py

Purpose:
    Discover Node.js projects on Linux, collect npm audit evidence plus local
    project indicators, and export a consolidated JSON report for offline review
   
    - Tries local project npm first, then global npm in PATH
    - Runs:
        * npm audit --json
        * npm audit signatures
        * npm ls --all --json

"""

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# =============================================================================
# DEFAULT CONFIG
# =============================================================================

DEFAULT_SCAN_ROOTS = [
    "/home",
    "/opt",
    "/srv",
    "/var/www",
    "/usr/local",
]

DEFAULT_EXCLUDE_DIRS = {
    "node_modules",
    ".git",
    ".svn",
    ".hg",
    ".cache",
    ".npm",
    ".yarn",
    ".pnpm-store",
    "__pycache__",
    ".venv",
    "venv",
    "dist",
    "build",
    "coverage",
}

DEFAULT_SKIP_PATH_PREFIXES = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/tmp",
    "/var/tmp",
    "/boot",
    "/snap",
    "/lib",
    "/lib64",
    "/bin",
    "/sbin",
    "/usr/bin",
    "/usr/sbin",
    "/usr/lib",
    "/usr/lib64",
    "/var/lib",
    "/var/cache",
    "/var/log",
}

DEFAULT_SKIP_FS_TYPES = {
    "proc",
    "sysfs",
    "devtmpfs",
    "devpts",
    "tmpfs",
    "cgroup",
    "cgroup2",
    "overlay",
    "squashfs",
    "debugfs",
    "tracefs",
    "securityfs",
    "ramfs",
    "autofs",
    "mqueue",
    "hugetlbfs",
    "fusectl",
    "configfs",
    "nsfs",
    "pstore",
}

DEFAULT_MAX_FILE_SIZE = 2 * 1024 * 1024  # 2 MB
DEFAULT_MAX_PROJECTS = 500
DEFAULT_TIMEOUT = 180
DEFAULT_FILE_SCAN_LIMIT = 300

TEXT_FILE_EXTENSIONS = {
    ".js", ".cjs", ".mjs", ".ts", ".json", ".sh", ".bash", ".zsh", ".yaml", ".yml", ".txt"
}

SUSPICIOUS_REGEXES = {
    "lifecycle_script_names": re.compile(r'"(preinstall|install|postinstall)"\s*:', re.IGNORECASE),
    "child_process": re.compile(r'\bchild_process\b|\bexec\s*\(|\bspawn\s*\(|\bexecFile\s*\(', re.IGNORECASE),
    "shell_download_exec": re.compile(r'\bcurl\b|\bwget\b|\bbash\b|\bsh\b|\bpowershell\b', re.IGNORECASE),
    "obfuscation_eval": re.compile(r'\beval\s*\(|\bFunction\s*\(|\batob\s*\(|fromCharCode\s*\(', re.IGNORECASE),
    "base64_like": re.compile(r'base64|Buffer\.from\s*\(.*base64', re.IGNORECASE),
    "network_calls": re.compile(r'http://|https://|\bfetch\s*\(|axios|XMLHttpRequest|net\.connect|tls\.connect', re.IGNORECASE),
    "env_access": re.compile(r'process\.env|os\.environ', re.IGNORECASE),
    "fs_sensitive": re.compile(r'\bfs\.(readFile|writeFile|appendFile|createWriteStream|rm|unlink|rmdir)\b', re.IGNORECASE),
}


# =============================================================================
# UTILITY
# =============================================================================

def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def which(binary: str) -> Optional[str]:
    return shutil.which(binary)


def safe_json_dump(path: Path, data: Any, pretty: bool = True) -> Tuple[bool, Optional[str]]:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8") as f:
            if pretty:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                json.dump(data, f, separators=(",", ":"), ensure_ascii=False)
        return True, None
    except Exception as exc:
        return False, str(exc)


def safe_read_text(path: Path, max_bytes: int = DEFAULT_MAX_FILE_SIZE) -> Tuple[Optional[str], Optional[str]]:
    try:
        if not path.exists():
            return None, "path does not exist"
        if not path.is_file():
            return None, "not a file"
        size = path.stat().st_size
        if size > max_bytes:
            return None, f"file too large (> {max_bytes} bytes)"
        with path.open("r", encoding="utf-8", errors="ignore") as f:
            return f.read(), None
    except PermissionError:
        return None, "permission denied"
    except Exception as exc:
        return None, str(exc)


def safe_read_json(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    content, err = safe_read_text(path)
    if err:
        return None, err
    try:
        return json.loads(content), None
    except Exception as exc:
        return None, f"json parse error: {exc}"


def path_owner_info(path: Path) -> Dict[str, Any]:
    try:
        st = path.stat()
        return {
            "uid": st.st_uid,
            "gid": st.st_gid,
            "mode_octal": oct(stat.S_IMODE(st.st_mode)),
            "readable": os.access(path, os.R_OK),
            "writable": os.access(path, os.W_OK),
            "executable": os.access(path, os.X_OK),
        }
    except Exception as exc:
        return {"error": str(exc)}


def is_excluded_dir(dirname: str, custom_excludes: set[str]) -> bool:
    return dirname in custom_excludes


def is_text_candidate(path: Path) -> bool:
    return path.suffix.lower() in TEXT_FILE_EXTENSIONS


# =============================================================================
# MOUNT / PATH POLICY
# =============================================================================

def read_mount_table() -> List[Dict[str, str]]:
    mounts: List[Dict[str, str]] = []
    try:
        with open("/proc/mounts", "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3:
                    mounts.append({
                        "device": parts[0],
                        "mount_point": parts[1],
                        "fs_type": parts[2],
                    })
    except Exception:
        pass
    return mounts


def build_unwanted_mount_points(
    mounts: List[Dict[str, str]],
    skip_fs_types: set[str],
    allowed_roots: List[Path],
) -> set[str]:
    allowed_root_strs = []
    for p in allowed_roots:
        try:
            allowed_root_strs.append(str(p.resolve()))
        except Exception:
            allowed_root_strs.append(str(p))

    skipped = set()

    for m in mounts:
        mp = m.get("mount_point", "")
        fs_type = m.get("fs_type", "")

        if not mp:
            continue

        if fs_type in skip_fs_types:
            skipped.add(mp)
            continue

        try:
            mp_real = str(Path(mp).resolve()) if os.path.exists(mp) else mp
        except Exception:
            mp_real = mp

        # If mount is inside allowed root and fs type is not explicitly skipped, keep it.
        if any(mp_real == r or mp_real.startswith(r + "/") for r in allowed_root_strs):
            continue

    return skipped


def should_skip_path(path: Path, skip_prefixes: set[str], skipped_mounts: set[str]) -> bool:
    p = str(path)

    for prefix in skip_prefixes:
        if p == prefix or p.startswith(prefix + "/"):
            return True

    for mp in skipped_mounts:
        if p == mp or p.startswith(mp + "/"):
            return True

    return False


# =============================================================================
# COMMAND EXECUTION
# =============================================================================

def run_command(
    cmd: List[str],
    cwd: Path,
    timeout: int = DEFAULT_TIMEOUT,
    env: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    started = time.time()

    result = {
        "command": cmd,
        "cwd": str(cwd),
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "duration_seconds": None,
        "timed_out": False,
        "error": None,
    }

    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            env=env,
        )
        result["returncode"] = proc.returncode
        result["stdout"] = proc.stdout
        result["stderr"] = proc.stderr
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    except subprocess.TimeoutExpired as exc:
        result["stdout"] = exc.stdout or ""
        result["stderr"] = exc.stderr or ""
        result["timed_out"] = True
        result["error"] = f"timeout after {timeout}s"
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    except FileNotFoundError as exc:
        result["error"] = f"binary not found: {exc}"
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    except PermissionError:
        result["error"] = "permission denied"
        result["duration_seconds"] = round(time.time() - started, 3)
        return result
    except Exception as exc:
        result["error"] = str(exc)
        result["duration_seconds"] = round(time.time() - started, 3)
        return result


def parse_json_from_stdout(stdout: str) -> Tuple[Optional[Any], Optional[str]]:
    if not stdout or not stdout.strip():
        return None, "empty stdout"
    try:
        return json.loads(stdout), None
    except Exception as exc:
        return None, f"json parse error: {exc}"


# =============================================================================
# DISCOVERY
# =============================================================================

def discover_projects(
    roots: List[Path],
    exclude_dirs: set[str],
    max_projects: int,
    skip_prefixes: set[str],
    skipped_mounts: set[str],
) -> Dict[str, Any]:
    found: List[Path] = []
    errors: List[Dict[str, str]] = []

    for root in roots:
        try:
            root = root.resolve()
        except Exception:
            pass

        if not root.exists():
            errors.append({"path": str(root), "error": "root does not exist"})
            continue

        if not root.is_dir():
            errors.append({"path": str(root), "error": "root is not directory"})
            continue

        if should_skip_path(root, skip_prefixes, skipped_mounts):
            errors.append({"path": str(root), "error": "root skipped by policy"})
            continue

        try:
            for dirpath, dirnames, filenames in os.walk(root, topdown=True, onerror=None, followlinks=False):
                current = Path(dirpath)

                if should_skip_path(current, skip_prefixes, skipped_mounts):
                    dirnames[:] = []
                    continue

                dirnames[:] = [
                    d for d in dirnames
                    if not is_excluded_dir(d, exclude_dirs)
                    and not should_skip_path(current / d, skip_prefixes, skipped_mounts)
                ]

                if "package.json" in filenames:
                    found.append(current)
                    if len(found) >= max_projects:
                        return {
                            "projects": found,
                            "truncated": True,
                            "errors": errors,
                        }
        except PermissionError:
            errors.append({"path": str(root), "error": "permission denied during walk"})
        except Exception as exc:
            errors.append({"path": str(root), "error": str(exc)})

    return {
        "projects": found,
        "truncated": False,
        "errors": errors,
    }


# =============================================================================
# PACKAGE INSPECTION
# =============================================================================

def classify_dependency_source(version_str: str) -> str:
    if not isinstance(version_str, str):
        return "unknown"

    v = version_str.strip()

    if v.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or "github.com" in v:
        return "git"
    if v.startswith(("http://", "https://")):
        return "url"
    if v.startswith(("file:", "link:")):
        return "file"

    return "registry_or_range"


def inspect_package_json(project_dir: Path) -> Dict[str, Any]:
    package_json_path = project_dir / "package.json"
    data, err = safe_read_json(package_json_path)

    result: Dict[str, Any] = {
        "path": str(package_json_path),
        "parse_error": err,
        "raw_loaded": isinstance(data, dict),
        "project_summary": {},
        "lifecycle_scripts": {},
        "dependency_source_flags": {
            "git": [],
            "url": [],
            "file": [],
        },
        "interesting_scripts": [],
    }

    if not isinstance(data, dict):
        return result

    scripts = data.get("scripts", {}) if isinstance(data.get("scripts"), dict) else {}
    deps_buckets = {
        "dependencies": data.get("dependencies", {}),
        "devDependencies": data.get("devDependencies", {}),
        "optionalDependencies": data.get("optionalDependencies", {}),
        "peerDependencies": data.get("peerDependencies", {}),
    }

    result["project_summary"] = {
        "name": data.get("name"),
        "version": data.get("version"),
        "private": data.get("private"),
        "description": data.get("description"),
        "license": data.get("license"),
        "package_manager": data.get("packageManager"),
        "dependency_counts": {
            k: len(v) if isinstance(v, dict) else 0
            for k, v in deps_buckets.items()
        }
    }

    for k in ("preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishOnly"):
        if k in scripts:
            result["lifecycle_scripts"][k] = scripts[k]

    for script_name, script_cmd in scripts.items():
        cmd_text = str(script_cmd).lower()
        if any(token in cmd_text for token in ["curl", "wget", "bash", " sh ", "powershell", "node "]):
            result["interesting_scripts"].append({
                "script": script_name,
                "command": script_cmd,
            })

    for bucket_name, deps in deps_buckets.items():
        if not isinstance(deps, dict):
            continue

        for pkg_name, version_spec in deps.items():
            src = classify_dependency_source(version_spec)
            if src in result["dependency_source_flags"]:
                result["dependency_source_flags"][src].append({
                    "bucket": bucket_name,
                    "package": pkg_name,
                    "spec": version_spec,
                })

    return result


# =============================================================================
# FILE SCAN
# =============================================================================

def gather_candidate_files(
    project_dir: Path,
    exclude_dirs: set[str],
    limit: int,
    skip_prefixes: set[str],
    skipped_mounts: set[str],
) -> List[Path]:
    out: List[Path] = []

    try:
        for dirpath, dirnames, filenames in os.walk(project_dir, topdown=True, onerror=None, followlinks=False):
            current = Path(dirpath)

            if should_skip_path(current, skip_prefixes, skipped_mounts):
                dirnames[:] = []
                continue

            dirnames[:] = [
                d for d in dirnames
                if not is_excluded_dir(d, exclude_dirs)
                and not should_skip_path(current / d, skip_prefixes, skipped_mounts)
            ]

            for filename in filenames:
                p = current / filename
                if is_text_candidate(p):
                    out.append(p)
                    if len(out) >= limit:
                        return out
    except Exception:
        pass

    return out


def inspect_files_for_suspicious_patterns(
    project_dir: Path,
    exclude_dirs: set[str],
    file_limit: int,
    skip_prefixes: set[str],
    skipped_mounts: set[str],
) -> Dict[str, Any]:
    files = gather_candidate_files(
        project_dir=project_dir,
        exclude_dirs=exclude_dirs,
        limit=file_limit,
        skip_prefixes=skip_prefixes,
        skipped_mounts=skipped_mounts,
    )

    matches: Dict[str, List[Dict[str, Any]]] = {k: [] for k in SUSPICIOUS_REGEXES.keys()}
    scan_errors: List[Dict[str, str]] = []

    for path in files:
        text, err = safe_read_text(path)
        if err:
            scan_errors.append({"path": str(path), "error": err})
            continue
        if text is None:
            continue

        lines = text.splitlines()

        for rule_name, regex in SUSPICIOUS_REGEXES.items():
            count = 0
            evidence = []

            for idx, line in enumerate(lines, 1):
                if regex.search(line):
                    count += 1
                    if len(evidence) < 5:
                        evidence.append({
                            "line": idx,
                            "snippet": line[:500],
                        })

            if count > 0:
                matches[rule_name].append({
                    "file": str(path),
                    "count": count,
                    "evidence": evidence,
                })

    return {
        "files_scanned": len(files),
        "files_considered": [str(p) for p in files[:50]],
        "truncated_file_listing": len(files) > 50,
        "matches": matches,
        "scan_errors": scan_errors[:50],
    }


# =============================================================================
# NPM EXECUTION STRATEGY
# =============================================================================

def detect_local_npm(project_dir: Path) -> Optional[str]:
    candidate = project_dir / "node_modules" / ".bin" / "npm"
    if candidate.exists() and os.access(candidate, os.X_OK):
        return str(candidate)
    return None


def build_execution_candidates(project_dir: Path) -> List[Dict[str, Any]]:
    candidates = []

    local_npm = detect_local_npm(project_dir)
    if local_npm:
        candidates.append({
            "label": "local_node_modules_bin_npm",
            "npm_path": local_npm,
        })

    global_npm = which("npm")
    if global_npm:
        candidates.append({
            "label": "global_npm_in_path",
            "npm_path": global_npm,
        })

    seen = set()
    final = []
    for c in candidates:
        p = c["npm_path"]
        if p not in seen:
            seen.add(p)
            final.append(c)

    return final


def run_npm_audit_bundle(project_dir: Path, timeout: int) -> Dict[str, Any]:
    candidates = build_execution_candidates(project_dir)
    attempts = []

    if not candidates:
        return {
            "used_candidate": None,
            "attempts": [],
            "fatal_error": "no npm binary found",
        }

    for candidate in candidates:
        npm_path = candidate["npm_path"]

        audit_exec = run_command([npm_path, "audit", "--json"], cwd=project_dir, timeout=timeout)
        audit_json, audit_parse_error = parse_json_from_stdout(audit_exec.get("stdout", ""))

        sig_exec = run_command([npm_path, "audit", "signatures"], cwd=project_dir, timeout=timeout)

        ls_exec = run_command([npm_path, "ls", "--all", "--json"], cwd=project_dir, timeout=timeout)
        ls_json, ls_parse_error = parse_json_from_stdout(ls_exec.get("stdout", ""))

        attempt = {
            "candidate": candidate,
            "npm_audit": audit_exec,
            "npm_audit_parsed": audit_json,
            "npm_audit_parse_error": audit_parse_error,
            "npm_audit_signatures": sig_exec,
            "npm_ls": ls_exec,
            "npm_ls_parsed": ls_json,
            "npm_ls_parse_error": ls_parse_error,
        }
        attempts.append(attempt)

        # Good enough if command executed and returned any code, even if audit found vulns.
        if audit_exec.get("returncode") is not None:
            return {
                "used_candidate": candidate,
                "attempts": attempts,
                "fatal_error": None,
            }

    return {
        "used_candidate": None,
        "attempts": attempts,
        "fatal_error": "all npm execution strategies failed",
    }


# =============================================================================
# AUDIT SUMMARY
# =============================================================================

def summarize_audit_json(audit_json: Any) -> Dict[str, Any]:
    out = {
        "audit_report_version": None,
        "severity_counts": {
            "info": 0,
            "low": 0,
            "moderate": 0,
            "high": 0,
            "critical": 0,
            "total": None,
        },
        "packages_flagged": 0,
        "top_packages": [],
        "summary_error": None,
    }

    if not isinstance(audit_json, dict):
        out["summary_error"] = "audit json not dict"
        return out

    out["audit_report_version"] = audit_json.get("auditReportVersion")
    meta = audit_json.get("metadata", {})
    vul_meta = meta.get("vulnerabilities", {}) if isinstance(meta, dict) else {}

    if isinstance(vul_meta, dict):
        for key in ["info", "low", "moderate", "high", "critical", "total"]:
            if key in vul_meta:
                out["severity_counts"][key] = vul_meta.get(key)

    vulns = audit_json.get("vulnerabilities", {})
    if isinstance(vulns, dict):
        out["packages_flagged"] = len(vulns)
        tmp = []
        for pkg_name, pkg_data in vulns.items():
            if not isinstance(pkg_data, dict):
                continue

            tmp.append({
                "name": pkg_name,
                "severity": pkg_data.get("severity"),
                "range": pkg_data.get("range"),
                "is_direct": pkg_data.get("isDirect"),
                "fix_available": pkg_data.get("fixAvailable"),
                "via_count": len(pkg_data.get("via", [])) if isinstance(pkg_data.get("via"), list) else None,
                "nodes_count": len(pkg_data.get("nodes", [])) if isinstance(pkg_data.get("nodes"), list) else None,
            })

        sev_order = {"critical": 5, "high": 4, "moderate": 3, "low": 2, "info": 1, None: 0}
        tmp.sort(key=lambda x: sev_order.get(x.get("severity"), 0), reverse=True)
        out["top_packages"] = tmp[:25]

    return out


# =============================================================================
# PER-PROJECT PROCESSING
# =============================================================================

def process_project(
    project_dir: Path,
    exclude_dirs: set[str],
    timeout: int,
    file_limit: int,
    skip_prefixes: set[str],
    skipped_mounts: set[str],
) -> Dict[str, Any]:
    report: Dict[str, Any] = {
        "project_dir": str(project_dir),
        "scanned_at_utc": now_utc(),
        "owner_info": path_owner_info(project_dir),
        "package_inspection": {},
        "npm_bundle": {},
        "audit_summary": {},
        "suspicious_scan": {},
        "errors": [],
    }

    try:
        report["package_inspection"] = inspect_package_json(project_dir)

        npm_bundle = run_npm_audit_bundle(project_dir, timeout=timeout)
        report["npm_bundle"] = npm_bundle

        parsed_audit = None
        if npm_bundle.get("attempts"):
            last = npm_bundle["attempts"][-1]
            parsed_audit = last.get("npm_audit_parsed")

        report["audit_summary"] = summarize_audit_json(parsed_audit)

        report["suspicious_scan"] = inspect_files_for_suspicious_patterns(
            project_dir=project_dir,
            exclude_dirs=exclude_dirs,
            file_limit=file_limit,
            skip_prefixes=skip_prefixes,
            skipped_mounts=skipped_mounts,
        )

        if npm_bundle.get("fatal_error"):
            report["errors"].append(npm_bundle["fatal_error"])

    except Exception as exc:
        report["errors"].append(str(exc))

    return report


# =============================================================================
# GLOBAL SUMMARY
# =============================================================================

def summarize_all_projects(project_reports: List[Dict[str, Any]]) -> Dict[str, Any]:
    summary = {
        "projects_total": len(project_reports),
        "projects_with_audit_data": 0,
        "projects_with_errors": 0,
        "projects_with_lifecycle_scripts": 0,
        "projects_with_git_dependencies": 0,
        "projects_with_url_dependencies": 0,
        "projects_with_file_dependencies": 0,
        "projects_with_suspicious_patterns": 0,
        "vulnerability_totals": {
            "critical": 0,
            "high": 0,
            "moderate": 0,
            "low": 0,
            "info": 0,
        },
        "top_projects_by_vulnerabilities": [],
    }

    tmp = []

    for pr in project_reports:
        if pr.get("errors"):
            summary["projects_with_errors"] += 1

        audit_summary = pr.get("audit_summary", {})
        sev = audit_summary.get("severity_counts", {})

        if audit_summary and audit_summary.get("summary_error") != "audit json not dict":
            summary["projects_with_audit_data"] += 1

        for key in ["critical", "high", "moderate", "low", "info"]:
            summary["vulnerability_totals"][key] += int(sev.get(key) or 0)

        pkg = pr.get("package_inspection", {})
        lifecycle = pkg.get("lifecycle_scripts", {})
        dep_flags = pkg.get("dependency_source_flags", {})

        if lifecycle:
            summary["projects_with_lifecycle_scripts"] += 1
        if dep_flags.get("git"):
            summary["projects_with_git_dependencies"] += 1
        if dep_flags.get("url"):
            summary["projects_with_url_dependencies"] += 1
        if dep_flags.get("file"):
            summary["projects_with_file_dependencies"] += 1

        suspicious = pr.get("suspicious_scan", {}).get("matches", {})
        suspicious_hit = any(bool(v) for v in suspicious.values()) if isinstance(suspicious, dict) else False
        if suspicious_hit:
            summary["projects_with_suspicious_patterns"] += 1

        tmp.append({
            "project_dir": pr.get("project_dir"),
            "critical": int(sev.get("critical") or 0),
            "high": int(sev.get("high") or 0),
            "moderate": int(sev.get("moderate") or 0),
            "low": int(sev.get("low") or 0),
            "has_lifecycle_scripts": bool(lifecycle),
            "has_suspicious_patterns": suspicious_hit,
            "has_errors": bool(pr.get("errors")),
        })

    tmp.sort(
        key=lambda x: (x["critical"], x["high"], x["moderate"], x["low"]),
        reverse=True
    )
    summary["top_projects_by_vulnerabilities"] = tmp[:50]

    return summary


# =============================================================================
# ARGUMENTS
# =============================================================================

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Linux npm audit crawler with JSON export for offline/AI analysis."
    )

    parser.add_argument(
        "--roots",
        nargs="+",
        default=DEFAULT_SCAN_ROOTS,
        help=f"Roots to scan. Default: {' '.join(DEFAULT_SCAN_ROOTS)}"
    )
    parser.add_argument(
        "--extra-roots",
        nargs="*",
        default=[],
        help="Additional roots to scan"
    )
    parser.add_argument(
        "--skip-prefixes",
        nargs="*",
        default=[],
        help="Additional path prefixes to skip"
    )
    parser.add_argument(
        "--skip-fs-types",
        nargs="*",
        default=[],
        help="Additional filesystem types to skip"
    )
    parser.add_argument(
        "--exclude",
        nargs="*",
        default=[],
        help="Additional directory names to exclude"
    )
    parser.add_argument(
        "-o", "--output",
        required=True,
        help="Output JSON file path"
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT,
        help=f"Per npm command timeout in seconds. Default: {DEFAULT_TIMEOUT}"
    )
    parser.add_argument(
        "--max-projects",
        type=int,
        default=DEFAULT_MAX_PROJECTS,
        help=f"Maximum projects to process. Default: {DEFAULT_MAX_PROJECTS}"
    )
    parser.add_argument(
        "--file-limit",
        type=int,
        default=DEFAULT_FILE_SCAN_LIMIT,
        help=f"Max candidate files to inspect per project. Default: {DEFAULT_FILE_SCAN_LIMIT}"
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print output JSON"
    )

    return parser.parse_args()


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    args = parse_args()

    roots = [Path(p).expanduser().resolve() for p in (args.roots + args.extra_roots)]
    roots = list(dict.fromkeys(roots))  # dedupe preserve order

    output_path = Path(args.output).expanduser().resolve()
    exclude_dirs = set(DEFAULT_EXCLUDE_DIRS).union(set(args.exclude))
    skip_prefixes = set(DEFAULT_SKIP_PATH_PREFIXES).union(set(args.skip_prefixes))
    skip_fs_types = set(DEFAULT_SKIP_FS_TYPES).union(set(args.skip_fs_types))

    started = time.time()

    final_report: Dict[str, Any] = {
        "schema_version": "4.0",
        "generated_at_utc": now_utc(),
        "host": {
            "hostname": os.uname().nodename if hasattr(os, "uname") else None,
            "platform": sys.platform,
            "python_executable": sys.executable,
            "python_version": sys.version,
            "uid": os.getuid() if hasattr(os, "getuid") else None,
            "gid": os.getgid() if hasattr(os, "getgid") else None,
            "cwd": os.getcwd(),
            "node_path": which("node"),
            "npm_path": which("npm"),
        },
        "scan_config": {
            "roots": [str(r) for r in roots],
            "timeout_seconds": args.timeout,
            "max_projects": args.max_projects,
            "file_limit_per_project": args.file_limit,
            "exclude_dirs": sorted(exclude_dirs),
            "skip_prefixes": sorted(skip_prefixes),
            "skip_fs_types": sorted(skip_fs_types),
        },
        "mount_policy": {},
        "discovery": {},
        "projects": [],
        "summary": {},
        "errors": [],
        "duration_seconds": None,
    }

    try:
        mounts = read_mount_table()
        skipped_mounts = build_unwanted_mount_points(
            mounts=mounts,
            skip_fs_types=skip_fs_types,
            allowed_roots=roots,
        )

        final_report["mount_policy"] = {
            "mounts_seen": len(mounts),
            "skipped_mount_points": sorted(skipped_mounts),
        }

        discovery = discover_projects(
            roots=roots,
            exclude_dirs=exclude_dirs,
            max_projects=args.max_projects,
            skip_prefixes=skip_prefixes,
            skipped_mounts=skipped_mounts,
        )

        final_report["discovery"] = {
            "roots_scanned": [str(r) for r in roots],
            "projects_found": len(discovery["projects"]),
            "truncated": discovery["truncated"],
            "errors": discovery["errors"],
        }

        print("=" * 100)
        print("SMART NPM AUDIT CRAWLER")
        print("=" * 100)
        print(f"Roots scanned     : {', '.join(str(r) for r in roots)}")
        print(f"Projects found    : {len(discovery['projects'])}")
        print(f"Global npm        : {which('npm') or 'NOT FOUND'}")
        print(f"Global node       : {which('node') or 'NOT FOUND'}")
        print("-" * 100)

        for idx, project_dir in enumerate(discovery["projects"], 1):
            print(f"[{idx}/{len(discovery['projects'])}] Scanning: {project_dir}")

            pr = process_project(
                project_dir=project_dir,
                exclude_dirs=exclude_dirs,
                timeout=args.timeout,
                file_limit=args.file_limit,
                skip_prefixes=skip_prefixes,
                skipped_mounts=skipped_mounts,
            )
            final_report["projects"].append(pr)

            npm_bundle = pr.get("npm_bundle", {})
            candidate = npm_bundle.get("used_candidate", {})
            candidate_label = candidate.get("label") if isinstance(candidate, dict) else None
            candidate_path = candidate.get("npm_path") if isinstance(candidate, dict) else None

            sev = pr.get("audit_summary", {}).get("severity_counts", {})
            pkg = pr.get("package_inspection", {})
            lifecycle = pkg.get("lifecycle_scripts", {})
            dep_flags = pkg.get("dependency_source_flags", {})
            suspicious = pr.get("suspicious_scan", {}).get("matches", {})
            suspicious_hit = any(bool(v) for v in suspicious.values()) if isinstance(suspicious, dict) else False

            print(f"    npm source     : {candidate_label or 'N/A'}")
            print(f"    npm path       : {candidate_path or 'N/A'}")
            print(
                f"    vulns          : "
                f"C={sev.get('critical', 0)} "
                f"H={sev.get('high', 0)} "
                f"M={sev.get('moderate', 0)} "
                f"L={sev.get('low', 0)} "
                f"I={sev.get('info', 0)} "
                f"T={sev.get('total')}"
            )
            print(f"    lifecycle      : {'yes' if lifecycle else 'no'}")
            print(f"    git deps       : {len(dep_flags.get('git', []))}")
            print(f"    url deps       : {len(dep_flags.get('url', []))}")
            print(f"    file deps      : {len(dep_flags.get('file', []))}")
            print(f"    suspicious     : {'yes' if suspicious_hit else 'no'}")
            print(f"    errors         : {len(pr.get('errors', []))}")

            if pr.get("errors"):
                for err in pr["errors"][:3]:
                    print(f"      - {err}")

            print("-" * 100)

        final_report["summary"] = summarize_all_projects(final_report["projects"])
        final_report["duration_seconds"] = round(time.time() - started, 3)

        ok, write_err = safe_json_dump(output_path, final_report, pretty=args.pretty)
        if not ok:
            final_report["errors"].append(f"failed to write output json: {write_err}")
            print(f"[ERROR] Failed to write JSON output: {write_err}", file=sys.stderr)
            return 1

        print("SCAN COMPLETE")
        print("-" * 100)
        print(f"Output file       : {output_path}")
        print(f"Duration          : {final_report['duration_seconds']} seconds")
        print(f"Projects total    : {final_report['summary'].get('projects_total', 0)}")
        print(f"With audit data   : {final_report['summary'].get('projects_with_audit_data', 0)}")
        print(f"With errors       : {final_report['summary'].get('projects_with_errors', 0)}")
        print(f"Lifecycle scripts : {final_report['summary'].get('projects_with_lifecycle_scripts', 0)}")
        print(f"Git deps          : {final_report['summary'].get('projects_with_git_dependencies', 0)}")
        print(f"URL deps          : {final_report['summary'].get('projects_with_url_dependencies', 0)}")
        print(f"File deps         : {final_report['summary'].get('projects_with_file_dependencies', 0)}")
        print(f"Suspicious hits   : {final_report['summary'].get('projects_with_suspicious_patterns', 0)}")

        vuln_totals = final_report["summary"].get("vulnerability_totals", {})
        print(
            f"Vuln totals       : "
            f"C={vuln_totals.get('critical', 0)} "
            f"H={vuln_totals.get('high', 0)} "
            f"M={vuln_totals.get('moderate', 0)} "
            f"L={vuln_totals.get('low', 0)} "
            f"I={vuln_totals.get('info', 0)}"
        )
        print("=" * 100)

        return 0

    except KeyboardInterrupt:
        final_report["errors"].append("interrupted by user")
        print("\n[ERROR] Interrupted by user", file=sys.stderr)
    except Exception as exc:
        final_report["errors"].append(str(exc))
        print(f"[ERROR] scan failed: {exc}", file=sys.stderr)

    final_report["duration_seconds"] = round(time.time() - started, 3)
    safe_json_dump(output_path, final_report, pretty=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
