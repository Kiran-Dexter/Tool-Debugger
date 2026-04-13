#!/usr/bin/env python3
"""
npm-valid_DL-v2.py

Show npm dependencies and peerDependencies for a package,
then download the package tarballs without installing them.

Default behavior:
- target package
- direct dependencies
- direct peerDependencies

Optional:
- --all  -> also include direct devDependencies

Supports:
- custom registry URL (JFrog / proxy / virtual repo) via --registry

Examples:
  python3 npm-valid_DL-v2.py react
  python3 npm-valid_DL-v2.py react@18
  python3 npm-valid_DL-v2.py axios --registry https://jfrog.example.com/artifactory/api/npm/npm-virtual
  python3 npm-valid_DL-v2.py react --all --registry https://jfrog.example.com/artifactory/api/npm/npm-virtual
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote, urlparse

import requests


HTTP_TIMEOUT = 30
HTTP_RETRIES = 4
DEFAULT_REGISTRY = "https://registry.npmjs.org"


def require_binary(name: str) -> None:
    if shutil.which(name) is None:
        raise RuntimeError(f"Required binary not found in PATH: {name}")


def run_cmd(cmd: List[str]) -> Tuple[int, str, str]:
    proc = subprocess.run(cmd, text=True, capture_output=True)
    return proc.returncode, proc.stdout.strip(), proc.stderr.strip()


def safe_filename(name: str, version: str) -> str:
    clean = name.replace("/", "__").replace("@", "")
    return f"{clean}-{version}.tgz"


def build_headers() -> Dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": "npm-valid-dl-v2/1.0",
    }

    npm_token = os.getenv("NPM_TOKEN", "").strip()
    if npm_token:
        headers["Authorization"] = f"Bearer {npm_token}"

    return headers


def http_get_json(session: requests.Session, url: str) -> Dict[str, Any]:
    last_error: Optional[Exception] = None

    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            resp = session.get(
                url,
                timeout=HTTP_TIMEOUT,
                headers=build_headers(),
            )
            if resp.status_code == 200:
                return resp.json()
            raise RuntimeError(f"HTTP {resp.status_code}: {resp.text[:300]}")
        except Exception as exc:
            last_error = exc
            if attempt < HTTP_RETRIES:
                time.sleep(attempt * 2)

    raise RuntimeError(f"Failed GET {url}: {last_error}")


def download_file(session: requests.Session, url: str, target: Path) -> None:
    last_error: Optional[Exception] = None

    for attempt in range(1, HTTP_RETRIES + 1):
        try:
            with session.get(
                url,
                timeout=HTTP_TIMEOUT,
                stream=True,
                headers={"User-Agent": "npm-valid-dl-v2/1.0"},
            ) as resp:
                if resp.status_code != 200:
                    raise RuntimeError(f"HTTP {resp.status_code}")

                with target.open("wb") as fh:
                    for chunk in resp.iter_content(chunk_size=1024 * 1024):
                        if chunk:
                            fh.write(chunk)
            return
        except Exception as exc:
            last_error = exc
            try:
                target.unlink(missing_ok=True)
            except Exception:
                pass
            if attempt < HTTP_RETRIES:
                time.sleep(attempt * 2)

    raise RuntimeError(f"Failed download {url}: {last_error}")


def verify_integrity(file_path: Path, integrity: str) -> Tuple[bool, str]:
    if not integrity:
        return False, "missing integrity"

    if "-" not in integrity:
        return False, "unsupported integrity format"

    algo, expected_b64 = integrity.split("-", 1)
    algo = algo.strip().lower()

    if algo not in hashlib.algorithms_available:
        return False, f"unsupported algorithm: {algo}"

    h = hashlib.new(algo)
    with file_path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)

    actual_b64 = base64.b64encode(h.digest()).decode("ascii")
    return actual_b64 == expected_b64, f"{algo} match={actual_b64 == expected_b64}"


def parse_json_output(text: str) -> Any:
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return text


def resolve_version_with_npm(name: str, spec: str, registry: str) -> str:
    package_spec = f"{name}@{spec}" if spec else name
    cmd = ["npm", "view", package_spec, "version", "--json", "--registry", registry]
    code, out, err = run_cmd(cmd)

    if code != 0:
        raise RuntimeError(f"npm view failed for {package_spec}: {err or out}")

    data = parse_json_output(out)

    if isinstance(data, list):
        if not data:
            raise RuntimeError(f"No version returned for {package_spec}")
        return str(data[-1])

    if isinstance(data, str):
        return data.strip()

    raise RuntimeError(f"Unexpected npm view output for {package_spec}: {out}")


def split_package_spec(spec: str) -> Tuple[str, Optional[str]]:
    if spec.startswith("@"):
        at_pos = spec.rfind("@")
        slash_pos = spec.find("/")
        if at_pos > slash_pos:
            return spec[:at_pos], spec[at_pos + 1:]
        return spec, None

    if "@" in spec:
        name, version = spec.rsplit("@", 1)
        return name, version or None

    return spec, None


def package_version_url(registry: str, name: str, version: str) -> str:
    return f"{registry.rstrip('/')}/{quote(name, safe='@/')}/{quote(version, safe='')}"


def package_doc_url(registry: str, name: str) -> str:
    return f"{registry.rstrip('/')}/{quote(name, safe='@/')}"


def fetch_version_metadata(session: requests.Session, registry: str, name: str, version: str) -> Dict[str, Any]:
    return http_get_json(session, package_version_url(registry, name, version))


def published_for_version(session: requests.Session, registry: str, name: str, version: str) -> str:
    url = package_doc_url(registry, name)
    doc = http_get_json(session, url)
    time_map = doc.get("time", {})
    if isinstance(time_map, dict):
        return str(time_map.get(version, "-"))
    return "-"


def render_table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(str(cell))), 42)

    def clip(text: str, width: int) -> str:
        text = str(text)
        return text if len(text) <= width else text[: width - 3] + "..."

    def line() -> str:
        return "+-" + "-+-".join("-" * w for w in widths) + "-+"

    def row_line(row: List[str]) -> str:
        return "| " + " | ".join(clip(str(row[i]), widths[i]).ljust(widths[i]) for i in range(len(row))) + " |"

    out = [line(), row_line(headers), line()]
    for row in rows:
        out.append(row_line(row))
    out.append(line())
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Show npm dependencies/peerDependencies and download tarballs without installing."
    )
    parser.add_argument("package", help="npm package name or name@version")
    parser.add_argument("--out", default="./npm_downloads", help="Output directory")
    parser.add_argument(
        "--all",
        action="store_true",
        help="Also include direct devDependencies",
    )
    parser.add_argument(
        "--registry",
        default=DEFAULT_REGISTRY,
        help="NPM registry base URL, e.g. JFrog virtual/remote repo",
    )
    args = parser.parse_args()

    registry = args.registry.rstrip("/")

    try:
        require_binary("npm")
    except Exception as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return 1

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    session = requests.Session()

    try:
        target_name, target_spec = split_package_spec(args.package)
        target_version = resolve_version_with_npm(target_name, target_spec or "", registry)
        target_meta = fetch_version_metadata(session, registry, target_name, target_version)
        target_published = published_for_version(session, registry, target_name, target_version)
    except Exception as exc:
        print(f"[ERROR] Failed to resolve target package: {exc}", file=sys.stderr)
        return 2

    deps = target_meta.get("dependencies", {})
    peer_deps = target_meta.get("peerDependencies", {})
    dev_deps = target_meta.get("devDependencies", {}) if args.all else {}

    if not isinstance(deps, dict):
        deps = {}
    if not isinstance(peer_deps, dict):
        peer_deps = {}
    if not isinstance(dev_deps, dict):
        dev_deps = {}

    package_rows: List[Dict[str, str]] = []
    download_items: List[Dict[str, str]] = []

    def add_item(kind: str, name: str, range_spec: str, resolved_version: str, meta: Dict[str, Any], published: str) -> None:
        dist = meta.get("dist", {}) if isinstance(meta.get("dist"), dict) else {}
        tarball = str(dist.get("tarball", ""))
        integrity = str(dist.get("integrity", ""))
        tarball_host = urlparse(tarball).netloc if tarball else "-"
        deprecated = str(meta.get("deprecated", "-")) if meta.get("deprecated") else "-"

        package_rows.append({
            "kind": kind,
            "name": name,
            "range": range_spec or "-",
            "resolved": resolved_version,
            "published": published or "-",
            "deps": str(len(meta.get("dependencies", {}) if isinstance(meta.get("dependencies"), dict) else {})),
            "peer": str(len(meta.get("peerDependencies", {}) if isinstance(meta.get("peerDependencies"), dict) else {})),
            "deprecated": deprecated,
            "host": tarball_host or "-",
        })

        download_items.append({
            "name": name,
            "version": resolved_version,
            "tarball": tarball,
            "integrity": integrity,
        })

    try:
        add_item("target", target_name, target_spec or "latest", target_version, target_meta, target_published)
    except Exception as exc:
        print(f"[ERROR] Failed to stage target package: {exc}", file=sys.stderr)
        return 3

    combined: List[Tuple[str, str, str]] = []

    for name, spec in deps.items():
        combined.append(("dependency", name, str(spec)))

    for name, spec in peer_deps.items():
        combined.append(("peerDependency", name, str(spec)))

    if args.all:
        for name, spec in dev_deps.items():
            combined.append(("devDependency", name, str(spec)))

    for kind, dep_name, dep_spec in combined:
        try:
            resolved = resolve_version_with_npm(dep_name, dep_spec, registry)
            dep_meta = fetch_version_metadata(session, registry, dep_name, resolved)
            dep_published = published_for_version(session, registry, dep_name, resolved)
            add_item(kind, dep_name, dep_spec, resolved, dep_meta, dep_published)
        except Exception as exc:
            package_rows.append({
                "kind": kind,
                "name": dep_name,
                "range": dep_spec,
                "resolved": "ERROR",
                "published": "-",
                "deps": "-",
                "peer": "-",
                "deprecated": str(exc),
                "host": "-",
            })

    seen = set()
    unique_download_items: List[Dict[str, str]] = []
    for item in download_items:
        key = (item["name"], item["version"])
        if key in seen:
            continue
        seen.add(key)
        unique_download_items.append(item)

    rows = [
        [
            r["kind"],
            r["name"],
            r["range"],
            r["resolved"],
            r["published"],
            r["deps"],
            r["peer"],
            r["deprecated"],
            r["host"],
        ]
        for r in package_rows
    ]

    print("\n=== PACKAGE / DEPENDENCY SUMMARY ===")
    print(
        render_table(
            ["Type", "Package", "Range", "Resolved", "Published", "Deps", "PeerDeps", "Deprecated", "TarballHost"],
            rows,
        )
    )

    print(f"\n[INFO] Registry        : {registry}")
    print(f"[INFO] Downloading {len(unique_download_items)} tarball(s) to: {out_dir}")

    failed = 0

    for item in unique_download_items:
        name = item["name"]
        version = item["version"]
        tarball = item["tarball"]
        integrity = item["integrity"]

        if not tarball:
            failed += 1
            print(f"[ERROR] Missing tarball URL for {name}@{version}")
            continue

        target_path = out_dir / safe_filename(name, version)

        try:
            download_file(session, tarball, target_path)

            if integrity:
                ok, msg = verify_integrity(target_path, integrity)
                if not ok:
                    failed += 1
                    print(f"[ERROR] Integrity verification failed for {name}@{version}: {msg}")
                    try:
                        target_path.unlink(missing_ok=True)
                    except Exception:
                        pass
                    continue

            print(f"[OK] Downloaded {name}@{version} -> {target_path}")
        except Exception as exc:
            failed += 1
            print(f"[ERROR] Failed {name}@{version}: {exc}")

    print("\n=== FINAL STATUS ===")
    print(f"[INFO] Registry       : {registry}")
    print(f"[INFO] Target package : {target_name}@{target_version}")
    print(f"[INFO] Direct deps    : {len(deps)}")
    print(f"[INFO] Peer deps      : {len(peer_deps)}")
    print(f"[INFO] Dev deps       : {len(dev_deps) if args.all else 0}")
    print(f"[INFO] Downloaded set : {len(unique_download_items) - failed}")
    print(f"[INFO] Failed         : {failed}")

    return 0 if failed == 0 else 4


if __name__ == "__main__":
    sys.exit(main())
