#!/usr/bin/env python3
"""
ubi_package_txt_exporter.py

Purpose:
  Export package lists from Red Hat UBI container images into TXT files.

Data source:
  Red Hat Container Catalog / Pyxis API

What it does:
  - Finds UBI 8 / 9 / 10 repositories
  - Skips deprecated repositories/images
  - Fetches latest image for each repo by default
  - Fetches RPM manifest/packages for each image
  - Creates one TXT file per image:
      <latest_image_date>_<image_name>.txt

Example:
  python3 ubi_package_txt_exporter.py --major all --out ./ubi_packages
  python3 ubi_package_txt_exporter.py --major 8 --out ./ubi8_packages
  python3 ubi_package_txt_exporter.py --major all --workers 20
  python3 ubi_package_txt_exporter.py --major all --all-images --max-images-per-repo 5

Dependency:
  python3 -m pip install requests
"""

import argparse
import datetime as dt
import json
import logging
import os
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import quote

try:
    import requests
    from requests.adapters import HTTPAdapter
except ImportError:
    print("[ERROR] Missing dependency: requests")
    print("Install it using:")
    print("  python3 -m pip install requests")
    sys.exit(2)


API_BASE = "https://catalog.redhat.com/api/containers/v1"
DEFAULT_MAJORS = ["8", "9", "10"]


class ScriptError(Exception):
    pass


def setup_logger(verbose: bool) -> logging.Logger:
    logger = logging.getLogger("ubi-package-exporter")
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    handler = logging.StreamHandler()
    handler.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    handler.setFormatter(formatter)

    if not logger.handlers:
        logger.addHandler(handler)

    return logger


def create_session(pool_size: int = 30) -> requests.Session:
    session = requests.Session()

    adapter = HTTPAdapter(
        pool_connections=pool_size,
        pool_maxsize=pool_size,
        max_retries=0,
    )

    session.mount("https://", adapter)
    session.mount("http://", adapter)

    session.headers.update(
        {
            "Accept": "application/json",
            "User-Agent": "ubi-package-txt-exporter/1.0",
        }
    )

    return session


def parse_date(value: Any) -> Optional[dt.date]:
    if not value:
        return None

    text = str(value).strip()

    if not text or text == "-":
        return None

    try:
        return dt.datetime.fromisoformat(text.replace("Z", "+00:00")).date()
    except Exception:
        pass

    try:
        return dt.datetime.strptime(text[:10], "%Y-%m-%d").date()
    except Exception:
        return None


def fmt_date(value: Any) -> str:
    parsed = parse_date(value)
    return parsed.isoformat() if parsed else "-"


def now_utc() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


def get_data_list(payload: Any) -> List[Dict[str, Any]]:
    if isinstance(payload, list):
        return payload

    if isinstance(payload, dict):
        data = payload.get("data")

        if isinstance(data, list):
            return data

        if isinstance(data, dict):
            return [data]

    return []


def http_get_json(
    session: requests.Session,
    url: str,
    logger: logging.Logger,
    retries: int = 3,
    timeout: int = 45,
) -> Dict[str, Any]:
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            logger.debug("GET %s", url)

            response = session.get(url, timeout=timeout)

            if response.status_code == 400:
                body = response.text[:500].replace("\n", " ")
                raise ScriptError(
                    f"HTTP 400 Bad Request from API. URL={url} Response={body}"
                )

            if response.status_code == 404:
                return {}

            if response.status_code in (429, 500, 502, 503, 504):
                wait = min(attempt * 3, 15)
                logger.warning(
                    "Temporary API issue HTTP %s. Retry %s/%s after %ss",
                    response.status_code,
                    attempt,
                    retries,
                    wait,
                )
                time.sleep(wait)
                continue

            response.raise_for_status()

            try:
                return response.json()
            except json.JSONDecodeError as exc:
                raise ScriptError(f"Invalid JSON returned by API: {url}") from exc

        except ScriptError:
            raise

        except requests.RequestException as exc:
            last_error = exc
            wait = min(attempt * 3, 15)
            logger.warning(
                "Request failed: %s. Retry %s/%s after %ss",
                exc,
                attempt,
                retries,
                wait,
            )
            time.sleep(wait)

    raise ScriptError(f"Request failed after retries. URL={url} Error={last_error}")


def parse_majors(value: str) -> List[str]:
    value = value.strip().lower()

    if value == "all":
        return DEFAULT_MAJORS

    result = []

    for item in value.split(","):
        item = item.strip()

        if item not in DEFAULT_MAJORS:
            raise argparse.ArgumentTypeError(
                f"Invalid major version: {item}. Allowed: 8, 9, 10, all"
            )

        result.append(item)

    return sorted(set(result), key=lambda x: int(x))


def make_repo_filter(major: str) -> str:
    return f'repository=regex="^ubi{major}/"'


def normalize_release_categories(value: Any) -> str:
    if isinstance(value, list):
        return ",".join(str(x) for x in value) if value else "-"

    if value:
        return str(value)

    return "-"


def is_deprecated_repo(repo: Dict[str, Any]) -> bool:
    deprecated_flag = bool(repo.get("deprecated"))

    category = normalize_release_categories(repo.get("release_categories")).lower()
    category_deprecated = "deprecated" in category

    return deprecated_flag or category_deprecated


def safe_filename(value: str) -> str:
    value = value.strip()
    value = value.replace("/", "_")
    value = re.sub(r"[^A-Za-z0-9._-]+", "_", value)
    value = re.sub(r"_+", "_", value)
    return value.strip("_") or "unknown"


def fetch_ubi_repositories(
    session: requests.Session,
    major: str,
    logger: logging.Logger,
    page_size: int,
    limit: Optional[int],
) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    seen = set()
    page = 0

    filter_text = make_repo_filter(major)
    logger.info("Searching UBI%s repositories", major)

    while True:
        encoded_filter = quote(filter_text, safe="")

        url = (
            f"{API_BASE}/repositories"
            f"?filter={encoded_filter}"
            f"&page={page}"
            f"&page_size={page_size}"
        )

        payload = http_get_json(session, url, logger)
        batch = get_data_list(payload)

        if not batch:
            break

        for item in batch:
            repository = str(item.get("repository", "")).strip()

            if not repository.startswith(f"ubi{major}/"):
                continue

            row_id = item.get("_id") or f"{item.get('registry')}:{repository}"

            if row_id in seen:
                continue

            seen.add(row_id)
            rows.append(item)

            if limit and len(rows) >= limit:
                return rows

        if len(batch) < page_size:
            break

        page += 1

    return rows


def fetch_images_for_repo(
    session: requests.Session,
    repo: Dict[str, Any],
    logger: logging.Logger,
    all_images: bool,
    max_images_per_repo: int,
) -> List[Dict[str, Any]]:
    registry = str(repo.get("registry", "registry.access.redhat.com")).strip()
    repository = str(repo.get("repository", "")).strip()

    if not registry or not repository:
        return []

    registry_q = quote(registry, safe="")
    repo_q = quote(repository, safe="")

    page_size = max_images_per_repo if all_images else 1

    url = (
        f"{API_BASE}/repositories/registry/{registry_q}/repository/{repo_q}/images"
        f"?page=0"
        f"&page_size={page_size}"
        f"&sort_by=creation_date[desc]"
    )

    payload = http_get_json(session, url, logger)
    images = get_data_list(payload)

    clean_images: List[Dict[str, Any]] = []

    for image in images:
        image["_source_registry"] = registry
        image["_source_repository"] = repository
        clean_images.append(image)

    if not all_images:
        return clean_images[:1]

    return clean_images[:max_images_per_repo]


def image_is_deprecated(image: Dict[str, Any]) -> bool:
    # Image-level deprecated fields are not always present, but handle them if they exist.
    if bool(image.get("deprecated")):
        return True

    category = normalize_release_categories(image.get("release_categories")).lower()
    if "deprecated" in category:
        return True

    return False


def fetch_rpm_manifest(
    session: requests.Session,
    image_id: str,
    logger: logging.Logger,
) -> Dict[str, Any]:
    image_id_q = quote(image_id, safe="")
    url = f"{API_BASE}/images/id/{image_id_q}/rpm-manifest"

    return http_get_json(session, url, logger)


def rpm_sort_key(rpm: Dict[str, Any]) -> Tuple[str, str, str, str]:
    name = str(rpm.get("name") or "")
    version = str(rpm.get("version") or "")
    release = str(rpm.get("release") or "")
    arch = str(rpm.get("architecture") or rpm.get("arch") or "")
    return name, version, release, arch


def rpm_to_line(rpm: Dict[str, Any]) -> str:
    name = rpm.get("name") or "-"
    epoch = rpm.get("epoch")
    version = rpm.get("version") or "-"
    release = rpm.get("release") or "-"
    arch = rpm.get("architecture") or rpm.get("arch") or "-"
    nvra = rpm.get("nvra") or rpm.get("nevra") or "-"
    summary = rpm.get("summary") or "-"

    epoch_text = str(epoch) if epoch not in (None, "", "-") else "-"

    return (
        f"{str(name):<45} "
        f"{epoch_text:<6} "
        f"{str(version):<28} "
        f"{str(release):<32} "
        f"{str(arch):<12} "
        f"{str(nvra):<80} "
        f"{str(summary)}"
    )


def write_package_txt(
    out_dir: str,
    repo: Dict[str, Any],
    image: Dict[str, Any],
    manifest: Dict[str, Any],
) -> Tuple[str, int]:
    repository = str(repo.get("repository", image.get("_source_repository", "unknown")))
    registry = str(repo.get("registry", image.get("_source_registry", "registry.access.redhat.com")))

    image_id = str(image.get("_id") or "-")
    image_date = fmt_date(image.get("creation_date") or image.get("last_update_date"))
    if image_date == "-":
        image_date = dt.datetime.now(dt.timezone.utc).date().isoformat()

    latest_digest = (
        image.get("docker_image_digest")
        or image.get("image_id")
        or image.get("manifest_digest")
        or "-"
    )

    image_ref = image.get("nvr") or image.get("_id") or "-"

    rpms = manifest.get("rpms") or []
    if not isinstance(rpms, list):
        rpms = []

    rpms_sorted = sorted(rpms, key=rpm_sort_key)

    filename = f"{image_date}_{safe_filename(repository)}.txt"

    # If --all-images is used, multiple image builds of same repo may have same date.
    # Add short image ID to avoid overwrite.
    if os.path.exists(os.path.join(out_dir, filename)):
        short_id = safe_filename(image_id[:12])
        filename = f"{image_date}_{safe_filename(repository)}_{short_id}.txt"

    path = os.path.join(out_dir, filename)

    with open(path, "w", encoding="utf-8") as f:
        f.write("Red Hat UBI Image Package Report\n")
        f.write("================================\n\n")
        f.write(f"Generated UTC      : {now_utc()}\n")
        f.write(f"Registry           : {registry}\n")
        f.write(f"Repository         : {repository}\n")
        f.write(f"Image Date         : {image_date}\n")
        f.write(f"Image ID           : {image_id}\n")
        f.write(f"Image Ref/NVR      : {image_ref}\n")
        f.write(f"Image Digest       : {latest_digest}\n")
        f.write(f"Published          : {str(repo.get('published', '-')).lower()}\n")
        f.write(f"Deprecated Flag    : {str(bool(repo.get('deprecated'))).lower()}\n")
        f.write(f"Release Category   : {normalize_release_categories(repo.get('release_categories'))}\n")
        f.write(f"Package Count      : {len(rpms_sorted)}\n")
        f.write(f"Source API         : {API_BASE}/images/id/{image_id}/rpm-manifest\n")
        f.write("\n")

        f.write(
            f"{'NAME':<45} "
            f"{'EPOCH':<6} "
            f"{'VERSION':<28} "
            f"{'RELEASE':<32} "
            f"{'ARCH':<12} "
            f"{'NVRA/NEVRA':<80} "
            f"SUMMARY\n"
        )
        f.write("-" * 240 + "\n")

        for rpm in rpms_sorted:
            f.write(rpm_to_line(rpm) + "\n")

    return path, len(rpms_sorted)


def process_repo(
    repo: Dict[str, Any],
    out_dir: str,
    all_images: bool,
    max_images_per_repo: int,
    logger: logging.Logger,
) -> Dict[str, Any]:
    repository = str(repo.get("repository", "-")).strip()

    result = {
        "repository": repository,
        "skipped": False,
        "skip_reason": "",
        "files": [],
        "errors": [],
    }

    if is_deprecated_repo(repo):
        result["skipped"] = True
        result["skip_reason"] = "deprecated_repo_or_category"
        return result

    session = create_session(pool_size=4)

    try:
        images = fetch_images_for_repo(
            session=session,
            repo=repo,
            logger=logger,
            all_images=all_images,
            max_images_per_repo=max_images_per_repo,
        )
    except Exception as exc:
        result["errors"].append(f"image_lookup_failed: {exc}")
        return result

    if not images:
        result["errors"].append("no_images_found")
        return result

    for image in images:
        try:
            if image_is_deprecated(image):
                continue

            image_id = str(image.get("_id") or "").strip()

            if not image_id:
                result["errors"].append("image_missing_id")
                continue

            manifest = fetch_rpm_manifest(
                session=session,
                image_id=image_id,
                logger=logger,
            )

            if not manifest:
                result["errors"].append(f"rpm_manifest_missing_for_image_id={image_id}")
                continue

            path, pkg_count = write_package_txt(
                out_dir=out_dir,
                repo=repo,
                image=image,
                manifest=manifest,
            )

            result["files"].append(
                {
                    "path": path,
                    "package_count": pkg_count,
                    "image_id": image_id,
                    "image_date": fmt_date(image.get("creation_date") or image.get("last_update_date")),
                }
            )

        except Exception as exc:
            result["errors"].append(f"image_processing_failed: {exc}")

    return result


def write_summary_json(out_dir: str, summary: Dict[str, Any]) -> str:
    path = os.path.join(out_dir, "summary.json")

    with open(path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    return path


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export RPM package lists from non-deprecated Red Hat UBI images into TXT files."
    )

    parser.add_argument(
        "--major",
        default="all",
        help="UBI major version: 8, 9, 10, 8,9,10, or all. Default: all",
    )

    parser.add_argument(
        "--out",
        default="./ubi_package_txt",
        help="Output directory. Default: ./ubi_package_txt",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=12,
        help="Parallel workers. Default: 12",
    )

    parser.add_argument(
        "--page-size",
        type=int,
        default=100,
        help="Repository API page size. Default: 100",
    )

    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Optional repo limit per UBI major for testing.",
    )

    parser.add_argument(
        "--all-images",
        action="store_true",
        help="Export package TXT for multiple image builds per repo, not only latest.",
    )

    parser.add_argument(
        "--max-images-per-repo",
        type=int,
        default=3,
        help="When --all-images is used, max image builds per repo. Default: 3",
    )

    parser.add_argument(
        "--repo-filter",
        default=None,
        help="Only process repos containing this text, example: --repo-filter nodejs",
    )

    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging.",
    )

    args = parser.parse_args()
    logger = setup_logger(args.verbose)

    try:
        if args.workers < 1 or args.workers > 50:
            raise ScriptError("--workers must be between 1 and 50")

        if args.page_size < 1 or args.page_size > 500:
            raise ScriptError("--page-size must be between 1 and 500")

        if args.max_images_per_repo < 1 or args.max_images_per_repo > 100:
            raise ScriptError("--max-images-per-repo must be between 1 and 100")

        majors = parse_majors(args.major)

        os.makedirs(args.out, exist_ok=True)

        logger.info("Starting UBI package TXT export")
        logger.info("Selected majors: %s", ",".join(majors))
        logger.info("Output directory: %s", os.path.abspath(args.out))
        logger.info("Deprecated repos/images will be skipped")

        session = create_session(pool_size=max(args.workers, 10))

        all_repos: List[Dict[str, Any]] = []

        for major in majors:
            repos = fetch_ubi_repositories(
                session=session,
                major=major,
                logger=logger,
                page_size=args.page_size,
                limit=args.limit,
            )
            logger.info("UBI%s repositories found: %s", major, len(repos))
            all_repos.extend(repos)

        if args.repo_filter:
            needle = args.repo_filter.lower()
            before = len(all_repos)
            all_repos = [
                repo for repo in all_repos
                if needle in str(repo.get("repository", "")).lower()
            ]
            logger.info("Repo filter applied: %s -> %s/%s repos", args.repo_filter, len(all_repos), before)

        non_deprecated_repos = [
            repo for repo in all_repos
            if not is_deprecated_repo(repo)
        ]

        deprecated_count = len(all_repos) - len(non_deprecated_repos)

        logger.info("Total repos discovered      : %s", len(all_repos))
        logger.info("Deprecated repos skipped    : %s", deprecated_count)
        logger.info("Repos to process            : %s", len(non_deprecated_repos))

        results: List[Dict[str, Any]] = []

        completed = 0
        total = len(non_deprecated_repos)

        with ThreadPoolExecutor(max_workers=args.workers) as executor:
            future_map = {
                executor.submit(
                    process_repo,
                    repo,
                    args.out,
                    args.all_images,
                    args.max_images_per_repo,
                    logger,
                ): repo
                for repo in non_deprecated_repos
            }

            for future in as_completed(future_map):
                completed += 1

                repo = future_map[future]
                repo_name = str(repo.get("repository", "-"))

                try:
                    result = future.result()
                except Exception as exc:
                    result = {
                        "repository": repo_name,
                        "skipped": False,
                        "skip_reason": "",
                        "files": [],
                        "errors": [str(exc)],
                    }

                results.append(result)

                file_count = len(result.get("files", []))
                error_count = len(result.get("errors", []))

                if file_count:
                    logger.info(
                        "[%s/%s] %s -> files=%s errors=%s",
                        completed,
                        total,
                        repo_name,
                        file_count,
                        error_count,
                    )
                else:
                    logger.warning(
                        "[%s/%s] %s -> no files errors=%s",
                        completed,
                        total,
                        repo_name,
                        error_count,
                    )

        txt_files = []
        total_packages = 0
        total_errors = 0

        for result in results:
            for file_info in result.get("files", []):
                txt_files.append(file_info.get("path"))
                total_packages += int(file_info.get("package_count", 0))

            total_errors += len(result.get("errors", []))

        summary = {
            "generated_at_utc": now_utc(),
            "source_api": API_BASE,
            "majors": majors,
            "output_directory": os.path.abspath(args.out),
            "total_repos_discovered": len(all_repos),
            "deprecated_repos_skipped": deprecated_count,
            "repos_processed": len(non_deprecated_repos),
            "txt_files_created": len(txt_files),
            "total_packages_written": total_packages,
            "total_errors": total_errors,
            "all_images_mode": bool(args.all_images),
            "max_images_per_repo": args.max_images_per_repo if args.all_images else 1,
            "results": results,
        }

        summary_path = write_summary_json(args.out, summary)

        print()
        print("Export Summary")
        print("--------------")
        print(f"Output directory        : {os.path.abspath(args.out)}")
        print(f"Total repos discovered  : {len(all_repos)}")
        print(f"Deprecated skipped      : {deprecated_count}")
        print(f"Repos processed         : {len(non_deprecated_repos)}")
        print(f"TXT files created       : {len(txt_files)}")
        print(f"Total packages written  : {total_packages}")
        print(f"Errors                  : {total_errors}")
        print(f"Summary JSON            : {summary_path}")
        print()

        if txt_files:
            print("Sample files:")
            for path in sorted(txt_files)[:10]:
                print(f"  {path}")

        if total_errors:
            print()
            print("Some repos/images had errors. Check summary.json for details.")

        logger.info("Completed")
        return 0

    except KeyboardInterrupt:
        logger.error("Interrupted by user")
        return 130

    except Exception as exc:
        logger.error("Failed: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())
