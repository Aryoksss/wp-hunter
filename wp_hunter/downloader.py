from __future__ import annotations

import os
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urljoin

import requests

from .archive import validate_zip_members as _validate_zip_members
from .core import (
    DOWNLOAD_MAX_RETRIES,
    MAX_DOWNLOAD_BYTES,
    MAX_DOWNLOAD_REDIRECTS,
    ROOT_MARKER_FILE,
    ProgressBar,
    _ensure_hunter_root,
    _root_marker_state,
    _safe_download_filename,
    _safe_download_url,
)
from .exporter import (
    export_patchstack_results,
    export_results,
    print_summary_table,
)
from .fsutil import atomic_write_json as _atomic_write_json
from .fsutil import md5_of_file as _md5_of_file
from .fsutil import sha256_of_file as _sha256_of_file
from .safe_names import is_safe_slug as _is_safe_slug
from .semgrep_adapter import decode_process_output as _decode_process_output
from .state import DownloadManifest
from .versioning import version_is_newer

__all__ = [
    "build_global_slug_index",
    "download_all",
    "download_plugin",
    "export_patchstack_results",
    "export_results",
    "print_summary_table",
]


def _validate_download_archive(
    path: Path,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
    expected_md5: str = "",
    expected_sha256: str = "",
) -> tuple[bool, str]:
    try:
        if path.is_symlink() or not path.is_file():
            return False, "not a regular archive"
        size = path.stat().st_size
        if size <= 0:
            return False, "archive is empty"
        if size > max_bytes:
            return False, f"archive exceeds {max_bytes} byte limit"
        if not zipfile.is_zipfile(path):
            return False, "response is not a ZIP archive"
        with zipfile.ZipFile(path) as zf:
            _validate_zip_members(zf)
        if expected_md5 and _md5_of_file(path).lower() != expected_md5.lower():
            return False, "MD5 mismatch"
        if expected_sha256 and _sha256_of_file(path).lower() != expected_sha256.lower():
            return False, "SHA-256 mismatch"
    except (OSError, ValueError, zipfile.BadZipFile) as exc:
        return False, str(exc)
    return True, ""


def _open_safe_download(download_url: str):
    current_url = download_url
    for redirect_count in range(MAX_DOWNLOAD_REDIRECTS + 1):
        if not _safe_download_url(current_url):
            raise ValueError("redirected to a non-WordPress HTTPS URL")
        response = requests.get(
            current_url,
            timeout=(15, 60),
            stream=True,
            allow_redirects=False,
        )
        status = int(getattr(response, "status_code", 200) or 200)
        if status not in {301, 302, 303, 307, 308}:
            return response
        location = response.headers.get("Location")
        response.close()
        if not location:
            raise ValueError("download redirect has no Location header")
        if redirect_count >= MAX_DOWNLOAD_REDIRECTS:
            raise ValueError("too many download redirects")
        current_url = urljoin(current_url, location)
    raise ValueError("too many download redirects")


def _persist_download_state(
    plugin_dir: Path,
    plugin: dict,
    filename: str,
    archive_path: Path,
    sha256: str,
    manifest: DownloadManifest | None,
) -> None:
    meta_file = plugin_dir / "plugin_info.json"
    if meta_file.is_symlink() or (meta_file.exists() and not meta_file.is_file()):
        raise ValueError("rejected unsafe metadata path")
    metadata = dict(plugin)
    metadata["downloaded_sha256"] = sha256
    _atomic_write_json(meta_file, metadata)
    if manifest:
        manifest.mark_downloaded(
            str(plugin["slug"]),
            filename,
            archive_path.stat().st_size // 1024,
            str(plugin.get("version", "") or ""),
            sha256,
        )


def build_global_slug_index(base_dir: str | None) -> set[str]:
    if not base_dir:
        return set()
    base = Path(base_dir)
    if not base.is_dir():
        return set()
    seen: set[str] = set()
    for folder in base.iterdir():
        if not folder.is_dir() or folder.is_symlink():
            continue
        if _root_marker_state(folder / ROOT_MARKER_FILE) != "valid":
            continue
        for p in folder.iterdir():
            if (
                not p.is_dir()
                or p.is_symlink()
                or p.name.startswith(("_", "."))
                or not _is_safe_slug(p.name)
            ):
                continue
            has_valid_archive = any(
                _validate_download_archive(candidate)[0] for candidate in p.glob("*.zip")
            )
            if has_valid_archive:
                seen.add(p.name)
    return seen


def download_plugin(
    plugin: dict,
    output_dir: str,
    skip_existing: bool = True,
    manifest: DownloadManifest | None = None,
    update_check: bool = False,
    global_slugs: set[str] | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> tuple[bool, str, str]:
    slug = plugin.get("slug", "")
    if not _is_safe_slug(slug):
        return False, str(slug), "Rejected unsafe plugin slug"
    download_url = plugin.get("download_link", "")
    if not download_url:
        return False, slug, "No download link"
    if not _safe_download_url(download_url):
        return False, slug, "Rejected non-WordPress HTTPS download URL"

    if skip_existing and not update_check and global_slugs and slug in global_slugs:
        return True, slug, "Already in another folder (dedup)"

    output_path = Path(output_dir)
    if output_path.is_symlink() or not output_path.is_dir():
        return False, slug, "Rejected invalid output root"
    root = output_path.resolve()
    raw_plugin_dir = root / slug
    if raw_plugin_dir.is_symlink():
        return False, slug, "Rejected symlink plugin directory"
    plugin_dir = raw_plugin_dir.resolve()
    if plugin_dir.parent != root:
        return False, slug, "Rejected plugin path outside output root"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    filename = _safe_download_filename(download_url, slug)
    filepath = plugin_dir / filename
    expected_md5 = str(plugin.get("md5") or "")

    if skip_existing and manifest and manifest.is_downloaded(slug):
        cached_filename = manifest.get_filename(slug)
        cached_path = plugin_dir / cached_filename
        local_ver = manifest.get_version(slug)
        remote_ver = str(plugin.get("version", "") or "")
        remote_is_newer = version_is_newer(remote_ver, local_ver)
        valid, _reason = _validate_download_archive(
            cached_path,
            max_bytes=max_bytes,
            # A newer remote release naturally has a different MD5. Without
            # --update-check, validate the cached release by its stored SHA-256.
            expected_md5="" if remote_is_newer else expected_md5,
        )
        version_ok = not update_check or not remote_is_newer
        if valid and version_ok:
            sha256 = _sha256_of_file(cached_path)
            try:
                _persist_download_state(
                    plugin_dir, plugin, cached_filename, cached_path, sha256, manifest
                )
            except (OSError, TypeError, ValueError) as exc:
                return False, slug, f"Could not persist verified download state: {exc}"
            state = (
                f"Up to date (v{local_ver})" if update_check else "Already downloaded (verified)"
            )
            return True, slug, state

    if filepath.is_symlink():
        return False, slug, "Rejected symlink download file"
    if filepath.exists() and not filepath.is_file():
        return False, slug, "Rejected non-file download path"
    if skip_existing and filepath.is_file():
        valid, _reason = _validate_download_archive(
            filepath, max_bytes=max_bytes, expected_md5=expected_md5
        )
        if valid:
            sha256 = _sha256_of_file(filepath)
            try:
                _persist_download_state(plugin_dir, plugin, filename, filepath, sha256, manifest)
            except (OSError, TypeError, ValueError) as exc:
                return False, slug, f"Could not persist verified download state: {exc}"
            return True, slug, "Already on disk (verified)"

    last_exc: Exception | None = None
    downloaded_sha256 = ""
    tmp_path: Path | None = None
    for attempt in range(1, DOWNLOAD_MAX_RETRIES + 1):
        try:
            fd, temporary_name = tempfile.mkstemp(
                prefix=f".{filename}.", suffix=".part", dir=str(plugin_dir)
            )
            tmp_path = Path(temporary_name)
            with os.fdopen(fd, "wb") as fh, _open_safe_download(download_url) as resp:
                resp.raise_for_status()
                content_length = resp.headers.get("Content-Length")
                if content_length:
                    try:
                        content_length_int = int(content_length)
                    except (TypeError, ValueError):
                        content_length_int = 0
                    if content_length_int > max_bytes:
                        raise ValueError(f"response exceeds {max_bytes} byte limit")
                written = 0
                for chunk in resp.iter_content(chunk_size=8192):
                    if not chunk:
                        continue
                    written += len(chunk)
                    if written > max_bytes:
                        raise ValueError(f"download exceeds {max_bytes} byte limit")
                    fh.write(chunk)
                fh.flush()
                os.fsync(fh.fileno())
            valid, reason = _validate_download_archive(
                tmp_path, max_bytes=max_bytes, expected_md5=expected_md5
            )
            if not valid:
                raise ValueError(reason)
            downloaded_sha256 = _sha256_of_file(tmp_path)
            os.replace(tmp_path, filepath)
            tmp_path = None
            last_exc = None
            break
        except Exception as exc:
            last_exc = exc
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)
                tmp_path = None
            if attempt < DOWNLOAD_MAX_RETRIES:
                time.sleep(2**attempt)

    if last_exc:
        return False, slug, f"Failed after {DOWNLOAD_MAX_RETRIES} attempts: {last_exc}"

    size_kb = filepath.stat().st_size // 1024
    sha256 = downloaded_sha256 or _sha256_of_file(filepath)

    try:
        _persist_download_state(plugin_dir, plugin, filename, filepath, sha256, manifest)
    except (OSError, TypeError, ValueError) as exc:
        return False, slug, f"Downloaded archive but could not persist metadata: {exc}"

    md5_note = " ✓md5" if expected_md5 else ""
    return True, slug, f"OK ({size_kb} KB) v{plugin.get('version', '')}{md5_note}"


def download_all(
    plugins: list[dict],
    output_dir: str,
    max_workers: int = 3,
    skip_existing: bool = True,
    update_check: bool = False,
    global_slugs: set[str] | None = None,
    max_bytes: int = MAX_DOWNLOAD_BYTES,
) -> None:
    max_workers = max(1, min(max_workers, 5))
    max_bytes = max(1, max_bytes)
    output_root = _ensure_hunter_root(output_dir)
    output_dir = str(output_root)
    manifest = DownloadManifest(output_root, autosave=False)
    already = sum(1 for p in plugins if skip_existing and manifest.is_downloaded(p["slug"]))
    to_download = len(plugins) - already
    print(f"\n{'=' * 60}")
    print("  Download plan")
    print(f"    Output   : {output_dir}")
    print(f"    Total    : {len(plugins)}")
    print(f"    In cache : {already}  (will skip)")
    print(f"    Fetch    : {to_download}  (new or forced)")
    print(f"{'=' * 60}")

    if to_download == 0:
        print("\n  Nothing to download — all plugins already in cache.\n")
        print("  Tip: use --update-check to re-download newer versions,")
        print("       or --force to re-download everything.\n")
        return

    success = updated = failed = skipped = 0
    bar = ProgressBar(total=len(plugins), label="Downloading")
    bar.start()

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {
            executor.submit(
                download_plugin,
                p,
                output_dir,
                skip_existing,
                manifest,
                update_check,
                global_slugs,
                max_bytes,
            ): p
            for p in plugins
        }
        for future in as_completed(futures):
            try:
                ok, slug, msg = future.result()
            except Exception as exc:
                plugin = futures[future]
                ok = False
                slug = str(plugin.get("slug", "unknown"))
                msg = f"Worker crashed: {_decode_process_output(exc, 160)}"
            msg_lower = msg.lower()
            if ok:
                if any(w in msg_lower for w in ("already", "up to date", "on disk", "dedup")):
                    skipped += 1
                    status = "SKIP"
                elif update_check and "ok" in msg_lower:
                    updated += 1
                    status = " UPD"
                else:
                    success += 1
                    status = " OK "
            else:
                failed += 1
                status = "FAIL"
            bar.update(message=f"[{status}] {slug}")

    bar.finish()
    manifest.save()
    print(
        f"\n  Results: {success} new  |  {skipped} skipped  |  {updated} updated  |  {failed} failed"
    )
    if failed:
        print("  Tip: re-run with same flags to retry failed downloads (retry logic included).")
    print(f"  Location : {output_dir}\n")
