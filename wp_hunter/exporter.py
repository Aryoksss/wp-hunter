from __future__ import annotations

import csv
from pathlib import Path

from .core import _display_text
from .fsutil import atomic_text_file as _atomic_text_file
from .fsutil import atomic_write_json as _atomic_write_json
from .installs import format_installs


def _csv_safe(value: object) -> object:
    if value is None:
        return ""
    text = str(value)
    index = 0
    while index < len(text) and (text[index].isspace() or ord(text[index]) <= 0x20):
        index += 1
    if text[index : index + 1] in {"=", "+", "-", "@"}:
        return "'" + text
    return text


def export_results(
    plugins: list[dict], output_dir: str, target_installs: int
) -> tuple[Path, Path]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    base_name = f"plugins_{format_installs(target_installs).replace('+', '')}"

    json_path = Path(output_dir) / f"{base_name}.json"
    _atomic_write_json(json_path, [dict(plugin) for plugin in plugins])

    csv_path = Path(output_dir) / f"{base_name}.csv"
    fieldnames = [
        "name",
        "slug",
        "version",
        "active_installs",
        "downloaded",
        "last_updated",
        "author",
        "requires",
        "requires_php",
        "tested",
        "download_link",
        "homepage",
        "tags",
    ]
    with _atomic_text_file(csv_path, newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        for p in plugins:
            row = dict(p)
            row["tags"] = "|".join(p.get("tags") or [])
            writer.writerow({k: _csv_safe(v) for k, v in row.items()})

    print(f"  Exported: {json_path.name}  +  {csv_path.name}")
    return json_path, csv_path


def export_patchstack_results(plugins: list[dict], output_dir: str) -> tuple[Path, Path]:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    json_path = Path(output_dir) / "patchstack_targets.json"
    _atomic_write_json(json_path, [dict(plugin) for plugin in plugins])

    csv_path = Path(output_dir) / "patchstack_targets.csv"
    fields = [
        "patchstack_boost",
        "patchstack_max_bounty",
        "slug",
        "name",
        "asset_kind",
        "version",
        "active_installs",
        "last_updated",
        "patchstack_vendor",
        "download_link",
    ]
    with _atomic_text_file(csv_path, newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        for p in plugins:
            writer.writerow({k: _csv_safe(v) for k, v in p.items()})

    print(f"  Exported: {json_path.name}  +  {csv_path.name}")
    return json_path, csv_path


def print_summary_table(plugins: list[dict], quiet: bool = False) -> None:
    if quiet:
        print(f"  Plugins collected: {len(plugins)}  (use without --quiet to see the full list)")
        return
    if not plugins:
        print("  [!] No plugins found.")
        return
    show = plugins[:50]
    print(f"\n  {'No':<4} {'Plugin Name':<42} {'Slug':<30} {'Ver':<8} {'Updated':<12}")
    print(f"  {'-' * 4} {'-' * 42} {'-' * 30} {'-' * 8} {'-' * 12}")
    for i, p in enumerate(show, 1):
        name = _display_text(p.get("name", ""), 41)
        slug = _display_text(p.get("slug", ""), 29)
        version = _display_text(p.get("version", ""), 7)
        updated = _display_text(p.get("last_updated") or "N/A", 10)
        print(f"  {i:<4} {name:<42} {slug:<30} {version:<8} {updated:<12}")
    if len(plugins) > 50:
        print(f"  … and {len(plugins) - 50} more  (full list in exported JSON/CSV)")
