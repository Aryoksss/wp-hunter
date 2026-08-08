from __future__ import annotations

from collections.abc import Iterator, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any, Literal


@dataclass(slots=True)
class PluginRecord(Mapping[str, Any]):
    slug: str
    name: str
    version: str = ""
    active_installs: int = 0
    download_link: str = ""
    extra: dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> PluginRecord:
        known = {"slug", "name", "version", "active_installs", "download_link"}
        return cls(
            slug=str(value.get("slug", "") or ""),
            name=str(value.get("name", value.get("slug", "")) or ""),
            version=str(value.get("version", "") or ""),
            active_installs=int(value.get("active_installs", 0) or 0),
            download_link=str(value.get("download_link", "") or ""),
            extra={key: item for key, item in value.items() if key not in known},
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "slug": self.slug,
            "name": self.name,
            "version": self.version,
            "active_installs": self.active_installs,
            "download_link": self.download_link,
            **self.extra,
        }

    def __getitem__(self, key: str) -> Any:
        if key in {"slug", "name", "version", "active_installs", "download_link"}:
            return getattr(self, key)
        return self.extra[key]

    def __iter__(self) -> Iterator[str]:
        yield from ("slug", "name", "version", "active_installs", "download_link")
        yield from self.extra

    def __len__(self) -> int:
        return 5 + len(self.extra)


@dataclass(slots=True)
class DownloadOptions:
    source: Literal["wporg", "patchstack"]
    installs: str = "10K"
    installs_mode: Literal["exact", "minimum"] = "exact"
    browse: Literal["popular", "new", "updated", "top-rated"] = "popular"
    pages: int = 50
    search: str | None = None
    tag: str | None = None
    min_boost: int = 0
    include_themes: bool = False
    max_age_years: int = 2
    since: str | None = None
    limit: int | None = None
    output: str | None = None
    workers: int = 3
    api_workers: int = 5
    max_download_mb: int = 512
    preview: bool = False
    force: bool = False
    update_check: bool = False
    revisit_reviewed: bool = False
    global_dedup: bool = True
    metadata_only: bool = False
    reset_cache: bool = False
    adopt_existing: bool = False
    save_preset: str | None = None
    replace_preset: bool = False

    def preset_values(self) -> dict[str, Any]:
        values = asdict(self)
        allowed = {
            "source",
            "installs",
            "installs_mode",
            "browse",
            "pages",
            "search",
            "tag",
            "min_boost",
            "include_themes",
            "max_age_years",
            "since",
            "limit",
            "output",
            "workers",
            "api_workers",
            "max_download_mb",
        }
        return {key: value for key, value in values.items() if key in allowed and value is not None}


@dataclass(slots=True)
class ScanOptions:
    root: str
    language: Literal["en", "id"] = "en"
    delete_no_findings: bool = False
    workers: int = 2
    timeout: int = 120
    mem_mb: int = 1024
    max_age_years: int = 2
    since: str | None = None
    keep_extracted: bool = False
    semgrep: str | None = None
    rules: str | None = None
    allow_unmarked: bool = False
