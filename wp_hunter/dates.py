from __future__ import annotations

import sys
from datetime import datetime, timedelta


def resolve_cutoff_date(min_updated_years: int = 0, since: str | None = None) -> datetime | None:
    if since:
        for date_format in ("%Y-%m-%d", "%Y-%m", "%Y"):
            try:
                return datetime.strptime(since, date_format)
            except ValueError:
                continue
        print(
            f"  [WARN] Could not parse --since {since!r} (use YYYY-MM-DD); ignoring filter.",
            file=sys.stderr,
        )
        return None
    if min_updated_years > 0:
        return datetime.now() - timedelta(days=round(365.2425 * min_updated_years))
    return None


def plugin_last_updated(last_updated: str) -> datetime | None:
    if not last_updated:
        return None
    raw = last_updated.split(" GMT")[0].strip()
    for date_format in ("%Y-%m-%d %I:%M%p", "%Y-%m-%d"):
        try:
            return datetime.strptime(raw, date_format)
        except ValueError:
            continue
    if len(raw) >= 4 and raw[:4].isdigit():
        try:
            return datetime(int(raw[:4]), 1, 1)
        except ValueError:
            return None
    return None
