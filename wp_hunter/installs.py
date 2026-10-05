from __future__ import annotations

import re

VALID_TIERS = [
    10,
    20,
    30,
    40,
    50,
    60,
    70,
    80,
    90,
    100,
    200,
    300,
    400,
    500,
    600,
    700,
    800,
    900,
    1000,
    2000,
    3000,
    4000,
    5000,
    6000,
    7000,
    8000,
    9000,
    10000,
    20000,
    30000,
    40000,
    50000,
    60000,
    70000,
    80000,
    90000,
    100000,
    200000,
    300000,
    400000,
    500000,
    600000,
    700000,
    800000,
    900000,
    1000000,
    2000000,
    3000000,
    4000000,
    5000000,
    10000000,
]


def format_installs(n: int) -> str:
    if n >= 1_000_000:
        return f"{n // 1_000_000}M+"
    if n >= 1_000:
        return f"{n // 1_000}K+"
    return str(n)


def parse_installs_input(value: str) -> int:
    value = value.strip().upper().removesuffix("+").replace(",", "")
    match = re.fullmatch(r"(\d+(?:\.\d+)?)([KM]?)", value)
    if not match:
        raise ValueError("invalid install count")
    number = float(match.group(1))
    multiplier = {"": 1, "K": 1_000, "M": 1_000_000}[match.group(2)]
    if number > 1_000_000_000 / multiplier:
        raise ValueError("install count is unreasonably large")
    return int(number * multiplier)
