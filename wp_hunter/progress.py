from __future__ import annotations

import math
import os
import sys
import threading
import time

from .text import display_text


class ProgressBar:
    _WIDTH = 30

    _MILESTONES = 20

    def __init__(self, total: int, label: str = "Progress"):
        self._total = max(total, 1)
        self._label = label
        self._done = 0
        self._lock = threading.Lock()
        self._is_tty = sys.stdout.isatty()
        self._start_time = 0.0
        self._last_render_width = 0
        self._milestone_step = max(1, math.ceil(self._total / self._MILESTONES))
        # Use Unicode blocks only if the output encoding can represent them;
        # otherwise fall back to ASCII (avoids UnicodeEncodeError on cp1252).
        enc = (getattr(sys.stdout, "encoding", "") or "").lower()
        self._fill, self._empty = ("#", "-")
        if "utf" in enc:
            try:
                "█░".encode(sys.stdout.encoding)
                self._fill, self._empty = ("█", "░")
            except (UnicodeEncodeError, LookupError, TypeError):
                pass

    def start(self) -> None:
        self._start_time = time.monotonic()
        if self._is_tty:
            sys.stdout.write("\n")
            sys.stdout.flush()

    def update(self, message: str = "") -> None:
        with self._lock:
            self._done += 1
            done = self._done
        self._render(done, message)

    def finish(self, message: str = "Done") -> None:
        self._render(self._total, message, final=True)
        if self._is_tty:
            sys.stdout.write("\n")
        sys.stdout.flush()

    def _render(self, done: int, message: str, final: bool = False) -> None:
        pct = done / self._total
        filled = int(self._WIDTH * pct)
        bar = self._fill * filled + self._empty * (self._WIDTH - filled)
        elapsed = time.monotonic() - self._start_time
        eta = ""
        if done > 0 and not final and elapsed > 0:
            remaining = (elapsed / done) * (self._total - done)
            m, s = divmod(int(remaining), 60)
            eta = f" ETA {m:02d}:{s:02d}"
        try:
            cols = os.get_terminal_size().columns if self._is_tty else 120
        except OSError:
            cols = 120
        line = f"  {self._label} [{bar}] {done}/{self._total} ({pct:.0%}){eta}"
        if message:
            avail = max(10, cols - len(line) - 3)
            line += f"  {display_text(message, avail)}"
        if self._is_tty:
            padding = " " * max(0, self._last_render_width - len(line))
            sys.stdout.write(f"\r{line}{padding}")
            sys.stdout.flush()
            self._last_render_width = len(line)
        else:
            milestone = final or (done % self._milestone_step == 0)
            if milestone:
                print(line, flush=True)
