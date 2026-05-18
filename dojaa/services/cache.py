"""Atomic JSON cache reads/writes with freshness metadata.

The pipeline output is large (~1 MB) and is rewritten on every rescan. A
crashed write would otherwise leave a half-written file that breaks the next
read. We write to ``<file>.tmp`` then rename.

Freshness metadata is stored in a sibling ``<file>.meta`` so the cache
payload itself stays plain JSON (consumable by external tools).
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


def write_json(path: Path, payload: Any) -> None:
    """Write ``payload`` to ``path`` atomically and stamp ``path.meta`` with mtime."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_str = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except OSError:
                pass
        raise
    _write_meta(path, datetime.now(timezone.utc))


def read_json(path: Path) -> Any | None:
    """Return parsed JSON or ``None`` if the file is missing or unreadable."""
    p = Path(path)
    if not p.exists():
        return None
    try:
        with p.open("r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("cache: failed to read %s (%s)", p, exc)
        return None


def read_freshness(path: Path) -> datetime | None:
    """Return the last successful write time of ``path``, or ``None``."""
    meta = _meta_path(Path(path))
    if not meta.exists():
        # Fall back to filesystem mtime if the .meta sidecar is missing.
        try:
            return datetime.fromtimestamp(Path(path).stat().st_mtime, tz=timezone.utc)
        except FileNotFoundError:
            return None
    try:
        raw = meta.read_text(encoding="utf-8").strip()
        return datetime.fromisoformat(raw)
    except (OSError, ValueError):
        return None


def _meta_path(path: Path) -> Path:
    return path.with_suffix(path.suffix + ".meta")


def _write_meta(path: Path, when: datetime) -> None:
    try:
        _meta_path(path).write_text(when.isoformat(), encoding="utf-8")
    except OSError as exc:
        log.debug("cache: could not write freshness meta for %s (%s)", path, exc)
