"""Atomic JSON cache reads/writes with freshness metadata.

The pipeline output is large (~1 MB) and is rewritten on every rescan. A
crashed write would otherwise leave a half-written file that breaks the next
read. We write to ``<file>.tmp`` then rename.

Freshness metadata is stored in a sibling ``<file>.meta`` so the freshness
stamp survives encrypted-blob rewrites.

Payloads are encrypted at rest with Fernet (AES-128-CBC + HMAC-SHA-256). The
cipher key is resolved from the application settings — see ``dojaa.security``.
Legacy plaintext files are still readable on first load and are transparently
re-written in encrypted form on the next ``write_json``.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Read the at-rest key from the environment directly. Settings.secret_key
# is auto-randomised when FLASK_SECRET_KEY is unset, which would silently
# rotate the cache key on every restart and brick existing cache files.
_FLASK_SECRET_ENV = "FLASK_SECRET_KEY"

from ..security import (
    InvalidToken,
    decrypt_json,
    encrypt_json,
    looks_encrypted,
    make_cipher,
    resolve_at_rest_key,
)

log = logging.getLogger(__name__)


_CIPHER_LOCK = threading.Lock()
_CIPHER = None  # cached MultiFernet, built lazily so settings can finish loading


def _get_cipher():
    """Return the process-wide MultiFernet, building it from current settings.

    Settings are read on first use via the Flask application context when
    available, with a no-Flask fallback for the standalone ``run.py`` CLI.
    """
    global _CIPHER
    if _CIPHER is not None:
        return _CIPHER
    with _CIPHER_LOCK:
        if _CIPHER is not None:
            return _CIPHER
        settings = _load_settings_safely()
        flask_secret_from_env = (os.environ.get(_FLASK_SECRET_ENV) or "").strip()
        key = resolve_at_rest_key(
            explicit_data_key=settings.data_key,
            flask_secret=flask_secret_from_env or None,
            cache_dir=settings.cache_dir,
        )
        _CIPHER = make_cipher(key)
    return _CIPHER


def _load_settings_safely():
    """Return Settings whether or not we're inside a Flask app context."""
    try:
        from flask import current_app  # local import to avoid hard dep
        if current_app:
            return current_app.config["DOJAA_SETTINGS"]
    except (RuntimeError, ImportError, KeyError):
        pass
    from ..settings import load_settings
    return load_settings()


def write_json(path: Path, payload: Any) -> None:
    """Write ``payload`` to ``path`` atomically (encrypted) and stamp ``path.meta``."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    cipher = _get_cipher()
    blob = encrypt_json(cipher, payload)

    fd, tmp_str = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=str(path.parent))
    tmp = Path(tmp_str)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(blob)
        # 0600 — only the owning user can read decryption-required bytes.
        try:
            os.chmod(tmp, 0o600)
        except OSError:
            pass
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
    """Return parsed JSON (decrypting on the fly) or ``None`` if unreadable.

    Auto-migrates legacy plaintext cache files: when the on-disk blob is not
    encrypted, parse it as JSON and re-write it encrypted so the next read
    is protected at rest.
    """
    p = Path(path)
    if not p.exists():
        return None
    try:
        blob = p.read_bytes()
    except OSError as exc:
        log.warning("cache: failed to read %s (%s)", p, exc)
        return None

    if not blob:
        return None

    cipher = _get_cipher()
    if looks_encrypted(blob):
        try:
            return decrypt_json(cipher, blob)
        except InvalidToken as exc:
            log.warning(
                "cache: %s appears encrypted but did not decrypt — wrong "
                "FLASK_SECRET_KEY / DOJAA_DATA_KEY? (%s)", p, exc,
            )
            return None
        except (ValueError, json.JSONDecodeError) as exc:
            log.warning("cache: decrypted %s but JSON parse failed (%s)", p, exc)
            return None

    # Legacy plaintext path — read, then upgrade to encrypted on the spot.
    try:
        payload = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        log.warning("cache: failed to parse legacy plaintext %s (%s)", p, exc)
        return None
    try:
        write_json(p, payload)
        log.info("cache: migrated %s to encrypted-at-rest format", p)
    except Exception as exc:  # pragma: no cover — best-effort migration
        log.warning("cache: could not re-encrypt %s in place (%s)", p, exc)
    return payload


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


def _reset_cipher_for_tests() -> None:
    """Test helper — drops the cached cipher so a new key takes effect."""
    global _CIPHER
    with _CIPHER_LOCK:
        _CIPHER = None
