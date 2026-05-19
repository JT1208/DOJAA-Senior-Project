"""Cryptographic primitives for DOJAA.

All algorithms are NIST-approved and implemented via ``cryptography`` (the
canonical PyCA library used by Django, Mozilla, AWS, and the CPython
standard-library SSL stack) and ``werkzeug.security`` (shipped with Flask).
No third-party network dependencies; everything runs locally.

  - At-rest encryption:    Fernet (AES-128-CBC + HMAC-SHA-256, authenticated)
  - Key derivation:        HKDF-SHA-256 from ``FLASK_SECRET_KEY``
  - Password hashing:      PBKDF2-HMAC-SHA-256, 600,000 iters (OWASP 2023)
  - Constant-time compare: hmac.compare_digest (used by werkzeug internally)

Threat model:
  Protects against attackers who gain read-only access to the project
  directory (lost laptop, leaked backup, mis-configured rsync, accidentally
  pushed cache file). It does NOT protect against an attacker who already
  has the process secret (FLASK_SECRET_KEY) or running-process memory.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import secrets
from pathlib import Path
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from werkzeug.security import check_password_hash, generate_password_hash

log = logging.getLogger(__name__)

PBKDF2_METHOD = "pbkdf2:sha256:600000"
HKDF_INFO = b"dojaa:at-rest:v1"
HKDF_SALT = b"dojaa:hkdf:v1"
KEYFILE_NAME = ".dojaa.key"


# ---------------------------------------------------------------------------
# Password hashing (werkzeug — PBKDF2-SHA-256, salted, constant-time compare)
# ---------------------------------------------------------------------------
def hash_password(plaintext: str) -> str:
    """Return a PBKDF2-SHA-256 hash with random salt and 600k iterations.

    Output format: ``pbkdf2:sha256:600000$<salt>$<hash>`` — readable by
    werkzeug.security.check_password_hash.
    """
    return generate_password_hash(plaintext, method=PBKDF2_METHOD)


def verify_password(stored_hash: str, candidate: str) -> bool:
    """Constant-time PBKDF2 verification. Empty/None hashes always fail."""
    if not stored_hash or not candidate:
        return False
    try:
        return check_password_hash(stored_hash, candidate)
    except (ValueError, TypeError):
        return False


# ---------------------------------------------------------------------------
# At-rest key derivation
# ---------------------------------------------------------------------------
def _hkdf_derive(secret: bytes) -> bytes:
    """HKDF-SHA-256 → 32 raw bytes → Fernet's url-safe base64 form."""
    raw = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    ).derive(secret)
    return base64.urlsafe_b64encode(raw)


def _load_or_create_keyfile(cache_dir: Path) -> bytes:
    """Persist a process-stable key in ``<cache_dir>/.dojaa.key`` (0600).

    Used only when no FLASK_SECRET_KEY / DOJAA_DATA_KEY is configured — keeps
    the dev experience zero-config while still giving real encryption at rest.
    Logs a warning so production deployments don't silently rely on it.
    """
    path = cache_dir / KEYFILE_NAME
    if path.exists():
        try:
            return path.read_bytes().strip()
        except OSError as exc:
            log.warning("security: cannot read %s (%s) — regenerating", path, exc)
    key = base64.urlsafe_b64encode(secrets.token_bytes(32))
    path.write_bytes(key)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    log.warning(
        "security: generated %s — set FLASK_SECRET_KEY (or DOJAA_DATA_KEY) "
        "in your .env for production deployments. Losing this file makes "
        "encrypted cache files unreadable.",
        path,
    )
    return key


def resolve_at_rest_key(
    explicit_data_key: str | None,
    flask_secret: str | None,
    cache_dir: Path,
) -> bytes:
    """Decide which key Fernet should use for at-rest encryption.

    Resolution order:
      1. ``DOJAA_DATA_KEY`` — full Fernet key, 44 chars urlsafe-b64
      2. ``FLASK_SECRET_KEY`` — derived via HKDF-SHA-256
      3. On-disk keyfile auto-generated in cache_dir (dev convenience)
    """
    if explicit_data_key:
        key = explicit_data_key.strip().encode("ascii")
        try:
            Fernet(key)  # validate length / charset
            return key
        except (ValueError, TypeError) as exc:
            log.error(
                "security: DOJAA_DATA_KEY is malformed (%s); falling back. "
                "Generate one with: python -c 'from cryptography.fernet import "
                "Fernet; print(Fernet.generate_key().decode())'",
                exc,
            )
    if flask_secret:
        return _hkdf_derive(flask_secret.encode("utf-8"))
    return _load_or_create_keyfile(cache_dir)


# ---------------------------------------------------------------------------
# Fernet ciphers — supports rotation via multiple keys (most recent first)
# ---------------------------------------------------------------------------
def make_cipher(keys: list[bytes] | bytes) -> MultiFernet:
    """Build a MultiFernet from one or many keys.

    Reads accept any of the listed keys (so rotation is non-breaking); writes
    always use ``keys[0]``. To rotate, prepend a new key and keep the old
    one around until all cache files are re-written.
    """
    if isinstance(keys, (bytes, bytearray)):
        keys = [bytes(keys)]
    return MultiFernet([Fernet(k) for k in keys])


# Magic header on every encrypted JSON blob. Lets us tell encrypted files
# from legacy plaintext during the auto-migration phase.
ENCRYPTED_MAGIC = b"DOJAA1:"


def encrypt_json(cipher: MultiFernet, payload: Any) -> bytes:
    """Serialize and encrypt a JSON-compatible value."""
    raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    return ENCRYPTED_MAGIC + cipher.encrypt(raw)


def decrypt_json(cipher: MultiFernet, blob: bytes) -> Any:
    """Decrypt and parse a payload previously written by encrypt_json.

    Raises InvalidToken (re-exported below) when the blob is missing the
    magic header, has been tampered with, or is encrypted under a key
    that's no longer in the rotation set.
    """
    if not blob.startswith(ENCRYPTED_MAGIC):
        raise InvalidToken("missing DOJAA1 header")
    raw = cipher.decrypt(blob[len(ENCRYPTED_MAGIC):])
    return json.loads(raw.decode("utf-8"))


def looks_encrypted(blob: bytes) -> bool:
    return blob.startswith(ENCRYPTED_MAGIC)


__all__ = [
    "PBKDF2_METHOD",
    "InvalidToken",
    "hash_password",
    "verify_password",
    "resolve_at_rest_key",
    "make_cipher",
    "encrypt_json",
    "decrypt_json",
    "looks_encrypted",
]
