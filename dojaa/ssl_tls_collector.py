"""TLS certificate probe for HTTPS endpoints.

Uses a permissive SSL context (no hostname or CA validation) because the goal
is asset *discovery* — we want metadata on whatever certificate the host
presents, including self-signed or expired ones.
"""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone
from typing import Any

from cryptography import x509
from cryptography.hazmat.backends import default_backend

from .settings import load_settings

log = logging.getLogger(__name__)


def _empty_row(host: str, status: str) -> dict[str, Any]:
    return {
        "ip": host,
        "status": status,
        "issuer": "-",
        "subject": "-",
        "expiry": "-",
        "days_left": None,
        "san": [],
        "key_length": "-",
        "self_signed": False,
        "risk_level": "UNKNOWN",
    }


def fetch_cert(host: str, port: int = 443, timeout: float | None = None) -> dict[str, Any]:
    if timeout is None:
        timeout = load_settings().ssl_probe_timeout

    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((host, port), timeout=timeout) as conn:
            conn.settimeout(timeout)
            with context.wrap_socket(conn, server_hostname=host) as sock:
                der_cert = sock.getpeercert(binary_form=True)

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        try:
            expiry_date = cert.not_valid_after_utc
        except AttributeError:
            expiry_date = cert.not_valid_after
        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)
        days_left = (expiry_date - datetime.now(timezone.utc)).days

        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except x509.ExtensionNotFound:
            san = []

        key_length = getattr(cert.public_key(), "key_size", None)
        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        if days_left < 0:
            risk = "EXPIRED"
        elif days_left < 30:
            risk = "CRITICAL"
        elif days_left < 90:
            risk = "HIGH"
        elif days_left < 180:
            risk = "MEDIUM"
        else:
            risk = "LOW"

        return {
            "ip": host,
            "issuer": issuer,
            "subject": subject,
            "expiry": expiry_date.strftime("%Y-%m-%d"),
            "days_left": days_left,
            "san": san,
            "key_length": key_length if key_length is not None else "-",
            "self_signed": issuer == subject,
            "risk_level": risk,
            "status": "ok",
        }

    except socket.timeout:
        return _empty_row(host, "timeout")
    except (ConnectionRefusedError, OSError):
        return _empty_row(host, "unreachable")
    except Exception as exc:  # noqa: BLE001 — last-resort guard
        log.info("ssl probe failed for %s: %s", host, exc)
        row = _empty_row(host, "error")
        row["status"] = f"error: {exc}"
        return row


def collect_ssl_data(hosts: list[str]) -> list[dict]:
    return [fetch_cert(h) for h in hosts if h]
