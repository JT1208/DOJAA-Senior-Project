import socket
import ssl
from datetime import datetime, timezone

from cryptography import x509
from cryptography.hazmat.backends import default_backend


def fetch_cert(host, port=443, timeout=1):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        conn = socket.create_connection((host, port), timeout=timeout)
        conn.settimeout(timeout)

        sock = context.wrap_socket(conn, server_hostname=host)

        der_cert = sock.getpeercert(binary_form=True)
        sock.close()

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        # ---------------- FIXED TIMEZONE HANDLING ----------------
        try:
            expiry_date = cert.not_valid_after_utc
        except Exception:
            expiry_date = cert.not_valid_after

        now = datetime.now(timezone.utc)

        if expiry_date.tzinfo is None:
            expiry_date = expiry_date.replace(tzinfo=timezone.utc)

        days_left = (expiry_date - now).days

        # ---------------- SAN DOMAINS ----------------
        try:
            san = cert.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            ).value.get_values_for_type(x509.DNSName)
        except Exception:
            san = []

        # ---------------- KEY SIZE ----------------
        key_length = getattr(cert.public_key(), "key_size", "N/A")

        # ---------------- RISK SCORING ----------------
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
            "key_length": key_length,
            "self_signed": issuer == subject,
            "risk_level": risk,
            "status": "ok"
        }

    except socket.timeout:
        return {
            "ip": host,
            "status": "timeout",
            "issuer": "-",
            "subject": "-",
            "expiry": "-",
            "san": [],
            "key_length": "-",
            "self_signed": False
        }

    except (ConnectionRefusedError, OSError):
        return {
            "ip": host,
            "status": "unreachable",
            "issuer": "-",
            "subject": "-",
            "expiry": "-",
            "san": [],
            "key_length": "-",
            "self_signed": False
        }

    except Exception as e:
        return {
            "ip": host,
            "status": f"error:{str(e)}",
            "issuer": "-",
            "subject": "-",
            "expiry": "-",
            "san": [],
            "key_length": "-",
            "self_signed": False
        }


def collect_ssl_data(hosts):
    results = []

    for h in hosts:
        if h:
            results.append(fetch_cert(h))

    return results