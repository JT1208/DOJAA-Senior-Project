import socket
import ssl
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

        try:
            expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")
        except Exception:
            expiry = cert.not_valid_after.strftime("%Y-%m-%d")

        return {
            "ip": host,
            "issuer": cert.issuer.rfc4514_string(),
            "subject": cert.subject.rfc4514_string(),
            "expiry": expiry,
            "key_length": getattr(cert.public_key(), "key_size", "N/A"),
            "self_signed": cert.issuer == cert.subject,
            "status": "ok"
        }

    except socket.timeout:
        return {
            "ip": host,
            "issuer": None,
            "subject": None,
            "expiry": None,
            "key_length": None,
            "self_signed": False,
            "status": "timeout"
        }

    except (ConnectionRefusedError, OSError):
        return {
            "ip": host,
            "issuer": None,
            "subject": None,
            "expiry": None,
            "key_length": None,
            "self_signed": False,
            "status": "unreachable"
        }

    except Exception as e:
        return {
            "ip": host,
            "issuer": None,
            "subject": None,
            "expiry": None,
            "key_length": None,
            "self_signed": False,
            "status": f"error: {str(e)}"
        }


def collect_ssl_data(hosts):
    results = []

    for h in hosts:
        if not h:
            continue
        results.append(fetch_cert(h))

    return results