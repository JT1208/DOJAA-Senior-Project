import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend


def fetch_cert(host, port=443, timeout=4):
    try:
        context = ssl.create_default_context()
        conn = socket.create_connection((host, port), timeout=timeout)

        sock = context.wrap_socket(conn, server_hostname=host)

        der_cert = sock.getpeercert(binary_form=True)
        sock.close()

        cert = x509.load_der_x509_certificate(der_cert, default_backend())

        issuer = cert.issuer.rfc4514_string()
        subject = cert.subject.rfc4514_string()

        expiry = cert.not_valid_after_utc.strftime("%Y-%m-%d")

        key_length = cert.public_key().key_size
        self_signed = issuer == subject

        return {
            "ip": host,
            "issuer": issuer,
            "subject": subject,
            "expiry": expiry,
            "key_length": key_length,
            "self_signed": self_signed
        }

    except Exception:
        return {
            "ip": host,
            "issuer": "N/A",
            "subject": "N/A",
            "expiry": "N/A",
            "key_length": "N/A",
            "self_signed": False
        }


def collect_ssl_data(hosts):
    if not hosts:
        return []

    results = []
    for h in hosts:
        results.append(fetch_cert(h))
    return results