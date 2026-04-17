import socket
import ssl
import time


ALLOWED_PORTS = {21, 22, 25, 80, 443}


def _tcp_banner(ip, port, timeout=2):
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            s.settimeout(timeout)
            try:
                return s.recv(2048).decode(errors="ignore").strip()
            except Exception:
                return ""
    except Exception:
        return ""


def _http_banner(ip, port):
    try:
        req = f"HEAD / HTTP/1.1\r\nHost: {ip}\r\nConnection: close\r\n\r\n"

        with socket.create_connection((ip, port), timeout=2) as s:
            s.sendall(req.encode())
            return s.recv(4096).decode(errors="ignore")
    except Exception:
        return ""


def _https_banner(ip, port):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((ip, port), timeout=2) as sock:
            with context.wrap_socket(sock, server_hostname=ip) as ssock:
                cert = ssock.getpeercert()
                return str(cert)
    except Exception:
        return ""


def _parse_banner(banner: str):
    product = None
    version = None

    if not banner:
        return product, version

    # simple heuristic parsing (safe, non-invasive)
    tokens = banner.replace("\r", " ").replace("\n", " ").split()

    for t in tokens:
        if "_" in t:
            try:
                parts = t.split("_")
                product = parts[0]
                version = parts[1] if len(parts) > 1 else None
                break
            except Exception:
                continue

    return product, version


def grab_banner(ip: str, port: int, service: str = None):
    """
    DOJAA-safe banner enrichment:
    - only works on known ports
    - only minimal protocol interaction
    - no scanning behavior
    """

    if not ip or not port:
        return None

    port = int(port)

    if port not in ALLOWED_PORTS:
        return None

    banner = ""

    if port == 80:
        banner = _http_banner(ip, port)

    elif port == 443:
        banner = _https_banner(ip, port)

    else:
        banner = _tcp_banner(ip, port)

    product, version = _parse_banner(banner)

    return {
        "ip": ip,
        "port": port,
        "banner": banner,
        "banner_product": product,
        "banner_version": version,
        "banner_source": "live",
        "timestamp": time.time()
    }