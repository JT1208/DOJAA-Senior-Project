import re


def _safe_lower(text):
    return text.lower() if isinstance(text, str) else ""


def parse_banner(banner: str, port: int = None):
    """
    Converts raw service banners into analyst-readable structured intelligence.
    Designed for DOJAA risk + reporting layer.
    """

    banner = banner or ""
    b = _safe_lower(banner)

    service = "Unknown"
    product = None
    version = None
    summary = "No meaningful banner detected"
    risk_hint = "Unknown"

    # ---------------- SSH ----------------
    if "ssh" in b:
        service = "SSH"

        match = re.search(r"openssh[_\-]?([0-9\.]+)", b)
        if match:
            product = "OpenSSH"
            version = match.group(1)

            major = version.split(".")[0]

            if major in ["6", "7"]:
                risk_hint = "High"
                summary = f"Legacy SSH service (OpenSSH {version}) likely outdated"
            else:
                risk_hint = "Medium"
                summary = f"SSH service running OpenSSH {version}"
        else:
            risk_hint = "Medium"
            summary = "SSH service detected (version not clearly exposed)"

    # ---------------- HTTP ----------------
    elif "http" in b or "server:" in b or "html" in b:
        service = "HTTP"

        server_match = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)

        if server_match:
            server = server_match.group(1).strip()
            product = server.split("/")[0] if "/" in server else server
            version = server.split("/")[1] if "/" in server else None

            sl = _safe_lower(server)

            if "apache/2.2" in sl:
                risk_hint = "High"
                summary = f"Legacy Apache 2.2 web server ({server})"
            elif "apache" in sl:
                risk_hint = "Medium"
                summary = f"Apache web server ({server})"
            elif "nginx" in sl:
                risk_hint = "Low"
                summary = f"Nginx web server ({server})"
            else:
                risk_hint = "Low"
                summary = f"Web server detected ({server})"
        else:
            summary = "HTTP service detected"

    # ---------------- FTP ----------------
    elif "ftp" in b:
        service = "FTP"
        risk_hint = "High"
        summary = "FTP service exposed (unencrypted file transfer protocol)"

    # ---------------- SMTP / MAIL ----------------
    elif "smtp" in b or "mail" in b:
        service = "SMTP"
        risk_hint = "Medium"
        summary = "Mail transfer service detected"

    # ---------------- TLS / CERT DATA ----------------
    elif "issuer" in b or "certificate" in b:
        service = "TLS/SSL"
        risk_hint = "Low"
        summary = "TLS certificate metadata observed"

    # ---------------- GENERIC FALLBACK ----------------
    else:
        if port == 22:
            service = "SSH"
        elif port == 80:
            service = "HTTP"
        elif port == 443:
            service = "HTTPS"
        elif port == 21:
            service = "FTP"
        elif port == 25:
            service = "SMTP"
        else:
            service = "Unknown"

        summary = "Unclassified or minimal banner response"
        risk_hint = "Unknown"

    return {
        "service": service,
        "product": product,
        "version": version,
        "summary": summary,
        "risk_hint": risk_hint
    }