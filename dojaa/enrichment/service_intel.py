import re


def build_service_intel(asset):
    """
    Creates a single human-readable service intelligence string.
    Safe add-on layer (does not affect core pipeline logic).
    """

    banner = asset.get("banner") or ""
    port = asset.get("port")
    service = (asset.get("service") or "unknown").lower()

    text = banner.lower()

    name = "Unknown"
    product = "Unknown Service"
    version = None
    risk = "Low"

    # ---------------- SSH ----------------
    if "ssh" in text or port == 22:
        name = "SSH"

        match = re.search(r"openssh[_\-]?([0-9\.]+)", text)
        if match:
            product = "OpenSSH"
            version = match.group(1)

            major = version.split(".")[0]
            risk = "High" if major in ["6", "7"] else "Medium"
        else:
            product = "SSH Service"
            risk = "Medium"

    # ---------------- HTTP ----------------
    elif "http" in text or port in [80, 443]:
        name = "HTTP"

        match = re.search(r"server:\s*([^\r\n]+)", banner, re.IGNORECASE)
        if match:
            product = match.group(1).strip()
        else:
            product = "Web Service"

        risk = "Medium"

    # ---------------- FTP ----------------
    elif "ftp" in text or port == 21:
        name = "FTP"
        product = "FTP Service"
        risk = "High"

    # ---------------- SMTP ----------------
    elif "smtp" in text or port == 25:
        name = "SMTP"
        product = "Mail Service"
        risk = "Medium"

    # ---------------- DEFAULT ----------------
    else:
        name = service.upper() if service != "unknown" else "Unknown"
        product = "Unclassified Service"
        risk = "Low"

    version_text = f" {version}" if version else ""

    service_intel = f"{name} ({product}{version_text}) — Risk: {risk}"

    return {
        "service_intel": service_intel,
        "service_risk_hint": risk
    }