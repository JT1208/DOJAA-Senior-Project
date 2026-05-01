from datetime import datetime
from io import BytesIO

from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    session,
    url_for,
)
from functools import wraps
import requests as req

from dojaa.config import ORG_DOMAIN
from dojaa.pipeline import run_pipeline
from dojaa.report_pdf import build_dashboard_report_pdf
from dojaa.risk_tiers import risk_tier_counts
from dojaa.robots_txt import (
    disallow_paths_for_wildcard,
    disallow_paths_tree_preview,
    fetch_robots_rules,
)

app = Flask(__name__)
app.secret_key = "supersecretkey"


# ---------------- LOGIN ----------------
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        if email and email.endswith("@drexel.edu") and password == "Drexel123!":
            session["user"] = email
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Invalid login")

    return render_template("login.html", error=None)


# ---------------- AUTH ----------------
def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# ---------------- PIPELINE ----------------
def get_dashboard_data(rescan=False):
    data = run_pipeline(use_api=rescan)
    for msg in data.get("_pipeline_notices") or []:
        flash(msg, "warning")
    data.pop("_pipeline_notices", None)
    return data


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@require_login
def dashboard():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )
    shodan = data.get("shodan", [])
    censys = data.get("censys", [])
    risk_low, risk_mid, risk_high = risk_tier_counts(shodan, censys)

    return render_template(
        "dashboard.html",
        shodan=shodan,
        censys=censys,
        cves=data.get("cves", []),
        user=session.get("user"),
        risk_low=risk_low,
        risk_mid=risk_mid,
        risk_high=risk_high,
    )


@app.route("/cves")
@require_login
def cves():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )
    return render_template(
        "cves.html",
        cves=data.get("cves", []),
        user=session.get("user"),
    )


@app.route("/dashboard/report.pdf")
@require_login
def dashboard_report_pdf():
    """Generated DOJAA report PDF (no merged template PDF)."""
    data = get_dashboard_data(rescan=False)
    pdf_bytes, err = build_dashboard_report_pdf(
        data.get("shodan", []),
        data.get("censys", []),
        data.get("cves", []),
        data.get("ssl_tls") or [],
        session.get("user"),
    )
    if err:
        flash(err, "danger")
        return redirect(url_for("dashboard"))

    fname = f"DOJAA_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"
    return send_file(
        BytesIO(pdf_bytes),
        mimetype="application/pdf",
        as_attachment=True,
        download_name=fname,
    )


# ---------------- HOSTS ----------------
@app.route("/hosts")
@require_login
def hosts():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )

    return render_template(
        "hosts.html",
        shodan=data.get("shodan", []),
        censys=data.get("censys", []),
        user=session.get("user")
    )


# ---------------- OPEN PORTS ----------------
@app.route("/open_ports")
@require_login
def open_ports():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )

    return render_template(
        "open_ports.html",
        shodan=data.get("shodan", []),
        censys=data.get("censys", []),
        user=session.get("user")
    )


# ---------------- RISK ----------------
@app.route("/risk_summary")
@require_login
def risk_summary():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )
    shodan = data.get("shodan", [])
    censys = data.get("censys", [])
    risk_low, risk_mid, risk_high = risk_tier_counts(shodan, censys)

    return render_template(
        "risk_summary.html",
        shodan=shodan,
        censys=censys,
        user=session.get("user"),
        risk_low=risk_low,
        risk_mid=risk_mid,
        risk_high=risk_high,
    )


# ---------------- ASSET DETAIL ----------------
@app.route("/asset/<ip>")
@require_login
def asset_detail(ip):
    data = get_dashboard_data(rescan=False)

    all_assets = data.get("shodan", []) + data.get("censys", [])
    asset = next((a for a in all_assets if a.get("ip") == ip), None)

    if not asset:
        return "Asset not found", 404

    return render_template("asset_detail.html", asset=asset)


# ---------------- GRAPH ----------------
@app.route("/graph")
@require_login
def graph():
    data = get_dashboard_data(rescan=False)

    return render_template(
        "graph.html",
        shodan=data.get("shodan", []),
        user=session.get("user")
    )


# ---------------- SSL/TLS ----------------
@app.route("/ssl_tls")
@require_login
def ssl_tls():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )

    ssl_data = data.get("ssl_tls") or []

    print("[SSL DEBUG] count =", len(ssl_data))

    return render_template(
        "ssl_tls.html",
        ssl_tls=ssl_data,
        user=session.get("user")
    )


# ---------------- ROBOTS.TXT ----------------
@app.route("/robots")
@require_login
def robots():
    site = (request.args.get("site") or "").strip() or ORG_DOMAIN
    rules, err = fetch_robots_rules(site)
    if err:
        flash(err, "warning")
        tree_text = ""
    elif not rules:
        tree_text = ""
    else:
        dis = disallow_paths_for_wildcard(rules)
        if not dis:
            tree_text = "(No Disallow entries for User-agent: *)"
        else:
            tree_text = disallow_paths_tree_preview(dis)

    return render_template(
        "robots.html",
        tree_text=tree_text,
        site=site,
        user=session.get("user"),
    )


# ---------------- BROWSER TOOLS ----------------
@app.route("/browser_tools")
@require_login
def browser_tools_page():
    return render_template("browser_tools.html", user=session.get("user"))


@app.route("/api/browser_tools")
@require_login
def api_browser_tools():
    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = req.get(url, timeout=8, allow_redirects=True)
        headers = response.headers

        checks = {
            "Content-Security-Policy": headers.get("Content-Security-Policy"),
            "Strict-Transport-Security": headers.get("Strict-Transport-Security"),
            "X-Frame-Options": headers.get("X-Frame-Options"),
            "X-Content-Type-Options": headers.get("X-Content-Type-Options"),
            "Referrer-Policy": headers.get("Referrer-Policy"),
            "Permissions-Policy": headers.get("Permissions-Policy"),
        }

        results = {}
        for header, value in checks.items():
            results[header] = {
                "present": value is not None,
                "value": value if value else "Missing",
            }

        return jsonify({"url": url, "status_code": response.status_code, "results": results})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ---------------- DNS ENUMERATION ----------------
@app.route("/dns")
@require_login
def dns_page():
    return render_template("dns.html", user=session.get("user"))


@app.route("/api/dns_enum")
@require_login
def api_dns_enum():
    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "No domain provided"}), 400

    # Basic cleanup: DNS-over-HTTPS resolver expects domain only.
    domain = domain.replace("https://", "").replace("http://", "").strip().strip("/")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]
    results = {}

    for rtype in record_types:
        try:
            url = f"https://dns.google/resolve?name={domain}&type={rtype}"
            response = req.get(url, timeout=8)
            data = response.json()
            answers = data.get("Answer", [])
            results[rtype] = [a.get("data", "") for a in answers if a.get("data")]
        except Exception:
            results[rtype] = []

    return jsonify({"domain": domain, "records": results})


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)