from flask import Flask, render_template, request, redirect, url_for, session
from functools import wraps
from dojaa.pipeline import run_pipeline

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
    return run_pipeline(use_api=rescan)


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@require_login
def dashboard():
    data = get_dashboard_data(
        rescan=request.args.get("rescan", "false").lower() == "true"
    )

    return render_template(
        "dashboard.html",
        shodan=data.get("shodan", []),
        censys=data.get("censys", []),
        user=session.get("user")
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

    return render_template(
        "risk_summary.html",
        shodan=data.get("shodan", []),
        censys=data.get("censys", []),
        user=session.get("user")
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

# ---------------- WHOIS ----------------
@app.route("/whois")
@require_login
def whois_page():
    return render_template("whois.html", user=session.get("user"))

@app.route("/api/whois")
def api_whois():
    from flask import jsonify
    import requests as req

    domain = request.args.get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Missing domain"}), 400

    try:
        urls_to_try = [
            f"https://rdap.verisign.com/edu/v1/domain/{domain}",
            f"https://rdap.verisign.com/com/v1/domain/{domain}",
            f"https://rdap.org/domain/{domain}",
        ]

        result = None
        for url in urls_to_try:
            try:
                r = req.get(url, timeout=5)
                if r.status_code == 200:
                    result = r.json()
                    break
            except:
                continue

        if not result:
            return jsonify({"error": "Could not retrieve WHOIS data"}), 500

        registrar = "N/A"
        creation_date = "N/A"
        expiration_date = "N/A"
        name_servers = "N/A"

        for entity in result.get("entities", []):
            for role in entity.get("roles", []):
                if role == "registrar":
                    vcard = entity.get("vcardArray", [None, []])[1]
                    for field in vcard:
                        if field[0] == "fn":
                            registrar = field[3]
                            break

        for event in result.get("events", []):
            if event.get("eventAction") == "registration":
                creation_date = event.get("eventDate", "N/A")[:10]
            if event.get("eventAction") == "expiration":
                expiration_date = event.get("eventDate", "N/A")[:10]

        ns_list = [ns.get("ldhName", "") for ns in result.get("nameservers", [])]
        if ns_list:
            name_servers = ", ".join(ns_list)

        return jsonify({
            "domain": domain,
            "registrar": registrar,
            "creation_date": creation_date,
            "expiration_date": expiration_date,
            "name_servers": name_servers
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)