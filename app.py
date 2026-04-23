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

# ---------------- BROWSER TOOLS ----------------
@app.route("/browser_tools")
@require_login
def browser_tools_page():
    return render_template("browser_tools.html", user=session.get("user"))

@app.route("/api/browser_tools")
def api_browser_tools():
    from flask import jsonify
    import requests as req

    url = request.args.get("url", "").strip()
    if not url:
        return jsonify({"error": "No URL provided"}), 400

    if not url.startswith("http"):
        url = "https://" + url

    try:
        response = req.get(url, timeout=5, allow_redirects=True)
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
                "value": value if value else "Missing"
            }

        return jsonify({"url": url, "results": results})

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