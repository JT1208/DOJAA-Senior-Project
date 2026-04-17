from flask import Flask, render_template, request, redirect, url_for, session
from dojaa.pipeline import run_pipeline
from functools import wraps

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


# ---------------- AUTH DECORATOR ----------------
def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# ---------------- DATA PIPELINE ----------------
def get_dashboard_data(rescan=False):
    return run_pipeline(use_api=rescan)


# ---------------- DASHBOARD ----------------
@app.route("/dashboard")
@require_login
def dashboard():
    rescan = request.args.get("rescan", "false").lower() == "true"
    data = get_dashboard_data(rescan=rescan)

    return render_template(
        "dashboard.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )


# ---------------- HOSTS ----------------
@app.route("/hosts")
@require_login
def hosts():
    rescan = request.args.get("rescan", "false").lower() == "true"
    data = get_dashboard_data(rescan=rescan)

    return render_template(
        "hosts.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )


# ---------------- OPEN PORTS ----------------
@app.route("/open_ports")
@require_login
def open_ports():
    rescan = request.args.get("rescan", "false").lower() == "true"
    data = get_dashboard_data(rescan=rescan)

    return render_template(
        "open_ports.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )


# ---------------- RISK SUMMARY ----------------
@app.route("/risk_summary")
@require_login
def risk_summary():
    rescan = request.args.get("rescan", "false").lower() == "true"
    data = get_dashboard_data(rescan=rescan)

    return render_template(
        "risk_summary.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )


# ---------------- ASSET DETAIL ----------------
@app.route("/asset/<ip>")
@require_login
def asset_detail(ip):

    data = get_dashboard_data(rescan=False)

    all_assets = data["shodan"] + data["censys"]

    asset = next((a for a in all_assets if a.get("ip") == ip), None)

    if not asset:
        return "Asset not found", 404

    return render_template("asset_detail.html", asset=asset)


# ---------------- GRAPH VIEW (NEW) ----------------
@app.route("/graph")
@require_login
def graph():

    data = get_dashboard_data(rescan=False)

    return render_template(
        "graph.html",
        shodan=data["shodan"],
        user=session.get("user")
    )


# ---------------- LOGOUT ----------------
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


# ---------------- RUN ----------------
if __name__ == "__main__":
    app.run(debug=True)