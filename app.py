from flask import Flask, render_template, request, redirect, url_for, session
from dojaa.pipeline import run_pipeline
from functools import wraps

app = Flask(__name__)
app.secret_key = "supersecretkey"  # Required for sessions

# --- LOGIN ---
@app.route("/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # Validate Drexel email and correct password
        if email and email.endswith("@drexel.edu") and password == "Drexel123!":
            session["user"] = email
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid Drexel email or password. Please try again."
            return render_template("login.html", error=error)

    return render_template("login.html", error=None)


# --- LOGIN REQUIRED DECORATOR ---
def require_login(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user" not in session:
            return redirect(url_for("login"))
        return func(*args, **kwargs)
    return wrapper


# --- DASHBOARD AND OTHER PAGES ---
@app.route("/dashboard")
@require_login
def dashboard():
    data = run_pipeline(use_api=False)
    return render_template(
        "dashboard.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )

@app.route("/hosts")
@require_login
def hosts():
    data = run_pipeline(use_api=False)
    return render_template(
        "hosts.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )

@app.route("/open_ports")
@require_login
def open_ports():
    data = run_pipeline(use_api=False)
    return render_template(
        "open_ports.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )

@app.route("/risk_summary")
@require_login
def risk_summary():
    data = run_pipeline(use_api=False)
    return render_template(
        "risk_summary.html",
        shodan=data["shodan"],
        censys=data["censys"],
        user=session.get("user")
    )


# --- LOGOUT ---
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)