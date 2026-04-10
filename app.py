# app.py
from flask import Flask, render_template, request, redirect, url_for, session
from dojaa.pipeline import run_pipeline
from functools import wraps
import subprocess
import os
import shutil
import requests
import ipaddress
import re

class Robots():
    def __init__(self, siteName):
        try:
            IP = ipaddress.ip_address(siteName)
            response = requests.get(IP)
            self.address = response.url
        except ValueError:
            try:
                response = requests.get('https://' + siteName)
                self.address = response.url
            except:
                self.address = None

        if self.address != None:
            rules = {}
            robotstxt = requests.get(self.address + "robots.txt").text.split('\n')
            agents = []
            agentFlag = False
            for line in robotstxt:
                if "User-agent" in line:
                    if not agentFlag:
                        agents = []
                    agents.append(line.split(' ')[1])
                    agentFlag = True
                elif "Disallow" in line:
                    for agent in agents:
                        rules.setdefault(agent, []).append([False, line.split(' ')[1]])
                    agentFlag = False
                elif "Allow" in line:
                    for agent in agents:
                        rules.setdefault(agent, []).append([True, line.split(' ')[1]])
                    agentFlag = False
            self.rules = rules

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


# --- HELPER TO GET DATA ---
def get_dashboard_data(rescan=False):
    """
    Returns the dashboard data.
    If rescan=True, forces fresh API scan and overwrites JSON cache.
    Otherwise, uses cached data if available.
    """
    return run_pipeline(use_api=rescan)


# --- DASHBOARD AND OTHER PAGES ---
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

@app.route("/robots")
@require_login
def robots():
    rescan = request.args.get("rescan", "false").lower() == "true"
    data = get_dashboard_data(rescan=rescan)
    robotstxt = Robots("www.google.com") # Change later
    directories = []

    for i in range(len(robotstxt.rules["*"])):
        directories.append(robotstxt.rules["*"][i][1])
    try:
        shutil.rmtree("./robotslist")
    except:
        pass
    for dir in directories:
        os.makedirs("./robotslist"+dir, exist_ok=True)
    command = ["tree", "./robotslist"]
    result = subprocess.run(
    command,
    capture_output=True,
    text=True,
    check=True
    )
    string = result.stdout[13:]
    return render_template(
        "robots.html",
        shodan=string,
        censys=data["censys"],
        user=session.get("user"),
    )

# --- LOGOUT ---
@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run(debug=True)