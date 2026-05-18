"""Login / logout."""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

bp = Blueprint("auth", __name__)


@bp.route("/", methods=["GET", "POST"])
@bp.route("/login", methods=["GET", "POST"])
def login():
    settings = current_app.config["DOJAA_SETTINGS"]
    if settings.auth_disabled:
        return redirect(url_for("dashboard.index"))

    if request.method == "POST":
        email = (request.form.get("email") or "").strip()
        password = request.form.get("password") or ""
        domain = settings.demo_email_domain
        demo_password = settings.demo_password

        if (
            demo_password
            and email.endswith(f"@{domain}")
            and password == demo_password
        ):
            session["user"] = email
            return redirect(url_for("dashboard.index"))

        return render_template("login.html", error="Invalid login", email_domain=domain)

    return render_template("login.html", error=None, email_domain=settings.demo_email_domain)


@bp.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("auth.login"))
