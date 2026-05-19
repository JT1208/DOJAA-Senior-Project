"""Login / logout.

Credentials are verified against a PBKDF2-SHA-256 hash via werkzeug's
constant-time check. The plaintext password is never stored in source,
.env, or session state.
"""

from __future__ import annotations

from flask import Blueprint, current_app, redirect, render_template, request, session, url_for

from ..security import verify_password

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

        domain_ok = bool(domain) and email.endswith(f"@{domain}")
        # Always run verify_password — even on domain failure — so the
        # response time doesn't reveal whether the email was acceptable.
        password_ok = verify_password(settings.demo_password_hash, password)

        if domain_ok and password_ok:
            session.clear()
            session["user"] = email
            session.permanent = True
            return redirect(url_for("dashboard.index"))

        return render_template(
            "login.html",
            error="Invalid credentials.",
            email_domain=domain,
        )

    return render_template(
        "login.html",
        error=None,
        email_domain=settings.demo_email_domain,
    )


@bp.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("auth.login"))
