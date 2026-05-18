"""Flask blueprint registration."""

from __future__ import annotations

from flask import Flask

from . import auth, cves, dashboard, graph, hosts, ports, reports, risk, ssl_tls, tools


def register_blueprints(app: Flask) -> None:
    app.register_blueprint(auth.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(hosts.bp)
    app.register_blueprint(ports.bp)
    app.register_blueprint(risk.bp)
    app.register_blueprint(cves.bp)
    app.register_blueprint(ssl_tls.bp)
    app.register_blueprint(graph.bp)
    app.register_blueprint(tools.bp)
    app.register_blueprint(reports.bp)
