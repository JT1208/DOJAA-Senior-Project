"""Flask entrypoint — thin wrapper around the application factory."""

from __future__ import annotations

from dojaa import create_app

app = create_app()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=app.config.get("DEBUG", False))
