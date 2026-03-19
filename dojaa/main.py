from flask import Flask, render_template, request, jsonify
import logging
from dojaa.pipeline import run_pipeline

app = Flask(__name__)

# Logging setup
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("dojaa")

# Store last data in memory (simple approach)
DATA_STORE = {"shodan": [], "censys": []}


@app.route("/")
def dashboard():
    return render_template(
        "dashboard.html",
        user="Admin",
        shodan=DATA_STORE["shodan"],
        censys=DATA_STORE["censys"]
    )


@app.route("/run-pipeline", methods=["POST"])
def run_pipeline_route():
    data = request.json
    use_cache = data.get("use_cache", True)

    logger.info(f"Pipeline triggered | use_cache={use_cache}")

    try:
        result = run_pipeline(use_cache=use_cache)

        DATA_STORE["shodan"] = result.get("shodan", [])
        DATA_STORE["censys"] = result.get("censys", [])

        logger.info("Pipeline completed successfully")

        return jsonify({"status": "ok"})

    except Exception as e:
        logger.error(f"Pipeline failed: {e}")
        return jsonify({"status": "error"}), 500


@app.route("/log", methods=["POST"])
def log():
    data = request.json
    level = data.get("level", "info")

    msg = f"{data.get('message')} | {data.get('data')}"

    if level == "error":
        logger.error(msg)
    elif level == "warn":
        logger.warning(msg)
    else:
        logger.info(msg)

    return jsonify({"status": "logged"})


if __name__ == "__main__":
    app.run(debug=True)