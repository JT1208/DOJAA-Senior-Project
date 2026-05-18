"""CLI entrypoint to run the pipeline once and print a summary."""

from __future__ import annotations

import logging

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

from dojaa.pipeline import run_pipeline


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s: %(message)s")
    data = run_pipeline(use_api=True)

    print("\n--- DOJAA Pipeline Complete ---")
    print(f"Shodan assets : {len(data.get('shodan') or [])}")
    print(f"Censys assets : {len(data.get('censys') or [])}")
    print(f"CVE findings  : {len(data.get('cves') or [])}")
    print(f"SSL/TLS rows  : {len(data.get('ssl_tls') or [])}")

    for notice in data.get("_pipeline_notices") or []:
        print(f"[notice] {notice}")


if __name__ == "__main__":
    main()
