"""
Description:

    Loads scan json data into PostgreSQL.

Usage:
    python dojaa/writeToDb.py --file dashboard_data.json

Requirements:
    pip install psycopg2-binary

Database connection:
    In dojaa/config.py (DB_CONFIG)
"""

import argparse
import json
import os

import psycopg2
from psycopg2.extras import execute_values

from dojaa import config


def get_connection():
    return psycopg2.connect(
        host=config.DB_CONFIG["host"],
        port=config.DB_CONFIG["port"],
        dbname=config.DB_CONFIG["database"],
        user=config.DB_CONFIG["user"],
        password=config.DB_CONFIG["password"],
    )


def upsert_asset(cur, ip: str) -> int:
    cur.execute(
        """
        INSERT INTO public.assets (primary_ipv4, created_at, updated_at)
        VALUES (%s, NOW(), NOW())
        ON CONFLICT (primary_ipv4) DO UPDATE
            SET updated_at = NOW()
        RETURNING asset_id
        """,
        (ip,),
    )
    return cur.fetchone()[0]


def insert_shodan_general(cur, asset_id: int, record: dict):
    cur.execute(
        """
        INSERT INTO public.asset_shodan_general
            (asset_id, port, ip, service, banner, provider,
             ssh_exposed, http_exposed, https_exposed, known)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (
            asset_id,
            record.get("port"),
            record.get("ip"),
            record.get("service"),
            record.get("banner"),
            record.get("provider"),
            record.get("ssh_exposed"),
            record.get("http_exposed"),
            record.get("https_exposed"),
            record.get("known"),
        ),
    )


def insert_shodan_risk(cur, asset_id: int, record: dict):
    cur.execute(
        """
        INSERT INTO public.asset_shodan_risk
            (asset_id, risk_score, shadow_asset, severity,
             issues, service_intel, service_risk)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (
            asset_id,
            record.get("risk_score"),
            record.get("shadow_asset"),
            record.get("severity"),
            record.get("issues"),
            record.get("service_intel"),
            record.get("service_risk_hint"),
        ),
    )


def insert_recommendations(cur, asset_id: int, recommendations: list):
    if not recommendations:
        return
    rows = [(asset_id, r) for r in recommendations]
    execute_values(
        cur,
        """
        INSERT INTO public.asset_recommendations (asset_id, recommendation_text)
        VALUES %s
        ON CONFLICT DO NOTHING
        """,
        rows,
    )


def process_shodan(cur, records: list):
    print(f"  Processing {len(records)} shodan records...")
    for record in records:
        ip = record.get("ip")
        if not ip:
            continue
        asset_id = upsert_asset(cur, ip)
        insert_shodan_general(cur, asset_id, record)
        insert_shodan_risk(cur, asset_id, record)
        insert_recommendations(cur, asset_id, record.get("recommendations", []))
    print("  Shodan done.")


def insert_ssl_tls(cur, asset_id: int, record: dict):
    cur.execute(
        """
        INSERT INTO public.asset_ssl_tls
            (asset_id, issuer, subject, expiry, days_left, san,
             key_length, self_signed, risk_level, status,
             issuer_name, subject_name, issuer_cn, subject_cn,
             san_clean, trust)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT DO NOTHING
        """,
        (
            asset_id,
            record.get("issuer"),
            record.get("subject"),
            record.get("expiry"),
            record.get("days_left"),
            record.get("san"),
            record.get("key_length"),
            record.get("self_signed"),
            record.get("risk_level"),
            record.get("status"),
            record.get("issuer_name"),
            record.get("subject_name"),
            record.get("issuer_cn"),
            record.get("subject_cn"),
            record.get("san_clean"),
            record.get("trust"),
        ),
    )


def process_ssl_tls(cur, records: list):
    print(f"  Processing {len(records)} ssl_tls records...")
    for record in records:
        ip = record.get("ip")
        if not ip:
            continue
        asset_id = upsert_asset(cur, ip)
        insert_ssl_tls(cur, asset_id, record)
    print("  SSL/TLS done.")


def load(filepath: str):
    print(f"Loading: {filepath}")
    with open(filepath, "r") as f:
        data = json.load(f)

    conn = get_connection()
    try:
        with conn:
            with conn.cursor() as cur:
                shodan_records = data.get("shodan", [])
                ssl_tls_records = data.get("ssl_tls", [])
                censys_records = data.get("censys", [])

                if shodan_records:
                    process_shodan(cur, shodan_records)
                if ssl_tls_records:
                    process_ssl_tls(cur, ssl_tls_records)
                if censys_records:
                    print(
                        f"  WARNING: {len(censys_records)} censys records found but "
                        "censys DB schema is not implemented in this loader."
                    )

        print("\nAll done. Data committed successfully.")
    except Exception as e:
        print(f"\nERROR: {e}")
        conn.rollback()
        raise
    finally:
        conn.close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load JSON scan data into PostgreSQL.")
    parser.add_argument("--file", help="Path to JSON file (defaults to ../dashboard_data.json)")
    args = parser.parse_args()

    base_dir = os.path.dirname(os.path.abspath(__file__))
    default_file = os.path.normpath(os.path.join(base_dir, "../dashboard_data.json"))
    load(args.file or default_file)
