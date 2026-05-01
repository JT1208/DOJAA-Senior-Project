"""
Shared 0–100 risk bands: Low < 20, Medium 20–49, High ≥50.
Used by the dashboard, risk page, and PDF so counts stay consistent.
"""

from __future__ import annotations

from typing import Any


def risk_bucket(score: Any) -> str:
    """Classify a numeric risk score. Returns 'low' | 'medium' | 'high' | 'unknown'."""
    try:
        s = float(score)
    except (TypeError, ValueError):
        return "unknown"
    if s < 20:
        return "low"
    if s < 50:
        return "medium"
    return "high"


def risk_tier_counts(
    shodan: list[dict[str, Any]], censys: list[dict[str, Any]]
) -> tuple[int, int, int]:
    low = med = high = 0
    for row in shodan + censys:
        b = risk_bucket(row.get("risk_score"))
        if b == "low":
            low += 1
        elif b == "medium":
            med += 1
        elif b == "high":
            high += 1
    return low, med, high
