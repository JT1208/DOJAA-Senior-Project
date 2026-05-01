"""
DOJAA PDF report: exposure, risk tiers, Shodan/Censys, CVEs, optional SSL/TLS, executive analysis.
"""

from __future__ import annotations

import html
from collections import Counter, defaultdict
from datetime import datetime
from io import BytesIO
from statistics import fmean
from typing import Any

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from dojaa.risk_tiers import risk_tier_counts as _risk_counts

# Main narrative: 11 pt, double-spaced (leading = 2 × font size)
_REPORT_FONT = 11
_REPORT_LEADING = 22
# Usable table width: letter 8.5" minus left/right margins (0.72" each in SimpleDocTemplate)
_TABLE_PAGE_WIDTH = 6.9 * inch
# CVE findings table: Service column is truncated to this many characters (ellipsis included).
_CVE_TABLE_SERVICE_MAX = 200


def _escape_reportlab_paragraph(s: str) -> str:
    """Escape user/NVD text for ReportLab Paragraph; newlines become <br/>."""
    if not s:
        return ""
    t = s.replace("\r\n", "\n").replace("\r", "\n")
    t = html.escape(t, quote=False)
    return t.replace("\n", "<br/>")


def _truncate(s: str, max_len: int) -> str:
    s = (s or "").replace("\n", " ").replace("\r", " ").strip()
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."


def _severity_col_width_inches(max_chars: int, min_in: float, max_in: float) -> float:
    """Width for Sev column from longest string in that column (Helvetica ~11 pt table)."""
    m = max(1, int(max_chars))
    # Padding + approximate char advance (inch); clamp keeps sane bounds.
    pad = 0.34 * inch
    per_char = 0.090 * inch
    return max(min_in, min(max_in, pad + per_char * m))


def _cve_finding_table_col_widths(rows: list[list[str]]) -> list[float]:
    """
    Column widths for CVE findings table. Severity (Sev) width follows the longest
    cell in that column; remaining width is split across CVE, Service, CVSS, Published
    (Service capped; slack favors Published and CVSS).
    """
    n = 5
    sev_i = 2
    tot = float(_TABLE_PAGE_WIDTH)
    if not rows:
        return [tot / n] * n
    max_lens = [0] * n
    for row in rows:
        for c in range(n):
            if c < len(row):
                max_lens[c] = max(max_lens[c], len(str(row[c])))
    # Index: CVE, Service, Sev, CVSS, Published
    min_w = [0.88 * inch, 0.78 * inch, 0.70 * inch, 0.44 * inch, 0.80 * inch]
    max_w = [1.42 * inch, 2.48 * inch, 1.45 * inch, 0.65 * inch, 1.18 * inch]

    sev_w = _severity_col_width_inches(max_lens[sev_i], min_w[sev_i], max_w[sev_i])
    others = (0, 1, 3, 4)
    min_rest = sum(min_w[i] for i in others)
    if sev_w > tot - min_rest:
        sev_w = max(min_w[sev_i], tot - min_rest)
    rem = tot - sev_w

    weights = [max(1, max_lens[i]) for i in others]
    sw = float(sum(weights))
    raw_o = [rem * weights[j] / sw for j in range(4)]
    out_o = [max(min_w[others[j]], min(max_w[others[j]], raw_o[j])) for j in range(4)]

    def _slack_fill_four(slack: float, grow: bool) -> None:
        # Map position in out_o -> table column index
        pos_to_col = (others[0], others[1], others[2], others[3])
        if grow:
            order = (3, 2, 0, 1)  # Published, CVSS, CVE, Service
            for pos in order:
                if slack <= 0:
                    break
                col = pos_to_col[pos]
                room = max(0.0, max_w[col] - out_o[pos])
                add = min(slack, room)
                out_o[pos] += add
                slack -= add
            if slack > 0.0001 * inch:
                col = 1  # Service
                p = 1
                room = max(0.0, max_w[col] - out_o[p])
                out_o[p] = min(max_w[col], out_o[p] + slack)
        else:
            over = slack
            p = 1
            take = min(over, max(0.0, out_o[p] - min_w[pos_to_col[p]]))
            out_o[p] -= take
            over -= take
            if over > 0.0001 * inch:
                for pos in (1, 0, 2, 3):
                    if over <= 0:
                        break
                    col = pos_to_col[pos]
                    take = min(over, max(0.0, out_o[pos] - min_w[col]))
                    out_o[pos] -= take
                    over -= take

    s_rest = sum(out_o)
    eps = 0.0001 * inch
    if s_rest < rem - eps:
        _slack_fill_four(rem - s_rest, grow=True)
    elif s_rest > rem + eps:
        _slack_fill_four(s_rest - rem, grow=False)

    out = [out_o[0], out_o[1], sev_w, out_o[2], out_o[3]]
    drift = tot - sum(out)
    if abs(drift) > eps:
        out[4] = max(min_w[4], min(max_w[4], out[4] + drift))
        drift2 = tot - sum(out)
        if abs(drift2) > eps:
            out[1] = max(min_w[1], min(max_w[1], out[1] + drift2))
    return out


def _table(data: list[list[str]], col_widths: list[float] | None = None) -> Table:
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), _REPORT_FONT),
                ("FONTSIZE", (0, 1), (-1, -1), _REPORT_FONT),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t


def _table_full(data: list[list[str]], col_widths: list[float] | None = None) -> Table:
    """Tabular data (same 11 pt as body text; wide tables use horizontal space)."""
    t = Table(data, colWidths=col_widths, repeatRows=1)
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), _REPORT_FONT),
                ("FONTSIZE", (0, 1), (-1, -1), _REPORT_FONT),
                ("GRID", (0, 0), (-1, -1), 0.2, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f7fafc")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]
        )
    )
    return t


def _exposure_counts(shodan: list[dict[str, Any]], censys: list[dict[str, Any]]) -> tuple[int, int, int]:
    """Count assets with SSH, HTTP, HTTPS exposure flags (per-asset)."""
    combined = shodan + censys
    n_ssh = sum(1 for a in combined if a.get("ssh_exposed"))
    n_http = sum(1 for a in combined if a.get("http_exposed"))
    n_https = sum(1 for a in combined if a.get("https_exposed"))
    return n_ssh, n_http, n_https


def _exposure_bar_png(n_ssh: int, n_http: int, n_https: int) -> bytes:
    """SSH / HTTP / HTTPS exposure bar chart (PNG)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(4.2, 2.4), dpi=100)
    ax.bar(
        ["SSH", "HTTP", "HTTPS"],
        [n_ssh, n_http, n_https],
        color=["#ff6384", "#36a2eb", "#ffce56"],
    )
    ax.set_ylabel("Exposed assets", fontsize=10)
    ax.set_title("Exposure overview", fontsize=11)
    fig.tight_layout()
    bio = BytesIO()
    fig.savefig(bio, format="png", bbox_inches="tight", pad_inches=0.2)
    plt.close(fig)
    return bio.getvalue()


def _risk_pie_png_bytes(low: int, med: int, high: int) -> bytes:
    """Risk breakdown pie chart as PNG (matplotlib; avoids reportlab renderPM backends)."""
    import matplotlib

    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    fig, ax = plt.subplots(figsize=(4.2, 2.4), dpi=100)
    sizes = [low, med, high]
    labels = ["Low", "Medium", "High"]
    colors_m = ["#4bc0c0", "#ff9f40", "#ff6384"]
    # omit zero slices for cleaner pie
    pairs = [(s, l, c) for s, l, c in zip(sizes, labels, colors_m) if s > 0]
    if not pairs:
        ax.text(0.5, 0.5, "No data", ha="center", va="center")
    else:
        ss, ll, cc = zip(*pairs)
        ax.pie(ss, labels=ll, colors=list(cc), autopct="%1.0f%%", startangle=90, textprops={"fontsize": 10})
    ax.axis("equal")
    ax.set_title("Risk severity", fontsize=11)
    bio = BytesIO()
    fig.savefig(bio, format="png", bbox_inches="tight", pad_inches=0.15)
    plt.close(fig)
    return bio.getvalue()


def _risk_tier_counts_table_flowable(low: int, med: int, high: int) -> Table:
    """Colored tier counts when the risk pie image cannot be generated."""
    data = [
        ["Low (&lt;20)", "Medium (20–49)", "High (≥50)"],
        [str(low), str(med), str(high)],
    ]
    t = Table(
        data,
        colWidths=[_TABLE_PAGE_WIDTH / 3.0, _TABLE_PAGE_WIDTH / 3.0, _TABLE_PAGE_WIDTH / 3.0],
        repeatRows=0,
    )
    t.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c5282")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, 0), _REPORT_FONT),
                ("FONTSIZE", (0, 1), (-1, 1), _REPORT_FONT),
                ("BACKGROUND", (0, 1), (0, 1), colors.HexColor("#4bc0c0")),
                ("BACKGROUND", (1, 1), (1, 1), colors.HexColor("#ff9f40")),
                ("BACKGROUND", (2, 1), (2, 1), colors.HexColor("#ff6384")),
                ("ALIGN", (0, 1), (-1, 1), "CENTER"),
                ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
            ]
        )
    )
    return t


def _asset_service_label(asset: dict[str, Any]) -> str:
    svcs = asset.get("services") or []
    if isinstance(svcs, list) and svcs:
        return str(svcs[0])
    return str(asset.get("service") or "Unknown")


def _safe_float(x: Any, default: float = 0.0) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return default


def _cvss_num(v: dict[str, Any]) -> float:
    c = v.get("cvss_score")
    if isinstance(c, (int, float)):
        return float(c)
    if c is None or c == "" or c == "-":
        return -1.0
    try:
        return float(c)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return -1.0


def _summary_shodan(shodan: list[dict[str, Any]]) -> str:
    if not shodan:
        return "No Shodan rows in this scan."
    scores = [_safe_float(h.get("risk_score")) for h in shodan]
    ports = [h.get("port") for h in shodan if h.get("port") is not None and h.get("port") != ""]
    top_port = Counter(ports).most_common(1)
    top_p = f"port {top_port[0][0]} ({top_port[0][1]} rows)" if top_port else "n/a"
    svc_c = Counter(str(h.get("service") or "Unknown") for h in shodan)
    top_s = ", ".join(f"{n} ({c})" for n, c in svc_c.most_common(5))
    return (
        f"<b>Rows:</b> {len(shodan)}. <b>Unique IPs:</b> {len({h.get('ip') for h in shodan if h.get('ip')})}. "
        f"<b>Risk score:</b> min {min(scores):.0f}, max {max(scores):.0f}, mean {fmean(scores):.1f}. "
        f"<b>Most common port:</b> {top_p}. <b>Top services:</b> {top_s}."
    )


def _summary_censys(censys: list[dict[str, Any]]) -> str:
    if not censys:
        return "No Censys rows in this scan."
    scores = [_safe_float(c.get("risk_score")) for c in censys]
    return (
        f"<b>Rows:</b> {len(censys)}. <b>Unique IPs:</b> {len({c.get('ip') for c in censys if c.get('ip')})}. "
        f"<b>Risk score:</b> min {min(scores):.0f}, max {max(scores):.0f}, mean {fmean(scores):.1f}."
    )


def _summary_cves(cves: list[dict[str, Any]]) -> str:
    if not cves:
        return "No CVE records returned for this report."
    sev = Counter(str(v.get("severity") or "UNKNOWN") for v in cves)
    sev_line = ", ".join(f"{k}: {v}" for k, v in sev.most_common(6))
    cvss_nums = [float(v.get("cvss_score")) for v in cves if isinstance(v.get("cvss_score"), (int, float))]
    cvss_part = f"<b>CVSS:</b> min {min(cvss_nums):.1f}, max {max(cvss_nums):.1f}." if cvss_nums else ""
    dates = [v.get("published") or "" for v in cves if v.get("published")]
    date_part = f"<b>Published range:</b> {min(dates)} … {max(dates)}." if dates else ""
    return f"<b>Total CVEs:</b> {len(cves)}. {cvss_part} <b>Severity mix:</b> {sev_line} {date_part}"


def _append_ssl_tls_bullet_sections(
    story: list[Any],
    ssl_tls: list[dict[str, Any]],
    body: ParagraphStyle,
    h3: ParagraphStyle,
) -> None:
    """SSL/TLS report content as overview + per-asset bullet lists (no table)."""
    if not ssl_tls:
        story.append(
            Paragraph(
                "\u2022 No certificate rows (no port 443 collection or empty cache).",
                body,
            )
        )
        return

    story.append(Paragraph("<b>Overview</b>", body))
    story.append(Spacer(1, 0.06 * inch))
    n = len(ssl_tls)
    self_n = sum(1 for x in ssl_tls if str(x.get("self_signed", "")).lower() in ("true", "1", "yes"))
    story.append(Paragraph(f"\u2022 <b>Total certificates:</b> {n}", body))
    story.append(Paragraph(f"\u2022 <b>Flagged self-signed:</b> {self_n}", body))

    trust = Counter(str(x.get("trust") or "Unknown") for x in ssl_tls)
    story.append(Spacer(1, 0.06 * inch))
    story.append(Paragraph("<b>Trust (count per label)</b>", body))
    for label, cnt in trust.most_common():
        story.append(
            Paragraph(
                f"\u2022 {_escape_reportlab_paragraph(label)}: <b>{cnt}</b>",
                body,
            )
        )

    story.append(Spacer(1, 0.14 * inch))
    story.append(Paragraph("<b>Details by asset</b>", body))
    story.append(Spacer(1, 0.06 * inch))

    for cert in ssl_tls:
        ip = str(cert.get("ip") or "-")
        story.append(
            Paragraph(
                f"<b>Certificate</b> \u2014 {_escape_reportlab_paragraph(ip)}",
                h3,
            )
        )
        subj = str(cert.get("subject_name") or cert.get("subject") or "-")
        iss = str(cert.get("issuer_name") or cert.get("issuer") or "-")
        exp = str(cert.get("expiry") or cert.get("not_after") or "-")
        tr = str(cert.get("trust") or "-")
        self_yes = str(cert.get("self_signed", "")).lower() in ("true", "1", "yes")
        self_s = "Yes" if self_yes else "No"
        for label, val in (
            ("Subject", subj),
            ("Issuer", iss),
            ("Expiry", exp),
            ("Trust", tr),
            ("Self-signed", self_s),
        ):
            story.append(
                Paragraph(
                    f"\u2022 <b>{label}:</b> {_escape_reportlab_paragraph(val)}",
                    body,
                )
            )
        story.append(Spacer(1, 0.1 * inch))


def _exposure_flags_cell(asset: dict[str, Any]) -> str:
    parts: list[str] = []
    if asset.get("ssh_exposed"):
        parts.append("SSH")
    if asset.get("http_exposed"):
        parts.append("HTTP")
    if asset.get("https_exposed"):
        parts.append("HTTPS")
    return "+".join(parts) or "—"


def _highest_mean_risk_service(
    shodan: list[dict[str, Any]], censys: list[dict[str, Any]]
) -> tuple[str, float, int] | None:
    """Service name (display), mean risk, asset count. Skips 'Unknown' if possible."""
    by_svc: dict[str, list[float]] = defaultdict(list)
    for h in shodan:
        name = str(h.get("service") or "Unknown").strip() or "Unknown"
        by_svc[name].append(_safe_float(h.get("risk_score")))
    for c in censys:
        name = _asset_service_label(c).strip() or "Unknown"
        by_svc[name].append(_safe_float(c.get("risk_score")))

    candidates = [
        (svc, fmean(scores), len(scores))
        for svc, scores in by_svc.items()
        if scores and (svc != "Unknown" or len(by_svc) == 1)
    ]
    if not candidates:
        return None
    candidates.sort(key=lambda t: (t[1], t[2]), reverse=True)
    return candidates[0]


def _latest_cve_by_published(cves: list[dict[str, Any]]) -> dict[str, Any] | None:
    """Latest by ISO date (YYYY-MM-DD); on same date, prefer higher CVSS, then CVE id."""
    with_date = [v for v in cves if len((v.get("published") or "").strip()) >= 10]
    if not with_date:
        return cves[0] if cves else None

    def sort_key(v: dict[str, Any]) -> tuple[str, float, str]:
        p = (v.get("published") or "").strip()[:10]
        return (p, _cvss_num(v), str(v.get("cve_id") or ""))

    return max(with_date, key=sort_key)


def _asset_match_score_for_cve_keyword(asset: dict[str, Any], kw_lower: str) -> int:
    """3 = exact service label match, 2 = substring token overlap, 0 = no match."""
    if not kw_lower or kw_lower == "unknown":
        return 0
    labels: list[str] = []
    svc = str(asset.get("service") or "").strip().lower()
    if svc:
        labels.append(svc)
    svcs = asset.get("services") or []
    if isinstance(svcs, list):
        for x in svcs:
            s = str(x).strip().lower()
            if s:
                labels.append(s)
    best = 0
    for lab in labels:
        if lab == kw_lower:
            best = max(best, 3)
        elif kw_lower in lab or lab in kw_lower:
            best = max(best, 2)
    return best


def _best_asset_row_for_cve_keyword(
    keyword: str,
    shodan: list[dict[str, Any]],
    censys: list[dict[str, Any]],
) -> dict[str, Any] | None:
    """Pick one scan row best matching the CVE’s stored keyword (highest match, then risk)."""
    kw = (keyword or "").strip().lower()
    if not kw or kw == "unknown":
        return None
    ranked: list[tuple[int, float, int, dict[str, Any]]] = []
    for idx, a in enumerate(shodan + censys):
        ms = _asset_match_score_for_cve_keyword(a, kw)
        if ms == 0:
            continue
        ranked.append((ms, _safe_float(a.get("risk_score")), idx, a))
    if not ranked:
        return None
    ranked.sort(key=lambda t: (-t[0], -t[1], t[2]))
    return ranked[0][3]


def _tls_cert_for_ip(
    ssl_tls: list[dict[str, Any]], ip: str
) -> dict[str, Any] | None:
    ip_s = str(ip).strip()
    for c in ssl_tls:
        if str(c.get("ip") or "").strip() == ip_s:
            return c
    return None


def _append_executive_intel_snapshot(
    story: list[Any],
    shodan: list[dict[str, Any]],
    censys: list[dict[str, Any]],
    ssl_tls: list[dict[str, Any]],
    latest_cve: dict[str, Any] | None,
    body: ParagraphStyle,
) -> None:
    """
    Single asset snapshot tied to the most date-relevant CVE: IP, port, service,
    TLS cert for that IP (if any), risk /100, plus CVE CVSS /10.
    """
    story.append(Paragraph("<b>Spotlight CVE \u2014 linked asset row</b>", body))
    story.append(Spacer(1, 0.06 * inch))

    if not latest_cve:
        story.append(
            Paragraph(
                "\u2022 No CVE in cache to anchor this summary; add scans and CVE data first.",
                body,
            )
        )
        story.append(Spacer(1, 0.12 * inch))
        return

    lid = str(latest_cve.get("cve_id") or "—")
    kw_raw = str(latest_cve.get("service") or "").strip()
    kw_esc = html.escape(kw_raw) if kw_raw else "—"
    lsev = str(latest_cve.get("severity") or "—")
    lpub = str(latest_cve.get("published") or "—")
    lcv = latest_cve.get("cvss_score")
    if isinstance(lcv, (int, float)):
        lcv_txt = f"{float(lcv):.1f}"
        cvss_line = f"CVSS <b>{lcv_txt}</b>/10.0 (NVD base score scale)."
    else:
        cvss_line = "CVSS not numeric in cache."

    story.append(
        Paragraph(
            f"\u2022 <b>CVE:</b> <b>{html.escape(lid)}</b> · keyword <b>{kw_esc}</b> · "
            f"{html.escape(lsev)} · published <b>{html.escape(lpub)}</b> · {cvss_line}",
            body,
        )
    )

    asset = _best_asset_row_for_cve_keyword(kw_raw, shodan, censys)
    if not asset:
        story.append(
            Paragraph(
                "\u2022 <b>Scan row:</b> no Shodan/Censys row matched this CVE’s keyword "
                "(exact or partial match on service labels). See full host tables earlier in the report.",
                body,
            )
        )
        story.append(Spacer(1, 0.12 * inch))
        return

    ip_s = str(asset.get("ip") or "—").strip()
    port_v = asset.get("port")
    port_s = str(port_v).strip() if port_v is not None and str(port_v).strip() != "" else "—"
    svc_disp = _asset_service_label(asset).strip() or str(asset.get("service") or "—")
    risk = _safe_float(asset.get("risk_score"))

    story.append(
        Paragraph(f"\u2022 <b>IP:</b> {html.escape(ip_s)}", body),
    )
    story.append(
        Paragraph(f"\u2022 <b>Port:</b> {html.escape(port_s)}", body),
    )
    story.append(
        Paragraph(
            f"\u2022 <b>Service:</b> {_escape_reportlab_paragraph(svc_disp)}",
            body,
        ),
    )
    story.append(
        Paragraph(
            f"\u2022 <b>Risk score</b> (DOJAA <b>0\u2013100</b>): <b>{risk:.0f}</b>/100 on this row.",
            body,
        ),
    )

    cert = _tls_cert_for_ip(ssl_tls, ip_s)
    if cert:
        subj = _truncate(str(cert.get("subject_name") or cert.get("subject") or "-"), 120)
        iss = _truncate(str(cert.get("issuer_name") or cert.get("issuer") or "-"), 120)
        tr = str(cert.get("trust") or "-")
        story.append(
            Paragraph(
                "\u2022 <b>Certificate</b> (TLS row for this IP): "
                f"<b>Subject</b> {_escape_reportlab_paragraph(subj)} · "
                f"<b>Issuer</b> {_escape_reportlab_paragraph(iss)} · "
                f"<b>Trust</b> {_escape_reportlab_paragraph(tr)}",
                body,
            )
        )
    else:
        story.append(
            Paragraph(
                "\u2022 <b>Certificate:</b> no TLS certificate row stored for this IP in this report.",
                body,
            )
        )

    story.append(Spacer(1, 0.12 * inch))


def _append_cve_references_for_record(
    story: list[Any],
    v: dict[str, Any],
    cve_ref_heading: ParagraphStyle,
    cve_ref_line: ParagraphStyle,
) -> None:
    """NVD reference URLs, tags, and source (used in executive analysis only)."""
    story.append(Paragraph("<b>References and advisories (NVD)</b>", cve_ref_heading))
    refs = v.get("references")
    if not isinstance(refs, list) or not refs:
        story.append(
            Paragraph(
                "<i>No reference URLs in the cache for this record (rescan to refresh NVD data).</i>",
                cve_ref_line,
            )
        )
        return
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        u = (ref.get("url") or "").strip()
        if not u:
            continue
        tags = ref.get("tags") or []
        tag_part = f" — <i>{html.escape(', '.join(str(t) for t in tags))}</i>" if tags else ""
        src = (ref.get("source") or "").strip()
        src_part = f" <i>[{html.escape(src)}]</i>" if src else ""
        line = f"• {html.escape(u)}{tag_part}{src_part}"
        story.append(Paragraph(line, cve_ref_line))


def _append_cve_descriptions_only(
    story: list[Any],
    cves: list[dict[str, Any]],
    body: ParagraphStyle,
    h2: ParagraphStyle,
    h3_cve: ParagraphStyle,
    cve_desc_style: ParagraphStyle,
) -> None:
    story.append(Paragraph("CVE descriptions (NVD)", h2))
    story.append(
        Paragraph(
            "Each CVE below includes the <b>full English description</b> from the cached NVD record. "
            "Reference links for the date-relevant CVE appear in the <b>Executive analysis</b> section at the end of this report.",
            body,
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    if not cves:
        story.append(Paragraph("No CVE rows in this report.", body))
        return
    service_heading_cap = max(
        (
            len(_truncate(str(v.get("service") or "-"), _CVE_TABLE_SERVICE_MAX))
            for v in cves
        ),
        default=_CVE_TABLE_SERVICE_MAX,
    )
    # _truncate needs a sensible minimum output budget
    service_heading_cap = max(service_heading_cap, 4)

    for v in cves:
        cid = str(v.get("cve_id") or "—")
        service = _truncate(str(v.get("service") or "—"), service_heading_cap)
        cv = v.get("cvss_score")
        cv_s = str(cv) if cv is not None and cv != "" else "—"
        pub = str(v.get("published") or "—")
        sev = str(v.get("severity") or "—")
        head = f"<b>{html.escape(cid)}</b> · {html.escape(service)} · {html.escape(sev)} · CVSS {html.escape(cv_s)} · {html.escape(pub)}"
        story.append(Paragraph(head, h3_cve))
        desc = (v.get("description") or "").strip() or "No description was available in the cached NVD data for this CVE."
        story.append(Paragraph(_escape_reportlab_paragraph(desc), cve_desc_style))
        story.append(Spacer(1, 0.1 * inch))


def _build_report_pdf(
    shodan: list[dict[str, Any]],
    censys: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    ssl_tls: list[dict[str, Any]],
    user: str | None,
) -> BytesIO:
    """Report: cover, TOC, exposure/risk charts, full Shodan/Censys/CVE tables, SSL bullets, executive analysis."""
    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=letter,
        rightMargin=0.72 * inch,
        leftMargin=0.72 * inch,
        topMargin=0.72 * inch,
        bottomMargin=0.72 * inch,
    )
    styles = getSampleStyleSheet()
    body = ParagraphStyle(
        name="ReportBody",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
    )
    title = ParagraphStyle(
        name="CoverTitle",
        parent=styles["Title"],
        fontSize=26,
        leading=32,
        alignment=TA_CENTER,
        spaceAfter=18,
    )
    subtitle = ParagraphStyle(
        name="CoverMeta",
        parent=body,
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
        alignment=TA_CENTER,
        spaceAfter=10,
    )
    h2 = ParagraphStyle(
        name="SectionH2",
        parent=styles["Heading2"],
        fontSize=14,
        leading=28,
        spaceBefore=6,
        spaceAfter=10,
    )
    h3_cve = ParagraphStyle(
        name="CveNarrativeTitle",
        parent=styles["Heading3"],
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
        spaceBefore=8,
        spaceAfter=4,
    )
    cve_desc_style = ParagraphStyle(
        name="CveDescription",
        parent=body,
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
        spaceAfter=4,
    )
    cve_ref_heading = ParagraphStyle(
        name="CveRefHead",
        parent=body,
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
        spaceBefore=2,
        spaceAfter=2,
    )
    cve_ref_line = ParagraphStyle(
        name="CveRefLine",
        parent=body,
        fontSize=_REPORT_FONT,
        leading=_REPORT_LEADING,
        leftIndent=12,
        spaceAfter=1,
    )

    story: list[Any] = []
    now = datetime.now()
    date_str = now.strftime("%B %d, %Y")
    time_str = now.strftime("%I:%M:%S %p")

    # ----- Page 1: cover -----
    story.append(Spacer(1, 1.4 * inch))
    story.append(Paragraph("DOJAA Report", title))
    story.append(Spacer(1, 0.35 * inch))
    story.append(Paragraph(f"<b>Date:</b> {date_str}", subtitle))
    story.append(Paragraph(f"<b>Time generated:</b> {time_str}", subtitle))
    if user:
        story.append(Paragraph(f"<b>Prepared for:</b> {user}", subtitle))
    story.append(PageBreak())

    # ----- Page 2: table of contents -----
    story.append(Paragraph("Table of Contents", h2))
    story.append(Spacer(1, 0.15 * inch))
    toc_items = [
        "Exposure overview — SSH, HTTP, and HTTPS exposure counts.",
        "Risk severity summary — Low / Medium / High tiers on the 0–100 scale (Low &lt;20, Medium 20–49, High ≥50).",
        "Shodan — summary statistics and the full set of Shodan rows from this scan.",
        "Censys — summary statistics and the full set of Censys rows from this scan.",
        "CVEs — summary table and full <i>descriptions</i> only; references for the highlighted CVE are in Executive analysis.",
        "SSL/TLS — overview and each certificate (port 443) as bullet lists.",
        "Executive analysis — one asset row (IP, port, service, cert, risk /100) tied to the spotlight CVE; highest mean risk by service; CVE <i>description</i> and <i>references</i> (NVD).",
    ]
    for item in toc_items:
        story.append(Paragraph(f"\u2022 {item}", body))
        story.append(Spacer(1, 0.12 * inch))
    story.append(PageBreak())

    # ----- Page 3: Exposure overview -----
    story.append(Paragraph("Exposure Overview", h2))
    n_ssh, n_http, n_https = _exposure_counts(shodan, censys)
    n_sh = len(shodan)
    n_ce = len(censys)
    story.append(
        Paragraph(
            f"Per-asset SSH, HTTP, and HTTPS exposure flags. "
            f"<b>Shodan rows:</b> {n_sh}, <b>Censys rows:</b> {n_ce}. "
            f"<b>SSH-exposed assets:</b> {n_ssh}, <b>HTTP-exposed:</b> {n_http}, <b>HTTPS-exposed:</b> {n_https}.",
            body,
        )
    )
    story.append(Spacer(1, 0.12 * inch))
    try:
        exp_png = _exposure_bar_png(n_ssh, n_http, n_https)
        story.append(Image(BytesIO(exp_png), width=4.2 * inch, height=2.4 * inch))
    except Exception:
        story.append(Paragraph("<i>Exposure chart could not be rendered.</i>", body))
    story.append(PageBreak())

    # ----- Page 4: Risk severity -----
    story.append(Paragraph("Risk Severity Summary", h2))
    low, med, high = _risk_counts(shodan, censys)
    total_r = low + med + high
    story.append(
        Paragraph(
            f"Risk scores use the project 0–100 model. Counts by tier: "
            f"<b>Low</b> (&lt;20): {low}, <b>Medium</b> (20–49.99): {med}, <b>High</b> (≥50): {high} "
            f"(rows: {total_r}).",
            body,
        )
    )
    story.append(Spacer(1, 0.1 * inch))
    if total_r > 0:
        try:
            png_data = _risk_pie_png_bytes(low, med, high)
            story.append(Image(BytesIO(png_data), width=4.2 * inch, height=2.4 * inch))
        except Exception:
            story.append(
                Paragraph(
                    "<i>Pie image unavailable (e.g. matplotlib not installed). Tier counts as colored cells:</i>",
                    body,
                )
            )
            story.append(Spacer(1, 0.08 * inch))
            story.append(_risk_tier_counts_table_flowable(low, med, high))
    else:
        story.append(Paragraph("<i>No risk-scored rows to chart.</i>", body))
    story.append(PageBreak())

    # ----- Shodan: full table -----
    story.append(Paragraph("Shodan results (all rows)", h2))
    story.append(Paragraph(_summary_shodan(shodan), body))
    story.append(Spacer(1, 0.1 * inch))
    s5: list[list[str]] = [["IP", "Port", "Service", "Risk", "Exposure"]]
    for h in shodan:
        s5.append(
            [
                str(h.get("ip") or "-"),
                str(h.get("port") or "-"),
                _truncate(str(h.get("service") or "-"), 56),
                str(h.get("risk_score") if h.get("risk_score") is not None else "0"),
                _exposure_flags_cell(h),
            ]
        )
    if len(s5) == 1:
        s5.append(["—", "—", "No Shodan rows in this scan", "0", "—"])
    story.append(
        _table_full(
            s5,
            col_widths=[
                1.15 * inch,
                0.5 * inch,
                3.35 * inch,
                0.55 * inch,
                1.35 * inch,
            ],
        )
    )
    story.append(PageBreak())

    # ----- Censys: full table -----
    story.append(Paragraph("Censys results (all rows)", h2))
    story.append(Paragraph(_summary_censys(censys), body))
    story.append(Spacer(1, 0.1 * inch))
    c5: list[list[str]] = [["IP", "Services", "Risk", "Exposure"]]
    for c in censys:
        svcs = c.get("services") or []
        if isinstance(svcs, list) and svcs:
            svc_str = _truncate(", ".join(str(s) for s in svcs), 95)
        else:
            svc_str = str(c.get("service") or "-")
        c5.append(
            [
                str(c.get("ip") or "-"),
                svc_str,
                str(c.get("risk_score") if c.get("risk_score") is not None else "0"),
                _exposure_flags_cell(c),
            ]
        )
    if len(c5) == 1:
        c5.append(["—", "No Censys rows in this scan", "0", "—"])
    story.append(
        _table_full(
            c5,
            col_widths=[
                1.15 * inch,
                4.5 * inch,
                0.55 * inch,
                0.7 * inch,
            ],
        )
    )
    story.append(PageBreak())

    # ----- CVE: index table + descriptions (no references; refs for highlighted CVE in Executive analysis) -----
    story.append(Paragraph("CVE findings (full cache for this report)", h2))
    story.append(Paragraph(_summary_cves(cves), body))
    story.append(Spacer(1, 0.1 * inch))
    cr: list[list[str]] = [
        ["CVE", "Service", "Sev", "CVSS", "Published"],
    ]
    for v in cves:
        cr.append(
            [
                str(v.get("cve_id") or "-"),
                _truncate(str(v.get("service") or "-"), _CVE_TABLE_SERVICE_MAX),
                str(v.get("severity") or "-"),
                str(v.get("cvss_score") if v.get("cvss_score") is not None else "-"),
                str(v.get("published") or "-"),
            ]
        )
    if len(cr) == 1:
        cr.append(["—", "—", "—", "—", "—"])
    story.append(_table_full(cr, col_widths=_cve_finding_table_col_widths(cr)))
    _append_cve_descriptions_only(story, cves, body, h2, h3_cve, cve_desc_style)
    story.append(PageBreak())

    # ----- SSL/TLS: sections of bullet points -----
    story.append(Paragraph("SSL/TLS certificates", h2))
    story.append(Spacer(1, 0.08 * inch))
    _append_ssl_tls_bullet_sections(story, ssl_tls, body, h3_cve)
    story.append(PageBreak())

    # ----- Last page: executive analysis -----
    story.append(Paragraph("Executive analysis", h2))
    latest = _latest_cve_by_published(cves)
    _append_executive_intel_snapshot(story, shodan, censys, ssl_tls, latest, body)
    hi = _highest_mean_risk_service(shodan, censys)
    if hi:
        name, mean_r, nrows = hi
        story.append(
            Paragraph(
                f"<b>Highest mean risk by service name (Shodan + Censys):</b> <i>{name}</i> with mean risk "
                f"<b>{mean_r:.1f}</b> / 100 over <b>{nrows}</b> row(s). "
                "The mean is over all rows that share the same service label; rows labeled <i>Unknown</i> are only ranked "
                "if there are no other named service groups.",
                body,
            )
        )
    else:
        story.append(
            Paragraph(
                "No service-labeled risk rows were available to rank by mean score (or only “Unknown” services).",
                body,
            )
        )
    story.append(Spacer(1, 0.12 * inch))
    if latest:
        lid = str(latest.get("cve_id") or "—")
        lsvc = str(latest.get("service") or "—")
        lpub = str(latest.get("published") or "—")
        lsev = str(latest.get("severity") or "—")
        lcv = latest.get("cvss_score")
        lcv_s = str(lcv) if lcv is not None and lcv != "" else "—"
        story.append(
            Paragraph(
                f"<b>Most date-relevant CVE</b> (latest <i>published</i> date in this report’s cache; CVSS as tie-breaker): "
                f"<b>{html.escape(lid)}</b> — keyword <b>{html.escape(lsvc)}</b> · {html.escape(lsev)} · published <b>{html.escape(lpub)}</b> · CVSS {html.escape(lcv_s)}.",
                body,
            )
        )
        story.append(Spacer(1, 0.1 * inch))
        story.append(Paragraph("<b>Description (NVD)</b>", cve_ref_heading))
        ldesc = (latest.get("description") or "").strip() or "No description was available in the cached NVD data for this CVE."
        story.append(Paragraph(_escape_reportlab_paragraph(ldesc), cve_desc_style))
        story.append(Spacer(1, 0.06 * inch))
        _append_cve_references_for_record(story, latest, cve_ref_heading, cve_ref_line)
    else:
        story.append(
            Paragraph("No CVE records were present in the cache to evaluate by date.", body)
        )

    doc.build(story)
    buf.seek(0)
    return buf


def build_dashboard_report_pdf(
    shodan: list[dict[str, Any]],
    censys: list[dict[str, Any]],
    cves: list[dict[str, Any]],
    ssl_tls: list[dict[str, Any]],
    user: str | None,
) -> tuple[bytes | None, str | None]:
    """Return the generated ReportLab PDF only (no external template merge)."""
    try:
        core_buf = _build_report_pdf(shodan, censys, cves, ssl_tls, user)
        return core_buf.getvalue(), None
    except Exception as e:
        return None, f"Could not build report PDF: {e}"
