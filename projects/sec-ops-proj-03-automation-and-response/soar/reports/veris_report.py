"""
soar/reports/veris_report.py — VERIS Weekly Incident Summary Report

Generates a DBIR-style Markdown report for a given date range.

Run directly to produce last-7-days report:
    python -m soar.reports.veris_report

Or import and call:
    from soar.reports.veris_report import generate_weekly_report
    generate_weekly_report(start_date, end_date, output_path)

Task 4 Deliverable — students complete the TODO sections below.
"""

import json
import os
import datetime
import sys

# Make sure we can import soar.database when run as a script
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from soar.database import fetch_all  # noqa: E402


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_weekly_report(start_date: str, end_date: str, output_path: str) -> None:
    """
    Generate a VERIS summary report for incidents closed between *start_date*
    and *end_date* and write it to *output_path* as Markdown.

    Args:
        start_date:  ISO date string "YYYY-MM-DD" (inclusive).
        end_date:    ISO date string "YYYY-MM-DD" (inclusive).
        output_path: File path for the Markdown report (e.g. /reports/weekly_summary.md).

    TODO (Task 4):
        Complete each step below by replacing the stub with real logic.
    """

    # -----------------------------------------------------------------------
    # Step 1: Load closed incidents in the date range
    # -----------------------------------------------------------------------
    # TODO: Use fetch_all() with a query like:
    #   SELECT * FROM incidents
    #   WHERE status = 'closed'
    #     AND closed_time >= ? AND closed_time <= ?
    # TODO: If no incidents found, write "No closed incidents in this period."
    #       and return early.
    incidents = []  # TODO: replace with real query

    # -----------------------------------------------------------------------
    # Step 2: Aggregate by VERIS actor category
    # -----------------------------------------------------------------------
    # VERIS actor categories: External, Internal, Partner, Unknown
    # TODO: For each incident, parse veris_classification JSON.
    #       Extract the top-level keys under "actor" (e.g. "external", "internal").
    #       Accumulate counts per category.
    actor_counts: dict[str, int] = {}  # e.g. {"External": 20, "Internal": 2}

    # -----------------------------------------------------------------------
    # Step 3: Aggregate by VERIS action category
    # -----------------------------------------------------------------------
    # VERIS action categories: Hacking, Malware, Social, Error, Misuse, Physical, Environmental
    # TODO: For each incident parse veris_classification["action"] and count categories.
    action_counts: dict[str, int] = {}

    # -----------------------------------------------------------------------
    # Step 4: Top action varieties
    # -----------------------------------------------------------------------
    # TODO: Drill into each action category and collect variety strings.
    #       e.g. veris["action"]["hacking"]["variety"] → ["Brute-force"]
    # TODO: Sort by frequency and keep the top 3.
    variety_counts: dict[str, int] = {}

    # -----------------------------------------------------------------------
    # Step 5: Top asset types targeted
    # -----------------------------------------------------------------------
    # TODO: Parse veris_classification["asset"]["assets"] → list of dicts.
    #       Extract the "variety" field from each.
    # TODO: Sort by frequency and keep the top 3.
    asset_counts: dict[str, int] = {}

    # -----------------------------------------------------------------------
    # Step 6: Compute mean MTTD and MTTR
    # -----------------------------------------------------------------------
    # TODO: Average the mttd_hours and mttr_hours columns from your incidents list.
    #       (Already computed by the API when incidents are closed.)
    total = len(incidents)
    mttd_values = [inc["mttd_hours"] for inc in incidents if inc.get("mttd_hours") is not None]
    mttr_values = [inc["mttr_hours"] for inc in incidents if inc.get("mttr_hours") is not None]
    avg_mttd = sum(mttd_values) / len(mttd_values) if mttd_values else 0.0
    avg_mttr = sum(mttr_values) / len(mttr_values) if mttr_values else 0.0

    # -----------------------------------------------------------------------
    # Step 7: Build the Markdown report
    # -----------------------------------------------------------------------
    # TODO: Use the helper functions _ascii_bar() and _pct_line() to produce
    #       DBIR-style percentage bars.
    # TODO: Write the report to output_path.
    week_label = _week_label(start_date)
    lines = [
        f"# WEEKLY SOC SUMMARY — {week_label}",
        "=" * 40,
        f"Total Incidents: {total}",
        f"Average MTTD: {avg_mttd:.1f} hours",
        f"Average MTTR: {avg_mttr:.1f} hours",
        "",
        "## Actor Categories",
        "",
    ]

    # TODO: replace the placeholder with real actor breakdown using _pct_line()
    if actor_counts:
        for category, count in sorted(actor_counts.items(), key=lambda x: -x[1]):
            pct = count / total if total else 0
            lines.append(f"  {_pct_line(category, pct, count)}")
    else:
        lines.append("  (no data — implement actor aggregation in Step 2)")

    lines += [
        "",
        "## Action Categories",
        "",
    ]

    # TODO: replace with real action breakdown
    if action_counts:
        for category, count in sorted(action_counts.items(), key=lambda x: -x[1]):
            pct = count / total if total else 0
            lines.append(f"  {_pct_line(category, pct, count)}")
    else:
        lines.append("  (no data — implement action aggregation in Step 3)")

    lines += [
        "",
        "## Top Action Varieties",
        "",
    ]

    # TODO: replace with real variety breakdown
    top_varieties = sorted(variety_counts.items(), key=lambda x: -x[1])[:3]
    if top_varieties:
        for rank, (variety, count) in enumerate(top_varieties, 1):
            pct = count / total if total else 0
            lines.append(f"  {rank}. {_pct_line(variety, pct, count)}")
    else:
        lines.append("  (no data — implement variety aggregation in Step 4)")

    lines += [
        "",
        "## Top Asset Types Targeted",
        "",
    ]

    top_assets = sorted(asset_counts.items(), key=lambda x: -x[1])[:3]
    if top_assets:
        for rank, (asset, count) in enumerate(top_assets, 1):
            pct = count / total if total else 0
            lines.append(f"  {rank}. {_pct_line(asset, pct, count)}")
    else:
        lines.append("  (no data — implement asset aggregation in Step 5)")

    report = "\n".join(lines) + "\n"

    dirpath = os.path.dirname(output_path)
    if dirpath:
        os.makedirs(dirpath, exist_ok=True)
    with open(output_path, "w") as fh:
        fh.write(report)

    print(f"Report written to {output_path}")


# ---------------------------------------------------------------------------
# Formatting helpers
# ---------------------------------------------------------------------------

def _ascii_bar(pct: float, width: int = 20) -> str:
    """
    Return an ASCII progress bar proportional to *pct* (0.0 – 1.0).

    Example:
        _ascii_bar(0.52)  → '||||||||||'  (10 pipes for 52 %)
        _ascii_bar(0.87)  → '|||||||||||||||||'  (17 pipes for 87 %)

    Args:
        pct:   Fraction between 0.0 and 1.0.
        width: Maximum number of pipe characters (default 20).

    Returns:
        str: String of '|' characters, left-padded with spaces to *width*.
    """
    filled = int(pct * width)
    return "|" * filled


def _pct_line(label: str, pct: float, count: int, label_width: int = 18) -> str:
    """
    Format a single DBIR-style percentage bar line.

    Example output:
        External  ||||||||||||||||||||  87%  (20)
    """
    bar = _ascii_bar(pct)
    return f"{label:<{label_width}} {bar:<20}  {int(pct * 100):3d}%  ({count:3d})"


def _week_label(start_date: str) -> str:
    """Return a human-readable week label, e.g. 'Week of 2024-03-11'."""
    return f"Week of {start_date}"


# ---------------------------------------------------------------------------
# Script entry point — generate last-7-days report
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    today = datetime.date.today()
    week_ago = today - datetime.timedelta(days=7)

    start = week_ago.isoformat()
    end = today.isoformat()
    out = os.environ.get("REPORT_OUTPUT", "/reports/weekly_summary.md")

    print(f"Generating VERIS report for {start} → {end}")
    generate_weekly_report(start, end, out)
