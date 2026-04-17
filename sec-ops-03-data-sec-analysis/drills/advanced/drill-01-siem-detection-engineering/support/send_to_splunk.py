#!/usr/bin/env python3
"""
send_to_splunk.py — Ingest JSON events into Splunk via HTTP Event Collector (HEC).

Usage:
    cat events.jsonl | python3 send_to_splunk.py [OPTIONS]
    python3 send_to_splunk.py --hec-url http://splunk:8088 --token mytoken < events.jsonl

Each line of stdin must be a valid JSON object representing a single log event.
Events are wrapped in the HEC envelope and sent in batches to reduce HTTP overhead.

Options:
    --hec-url      Base URL of the Splunk HEC endpoint  (default: http://localhost:8088)
    --token        HEC authentication token             (default: demo03-token)
    --sourcetype   Splunk sourcetype for all events     (default: xmlwineventlog)
    --index        Splunk index to write into           (default: windows)
    --batch-size   Number of events per HTTP request    (default: 50)

Exit codes:
    0  All events sent successfully (or no events read)
    1  At least one batch failed
"""

import argparse
import json
import sys
import urllib.request
import urllib.error
from typing import List, Dict, Any


# ─────────────────────────────────────────────────────────────────────────────
# Argument parsing
# ─────────────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send JSON events from stdin to a Splunk HEC endpoint.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--hec-url",
        default="http://localhost:8088",
        help="Base URL of the Splunk HEC (default: http://localhost:8088)",
    )
    parser.add_argument(
        "--token",
        default="demo03-token",
        help="HEC authorization token (default: demo03-token)",
    )
    parser.add_argument(
        "--sourcetype",
        default="xmlwineventlog",
        help="Splunk sourcetype applied to all events (default: xmlwineventlog)",
    )
    parser.add_argument(
        "--index",
        default="windows",
        help="Splunk index to write into (default: windows)",
    )
    parser.add_argument(
        "--batch-size",
        type=int,
        default=50,
        metavar="N",
        help="Number of events per HTTP request (default: 50)",
    )
    return parser.parse_args()


# ─────────────────────────────────────────────────────────────────────────────
# HEC helpers
# ─────────────────────────────────────────────────────────────────────────────

def build_hec_url(base_url: str) -> str:
    """Normalise the base URL and append the HEC collector path."""
    base_url = base_url.rstrip("/")
    return base_url + "/services/collector/event"


def wrap_event(event: Any, sourcetype: str, index: str) -> Dict[str, Any]:
    """Wrap a parsed JSON event in the HEC envelope."""
    return {
        "event": event,
        "sourcetype": sourcetype,
        "index": index,
    }


def build_batch_payload(wrapped_events: List[Dict[str, Any]]) -> bytes:
    """
    Serialize a list of HEC-wrapped events into a newline-delimited JSON payload.
    Splunk HEC accepts multiple JSON objects concatenated without a separator array.
    """
    lines = [json.dumps(ev, separators=(",", ":")) for ev in wrapped_events]
    return "\n".join(lines).encode("utf-8")


def send_batch(
    url: str,
    token: str,
    payload: bytes,
) -> None:
    """
    POST a batch payload to the HEC endpoint.
    Raises urllib.error.HTTPError or urllib.error.URLError on failure.
    """
    req = urllib.request.Request(
        url,
        data=payload,
        method="POST",
        headers={
            "Authorization": "Splunk " + token,
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        # Read and discard the response body to allow connection reuse.
        resp.read()


# ─────────────────────────────────────────────────────────────────────────────
# Main loop
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    url = build_hec_url(args.hec_url)

    total_sent    = 0
    total_failed  = 0
    total_batches = 0
    batch_buffer: List[Dict[str, Any]] = []

    def flush_batch() -> None:
        """Send the current buffer as a single HEC request, then clear it."""
        nonlocal total_sent, total_failed, total_batches
        if not batch_buffer:
            return

        total_batches += 1
        batch_num = total_batches
        payload = build_batch_payload(batch_buffer)
        n = len(batch_buffer)

        try:
            send_batch(url, args.token, payload)
            total_sent += n
            print(
                f"[batch {batch_num:>4}] Sent {n} event(s)  "
                f"(cumulative: {total_sent} sent, {total_failed} failed)",
                file=sys.stderr,
            )
        except urllib.error.HTTPError as exc:
            total_failed += n
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            print(
                f"[batch {batch_num:>4}] HTTP {exc.code} error — {exc.reason}. "
                f"Response: {body[:200]}",
                file=sys.stderr,
            )
        except urllib.error.URLError as exc:
            total_failed += n
            print(
                f"[batch {batch_num:>4}] Connection error — {exc.reason}",
                file=sys.stderr,
            )
        except Exception as exc:  # noqa: BLE001
            total_failed += n
            print(
                f"[batch {batch_num:>4}] Unexpected error — {exc}",
                file=sys.stderr,
            )
        finally:
            batch_buffer.clear()

    # ── Read stdin line by line ──────────────────────────────────────────────
    line_num = 0
    for raw_line in sys.stdin:
        line_num += 1
        raw_line = raw_line.strip()
        if not raw_line:
            continue  # skip blank lines

        # Parse JSON
        try:
            event_data = json.loads(raw_line)
        except json.JSONDecodeError as exc:
            print(
                f"[line {line_num:>6}] JSON parse error — {exc}. Line skipped.",
                file=sys.stderr,
            )
            total_failed += 1
            continue

        wrapped = wrap_event(event_data, args.sourcetype, args.index)
        batch_buffer.append(wrapped)

        if len(batch_buffer) >= args.batch_size:
            flush_batch()

    # Flush any remaining events
    flush_batch()

    # ── Summary ─────────────────────────────────────────────────────────────
    print(
        f"\nSent {total_sent} events in {total_batches} batches ({total_failed} failures)",
        file=sys.stdout,
    )

    return 1 if total_failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
