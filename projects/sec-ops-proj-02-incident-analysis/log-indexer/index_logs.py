#!/usr/bin/env python3
"""
Log Indexer for TransLog SA Incident Analysis Lab
Reads all log files from /data/logs/ and indexes them into Elasticsearch.
Detects file format (JSON array, NDJSON, CSV, plain text) and handles each accordingly.
"""

import os
import json
import csv
import re
import time
import logging
import sys
from pathlib import Path
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser
from elasticsearch import Elasticsearch, helpers
from elasticsearch.exceptions import ConnectionError as ESConnectionError

# ── Configuration ──────────────────────────────────────────────────────────────
ES_URL = os.getenv("ELASTICSEARCH_URL", "http://elasticsearch:9200")
LOGS_DIR = os.getenv("LOGS_DIR", "/data/logs")
BATCH_SIZE = 500
MAX_RETRIES = 15
RETRY_DELAY = 5  # seconds

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger(__name__)


# ── Index mappings ─────────────────────────────────────────────────────────────
INDEX_SETTINGS = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "dynamic": True,
        "properties": {
            "@timestamp": {"type": "date"},
            "source_file": {"type": "keyword"},
            "log_type": {"type": "keyword"},
        },
    },
}

# Map filename stems to index names and log types
FILE_INDEX_MAP = {
    "web_access": ("logs-web-access", "apache_json"),
    "windows_security.evtx": ("logs-windows-security", "windows_evtx_json"),
    "dns_queries": ("logs-dns", "dns_text"),
    "firewall": ("logs-firewall", "netflow_csv"),
    "db_audit": ("logs-db-audit", "mysql_general"),
    "email_gateway": ("logs-email-gateway", "email_gw_text"),
}


# ── Elasticsearch helpers ──────────────────────────────────────────────────────
def wait_for_elasticsearch(es: Elasticsearch) -> None:
    """Block until Elasticsearch is reachable and cluster is healthy."""
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            health = es.cluster.health(wait_for_status="yellow", timeout="10s")
            log.info("Elasticsearch is ready (status: %s)", health["status"])
            return
        except ESConnectionError as exc:
            log.warning(
                "Elasticsearch not ready (attempt %d/%d): %s", attempt, MAX_RETRIES, exc
            )
            time.sleep(RETRY_DELAY)
    log.error("Elasticsearch did not become ready after %d attempts. Exiting.", MAX_RETRIES)
    sys.exit(1)


def ensure_index(es: Elasticsearch, index_name: str) -> None:
    if not es.indices.exists(index=index_name):
        es.indices.create(
            index=index_name,
            settings=INDEX_SETTINGS["settings"],
            mappings=INDEX_SETTINGS["mappings"],
        )
        log.info("Created index: %s", index_name)
    else:
        log.info("Index already exists: %s", index_name)


def bulk_index(es: Elasticsearch, index_name: str, documents: list[dict]) -> tuple[int, int]:
    """Bulk-index documents; returns (success_count, error_count)."""
    if not documents:
        return 0, 0

    actions = (
        {
            "_index": index_name,
            "_source": doc,
        }
        for doc in documents
    )
    success, errors = helpers.bulk(es, actions, chunk_size=BATCH_SIZE, raise_on_error=False)
    return success, len(errors)


# ── Timestamp normalisation ────────────────────────────────────────────────────
def normalise_timestamp(raw: str | None) -> str | None:
    """Convert any parseable timestamp string to ISO-8601 UTC."""
    if not raw:
        return None
    try:
        dt = dateutil_parser.parse(str(raw))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.isoformat()
    except (ValueError, OverflowError):
        return raw  # keep original if unparseable


# ── Format detection ───────────────────────────────────────────────────────────
def detect_format(path: Path) -> str:
    """
    Returns one of: 'json_array', 'ndjson', 'csv', 'text'.
    Reads at most the first 4 KB to decide.
    """
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            sample = fh.read(4096).strip()
    except OSError:
        return "text"

    if not sample:
        return "text"

    # JSON array (e.g. windows_security.evtx.json)
    if sample.startswith("["):
        return "json_array"

    # NDJSON: first line is a JSON object
    first_line = sample.splitlines()[0].strip()
    if first_line.startswith("{"):
        return "ndjson"

    # CSV: check whether first line looks like comma-separated values
    lines = sample.splitlines()
    if lines:
        try:
            dialect = csv.Sniffer().sniff(lines[0], delimiters=",")
            if dialect and "," in lines[0]:
                return "csv"
        except csv.Error:
            pass

    return "text"


# ── Per-format parsers ─────────────────────────────────────────────────────────
def parse_json_array(path: Path, source_file: str, log_type: str) -> list[dict]:
    """Parse a file that contains a single top-level JSON array."""
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)

    if not isinstance(data, list):
        data = [data]

    docs = []
    for item in data:
        if not isinstance(item, dict):
            continue
        doc = dict(item)
        doc["source_file"] = source_file
        doc["log_type"] = log_type

        # Try common timestamp field names
        ts_raw = (
            doc.get("TimeCreated")
            or doc.get("timestamp")
            or doc.get("@timestamp")
        )
        doc["@timestamp"] = normalise_timestamp(ts_raw) or datetime.utcnow().isoformat()
        docs.append(doc)
    return docs


def parse_ndjson(path: Path, source_file: str, log_type: str) -> list[dict]:
    """Parse a newline-delimited JSON file (one JSON object per line)."""
    docs = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            line = line.strip()
            if not line:
                continue
            try:
                doc = json.loads(line)
            except json.JSONDecodeError as exc:
                log.warning("%s line %d: JSON decode error: %s", source_file, lineno, exc)
                continue
            if not isinstance(doc, dict):
                continue
            doc["source_file"] = source_file
            doc["log_type"] = log_type
            ts_raw = doc.get("timestamp") or doc.get("@timestamp")
            doc["@timestamp"] = normalise_timestamp(ts_raw) or datetime.utcnow().isoformat()
            docs.append(doc)
    return docs


def parse_csv(path: Path, source_file: str, log_type: str) -> list[dict]:
    """Parse a CSV file. First row is treated as header."""
    docs = []
    with path.open("r", encoding="utf-8", errors="replace", newline="") as fh:
        reader = csv.DictReader(fh)
        for lineno, row in enumerate(reader, 2):
            doc = dict(row)
            doc["source_file"] = source_file
            doc["log_type"] = log_type

            # Firewall CSV uses 'timestamp' column
            ts_raw = doc.get("timestamp")
            doc["@timestamp"] = normalise_timestamp(ts_raw) or datetime.utcnow().isoformat()

            # Cast numeric columns
            for field in ("bytes", "packets", "src_port", "dst_port"):
                if field in doc:
                    try:
                        doc[field] = int(doc[field])
                    except (ValueError, TypeError):
                        pass
            docs.append(doc)
    return docs


# ── Regex patterns for text log formats ───────────────────────────────────────
_DNS_RE = re.compile(
    r"(?P<timestamp>\S+)\s+client=(?P<client_ip>\S+)\s+query=(?P<query_name>\S+)"
    r"\s+type=(?P<query_type>\S+)\s+response=(?P<response>\S+)"
    r"\s+ttl=(?P<ttl>\d+)\s+status=(?P<status>\S+)"
)

_EMAIL_RE = re.compile(
    r"(?P<timestamp>\S+)\s+id=\S+\s+direction=(?P<direction>\S+)"
    r"\s+from=(?P<from>\S+)\s+to=(?P<to>\S+)\s+subject=\"(?P<subject>[^\"]+)\""
    r"\s+size=(?P<size>\d+)\s+attachments=(?P<attachments>\d+)"
    r"(?:\s+attachment_name=\"(?P<attachment_name>[^\"]+)\")?"
    r"\s+spam_score=(?P<spam_score>[\d.]+)\s+action=(?P<action>\S+)"
    r"\s+verdict=(?P<verdict>\S+)"
)

_DB_TIMESTAMP_RE = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+-]\d{2}:\d{2})")
_DB_SLOW_RE = re.compile(
    r"#\s*Query_time:\s*(?P<query_time>[\d.]+)\s+Lock_time:\s*(?P<lock_time>[\d.]+)"
    r"\s+Rows_sent:\s*(?P<rows_sent>\d+)\s+Rows_examined:\s*(?P<rows_examined>\d+)"
)


def parse_dns_log(path: Path, source_file: str, log_type: str) -> list[dict]:
    docs = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = _DNS_RE.match(line)
            if m:
                doc = m.groupdict()
                doc["ttl"] = int(doc["ttl"])
                doc["@timestamp"] = normalise_timestamp(doc.pop("timestamp"))
                doc["source_file"] = source_file
                doc["log_type"] = log_type
                doc["raw"] = line
            else:
                doc = {
                    "raw": line,
                    "source_file": source_file,
                    "log_type": log_type,
                    "@timestamp": datetime.utcnow().isoformat(),
                }
            docs.append(doc)
    return docs


def parse_email_log(path: Path, source_file: str, log_type: str) -> list[dict]:
    docs = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            m = _EMAIL_RE.match(line)
            if m:
                doc = m.groupdict()
                doc["size"] = int(doc["size"])
                doc["attachments"] = int(doc["attachments"])
                doc["spam_score"] = float(doc["spam_score"])
                doc["@timestamp"] = normalise_timestamp(doc.pop("timestamp"))
                doc["source_file"] = source_file
                doc["log_type"] = log_type
                doc["raw"] = line
            else:
                doc = {
                    "raw": line,
                    "source_file": source_file,
                    "log_type": log_type,
                    "@timestamp": datetime.utcnow().isoformat(),
                }
            docs.append(doc)
    return docs


def parse_db_audit_log(path: Path, source_file: str, log_type: str) -> list[dict]:
    """
    MySQL general/slow query log parser.
    Lines starting with a timestamp are query lines.
    Lines starting with '# Query_time:' are slow-query stats attached to the preceding doc.
    """
    docs = []
    current_doc: dict | None = None

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line_stripped = line.rstrip("\n")

            # Slow query stats line
            slow_m = _DB_SLOW_RE.match(line_stripped.strip())
            if slow_m and current_doc is not None:
                current_doc["query_time_s"] = float(slow_m.group("query_time"))
                current_doc["lock_time_s"] = float(slow_m.group("lock_time"))
                current_doc["rows_sent"] = int(slow_m.group("rows_sent"))
                current_doc["rows_examined"] = int(slow_m.group("rows_examined"))
                continue

            # Timestamp-bearing line → new log entry
            ts_m = _DB_TIMESTAMP_RE.match(line_stripped)
            if ts_m:
                # Save previous doc
                if current_doc is not None:
                    docs.append(current_doc)

                ts_str = ts_m.group(1)
                rest = line_stripped[len(ts_str):].strip()

                # Parse: <client_ip> <user>[<eff_user>] @ [<host>] <event_type> <detail>
                parts = rest.split(None, 3)
                current_doc = {
                    "@timestamp": normalise_timestamp(ts_str),
                    "source_file": source_file,
                    "log_type": log_type,
                    "raw": line_stripped,
                }
                if len(parts) >= 1:
                    current_doc["client_ip"] = parts[0]
                if len(parts) >= 4:
                    # e.g. "root[root] @ localhost Query SELECT ..."
                    combined = " ".join(parts[1:])
                    evt_m = re.match(
                        r"(?P<user>\S+)\s+@\s+(?P<host>\S+)\s+(?P<event_type>\w+)\s+(?P<detail>.*)",
                        combined,
                        re.DOTALL,
                    )
                    if evt_m:
                        current_doc["db_user"] = evt_m.group("user")
                        current_doc["db_host"] = evt_m.group("host")
                        current_doc["event_type"] = evt_m.group("event_type")
                        current_doc["query"] = evt_m.group("detail").strip()
                continue

            # Comment / continuation lines that don't match slow-query stats
            # (e.g. other '# ...' lines) — skip silently
            if line_stripped.startswith("#"):
                continue

            # Blank lines
            if not line_stripped.strip():
                continue

    # Flush last doc
    if current_doc is not None:
        docs.append(current_doc)

    return docs


def parse_text_generic(path: Path, source_file: str, log_type: str) -> list[dict]:
    """Fallback: store each non-empty line as a document with a raw field."""
    docs = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            # Try to extract a leading timestamp
            ts_m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}[^\s]*)", line)
            ts = normalise_timestamp(ts_m.group(1)) if ts_m else datetime.utcnow().isoformat()
            docs.append(
                {
                    "@timestamp": ts,
                    "raw": line,
                    "source_file": source_file,
                    "log_type": log_type,
                }
            )
    return docs


# ── Dispatcher ─────────────────────────────────────────────────────────────────
def parse_file(path: Path, log_type: str) -> list[dict]:
    source_file = path.name
    fmt = detect_format(path)
    log.info("  format detected: %s", fmt)

    # Special cases by log_type regardless of detected format
    if log_type == "dns_text":
        return parse_dns_log(path, source_file, log_type)
    if log_type == "email_gw_text":
        return parse_email_log(path, source_file, log_type)
    if log_type == "mysql_general":
        return parse_db_audit_log(path, source_file, log_type)

    # Generic dispatch
    if fmt == "json_array":
        return parse_json_array(path, source_file, log_type)
    if fmt == "ndjson":
        return parse_ndjson(path, source_file, log_type)
    if fmt == "csv":
        return parse_csv(path, source_file, log_type)
    return parse_text_generic(path, source_file, log_type)


# ── Main ───────────────────────────────────────────────────────────────────────
def main() -> None:
    log.info("Log Indexer starting — ES: %s  LOGS_DIR: %s", ES_URL, LOGS_DIR)

    es = Elasticsearch(ES_URL, request_timeout=30)
    wait_for_elasticsearch(es)

    logs_path = Path(LOGS_DIR)
    if not logs_path.is_dir():
        log.error("LOGS_DIR %s does not exist or is not a directory", LOGS_DIR)
        sys.exit(1)

    log_files = sorted(logs_path.iterdir())
    total_indexed = 0
    total_errors = 0

    for file_path in log_files:
        if not file_path.is_file():
            continue

        stem = file_path.stem  # e.g. "web_access", "windows_security.evtx"
        # Handle double-extension like windows_security.evtx.json
        if file_path.name in ("windows_security.evtx.json",):
            stem = "windows_security.evtx"

        if stem not in FILE_INDEX_MAP:
            log.warning("No index mapping for file '%s' (stem='%s') — skipping", file_path.name, stem)
            continue

        index_name, log_type = FILE_INDEX_MAP[stem]
        log.info("Processing %s → index '%s' (type: %s)", file_path.name, index_name, log_type)

        ensure_index(es, index_name)

        try:
            documents = parse_file(file_path, log_type)
        except Exception as exc:  # noqa: BLE001
            log.error("Failed to parse %s: %s", file_path.name, exc)
            continue

        log.info("  parsed %d documents", len(documents))

        if documents:
            ok, err = bulk_index(es, index_name, documents)
            log.info("  indexed %d  errors %d", ok, err)
            total_indexed += ok
            total_errors += err

    log.info(
        "Indexing complete. Total indexed: %d  Total errors: %d",
        total_indexed,
        total_errors,
    )


if __name__ == "__main__":
    main()
