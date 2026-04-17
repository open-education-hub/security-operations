"""
soar/database.py — SQLite schema and helper functions

All database interaction goes through the helpers defined here.
Students should NOT modify init_db() — the schema is fixed.
"""

import os
import sqlite3
import json

# ---------------------------------------------------------------------------
# Database path — override with the DB_PATH environment variable in Docker.
# ---------------------------------------------------------------------------
DB_PATH = os.environ.get("DB_PATH", "/data/incidents.db")


# ---------------------------------------------------------------------------
# Schema initialisation
# ---------------------------------------------------------------------------

def init_db():
    """
    Create all tables if they do not already exist.

    Called automatically by soar/app.py on startup — idempotent (safe to call
    multiple times).  Do NOT drop or recreate tables here.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ------------------------------------------------------------------
    # alerts — raw SIEM events, linked to an incident after triage
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id               INTEGER PRIMARY KEY AUTOINCREMENT,
            alert_id         TEXT    NOT NULL UNIQUE,
            timestamp        TEXT    NOT NULL,
            rule_name        TEXT    NOT NULL,
            severity         TEXT    NOT NULL,
            source_ip        TEXT,
            destination_ip   TEXT,
            destination_port INTEGER,
            raw_log          TEXT,
            incident_id      TEXT,
            created_at       TEXT    NOT NULL DEFAULT (datetime('now'))
        )
    """)

    # ------------------------------------------------------------------
    # incidents — one incident may group multiple related alerts
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incidents (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id         TEXT    NOT NULL UNIQUE,
            status              TEXT    NOT NULL DEFAULT 'open'
                                    CHECK(status IN ('open','investigating','contained','closed')),
            severity            TEXT    NOT NULL,
            source_ip           TEXT,
            title               TEXT,
            created_at          TEXT    NOT NULL DEFAULT (datetime('now')),
            detection_time      TEXT,
            contained_time      TEXT,
            closed_time         TEXT,
            mttd_hours          REAL,
            mttr_hours          REAL,
            veris_classification TEXT
        )
    """)

    # ------------------------------------------------------------------
    # incident_notes — analyst comments added during investigation
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS incident_notes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            timestamp   TEXT NOT NULL DEFAULT (datetime('now')),
            analyst     TEXT,
            note        TEXT NOT NULL
        )
    """)

    # ------------------------------------------------------------------
    # notifications — P1/P2 alert notifications written by the playbook
    # ------------------------------------------------------------------
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS notifications (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            incident_id TEXT NOT NULL,
            level       TEXT NOT NULL,
            message     TEXT NOT NULL,
            timestamp   TEXT NOT NULL DEFAULT (datetime('now'))
        )
    """)

    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Connection helper
# ---------------------------------------------------------------------------

def get_db():
    """
    Open and return a sqlite3 connection to DB_PATH.

    The caller is responsible for closing the connection (or use as a context
    manager).

    Example::

        conn = get_db()
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
        finally:
            conn.close()
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row  # rows accessible as dicts
    return conn


# ---------------------------------------------------------------------------
# Query helpers
# ---------------------------------------------------------------------------

def execute_query(sql: str, params: tuple = ()):
    """
    Execute a write query (INSERT / UPDATE / DELETE) and commit.

    Returns the ``lastrowid`` of the executed statement.

    Args:
        sql:    SQL statement string (use ? placeholders).
        params: Tuple of bind parameters.

    Returns:
        int: lastrowid after the statement.
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


def fetch_one(sql: str, params: tuple = ()):
    """
    Execute a SELECT and return the first matching row as a dict, or None.

    Args:
        sql:    SQL SELECT statement (use ? placeholders).
        params: Tuple of bind parameters.

    Returns:
        dict | None
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def fetch_all(sql: str, params: tuple = ()):
    """
    Execute a SELECT and return all matching rows as a list of dicts.

    Args:
        sql:    SQL SELECT statement (use ? placeholders).
        params: Tuple of bind parameters.

    Returns:
        list[dict]
    """
    conn = get_db()
    try:
        cursor = conn.cursor()
        cursor.execute(sql, params)
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()
