# ./MetaTron/engine/db_adapter.py
# MetaTron Security Tool - SQLite Database Adapter
# Created by David Kistner (Unconditional Love) at GlyphicMind Solutions LLC.



#system imports
import sqlite3
from pathlib import Path
from datetime import datetime

#pathing
DB_PATH = Path(__file__).resolve().parents[1] / "data" / "metatron.db"
DB_PATH.parent.mkdir(exist_ok=True)



# ============================================
# Startup Section
# ============================================
# -------------------------
# Connect 
# -------------------------
def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    _init_schema(conn)
    return conn

# -------------------------
# Initialize Schema
# -------------------------
def _init_schema(conn):
    c = conn.cursor()

    # HISTORY TABLE
    c.execute("""
        CREATE TABLE IF NOT EXISTS history (
            sl_no      INTEGER PRIMARY KEY AUTOINCREMENT,
            target     TEXT,
            scan_date  TEXT,
            status     TEXT
        )
    """)

    # VULNERABILITIES TABLE
    c.execute("""
        CREATE TABLE IF NOT EXISTS vulnerabilities (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no       INTEGER,
            vuln_name   TEXT,
            severity    TEXT,
            port        TEXT,
            service     TEXT,
            description TEXT
        )
    """)

    # FIXES TABLE
    c.execute("""
        CREATE TABLE IF NOT EXISTS fixes (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no     INTEGER,
            vuln_id   INTEGER,
            fix_text  TEXT,
            source    TEXT
        )
    """)

    # EXPLOITS TABLE
    c.execute("""
        CREATE TABLE IF NOT EXISTS exploits_attempted (
            id           INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no        INTEGER,
            exploit_name TEXT,
            tool_used    TEXT,
            payload      TEXT,
            result       TEXT,
            notes        TEXT
        )
    """)

    # SUMMARY TABLE
    c.execute("""
        CREATE TABLE IF NOT EXISTS summary (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            sl_no       INTEGER,
            raw_scan    TEXT,
            ai_analysis TEXT,
            risk_level  TEXT,
            generated_at TEXT
        )
    """)

    conn.commit()

# -------------------------
# Create Session
# -------------------------
def _create_session(target: str) -> int:
    conn = _connect()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (?, ?, ?)",
        (target, now, "active")
    )

    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


# =================================================
# Save Helpers Section
# =================================================
# -------------------------
# Save Vulnerabilities
# -------------------------
def _save_vuln(conn, sl_no: int, vuln: dict) -> int:
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, port, service, description)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sl_no,
        vuln.get("vuln_name", ""),
        vuln.get("severity", ""),
        vuln.get("port", ""),
        vuln.get("service", ""),
        vuln.get("description", "")
    ))
    conn.commit()
    return c.lastrowid

# -------------------------
# Save Fix
# -------------------------
def _save_fix(conn, sl_no: int, vuln_id: int, fix_text: str):
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (?, ?, ?, ?)
    """, (sl_no, vuln_id, fix_text, "ai"))
    conn.commit()


# -------------------------
# Save Exploit
# -------------------------
def _save_exploit(conn, sl_no: int, exp: dict):
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted
        (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (
        sl_no,
        exp.get("exploit_name", ""),
        exp.get("tool_used", ""),
        exp.get("payload", ""),
        exp.get("result", ""),
        exp.get("notes", "")
    ))
    conn.commit()


# -------------------------
# Save Summary
# -------------------------
def _save_summary(conn, sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str):
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, generated_at)
        VALUES (?, ?, ?, ?, ?)
    """, (sl_no, raw_scan, ai_analysis, risk_level, now))
    conn.commit()


# -------------------------
# Save Session
# -------------------------
def save_session(result: dict) -> int:
    target = result.get("target") or "unknown"
    sl_no = _create_session(target)
    conn = _connect()

    for vuln in result.get("vulnerabilities", []):
        vuln_id = _save_vuln(conn, sl_no, vuln)
        fix_text = vuln.get("fix")
        if fix_text:
            _save_fix(conn, sl_no, vuln_id, fix_text)

    for exp in result.get("exploits", []):
        _save_exploit(conn, sl_no, exp)

    _save_summary(
        conn,
        sl_no,
        result.get("raw_scan", ""),
        result.get("full_response", ""),
        result.get("risk_level", "UNKNOWN")
    )

    conn.close()
    return sl_no


# ==============================================
# Loading Section
# ==============================================
# -------------------------
# Load Session List
# -------------------------
def list_sessions():
    conn = _connect()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows

# -------------------------
# Load Session
# -------------------------
def load_session(sl_no: int) -> dict:
    conn = _connect()
    c = conn.cursor()

    # history
    c.execute("SELECT * FROM history WHERE sl_no = ?", (sl_no,))
    history = c.fetchone()

    # summary
    c.execute("SELECT * FROM summary WHERE sl_no = ?", (sl_no,))
    summary = c.fetchone()

    # vulnerabilities
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = ?", (sl_no,))
    vulns = c.fetchall()

    # fixes
    c.execute("SELECT * FROM fixes WHERE sl_no = ?", (sl_no,))
    fixes = c.fetchall()

    # exploits
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = ?", (sl_no,))
    exploits = c.fetchall()

    conn.close()

    return {
        "history": history,
        "summary": summary,
        "vulnerabilities": vulns,
        "fixes": fixes,
        "exploits": exploits
    }

