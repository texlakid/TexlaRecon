
import argparse
import sqlite3
import datetime
import sys
from pathlib import Path

DB_FILE = "texla_vulns.db"

def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            engagement INTEGER,
            host TEXT,
            phase TEXT,
            title TEXT,
            severity TEXT,
            evidence TEXT,
            remediation TEXT
        )
    ''')
    conn.commit()
    return conn

def add_finding(args):
    conn = init_db()
    c = conn.cursor()
    ts = datetime.datetime.now().isoformat()
    c.execute('''
        INSERT INTO findings (timestamp, engagement, host, phase, title, severity, evidence, remediation)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (ts, args.engagement, args.host, args.phase, args.title, args.severity, args.evidence, args.remediation))
    conn.commit()
    conn.close()

def main():
    parser = argparse.ArgumentParser(description="TexlaRecon Vuln Logger")
    subparsers = parser.add_subparsers(dest="command", required=True)

    add_parser = subparsers.add_parser("add", help="Add a finding")
    add_parser.add_argument("--engagement", type=int, required=True)
    add_parser.add_argument("--host", required=True)
    add_parser.add_argument("--phase", required=True)
    add_parser.add_argument("--title", required=True)
    add_parser.add_argument("--severity", required=True)
    add_parser.add_argument("--evidence", required=True)
    add_parser.add_argument("--remediation", required=True)

    args = parser.parse_args()

    if args.command == "add":
        add_finding(args)
        print(f"[+] Logged {args.severity}: {args.title} on {args.host}")

if __name__ == "__main__":
    main()
