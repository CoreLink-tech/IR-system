#!/usr/bin/env python3
"""Apply drizzle/*/migration.sql to local SQLite (no npm required)."""
import hashlib
import re
import sqlite3
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB = ROOT / "data" / "ir.db"
DRIZZLE = ROOT / "drizzle"

def main() -> None:
    DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB))
    cur = conn.cursor()
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS __drizzle_migrations (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          hash TEXT NOT NULL,
          created_at INTEGER
        )
        """
    )
    done = {r[0] for r in cur.execute("SELECT hash FROM __drizzle_migrations")}
    dirs = sorted(
        d.name
        for d in DRIZZLE.iterdir()
        if d.is_dir() and re.match(r"^\d{4}_", d.name)
    )
    for name in dirs:
        sql_path = DRIZZLE / name / "migration.sql"
        if not sql_path.exists():
            print("skip missing", name)
            continue
        sql = sql_path.read_text()
        h = hashlib.sha256((name + "\n" + sql).encode()).hexdigest()
        if h in done:
            print("already", name)
            continue
        print("applying", name)
        for stmt in sql.split(";"):
            s = stmt.strip()
            if not s:
                continue
            try:
                cur.execute(s)
            except sqlite3.Error as e:
                msg = str(e).lower()
                if "duplicate" in msg or "already exists" in msg:
                    continue
                print("  warn:", e)
        cur.execute(
            "INSERT INTO __drizzle_migrations (hash, created_at) VALUES (?, ?)",
            (h, int(time.time() * 1000)),
        )
        conn.commit()
        print("applied", name)
    tables = [
        r[0]
        for r in cur.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
    ]
    print("tables:", ", ".join(tables))
    print("done", DB)
    conn.close()


if __name__ == "__main__":
    main()
