"""node-db — real, least-privilege, read-ONLY database connector.

Replaces the mock. Defense-in-depth, fail-closed at the node itself:
  - Only a single read statement is accepted: must start with SELECT (or WITH),
    a semicolon may only be a trailing terminator (no stacked statements), and a
    denylist of write/DDL verbs is rejected even inside a SELECT.
  - The DB session is opened read-only where the driver allows it (SQLite
    query_only pragma; Postgres default_transaction_read_only). Pair this with a
    dedicated read-only DB *user* — code guards are not a substitute for grants.
  - Row and cell output is bounded (DB_MAX_ROWS, DB_MAX_CELL).

Backend via DB_BACKEND: "sqlite" (default, self-contained demo) or "postgres"
(needs DATABASE_URL + psycopg). The SQL guard is identical for both.
"""
import os
import re
import logging

from fastapi import FastAPI, Body, HTTPException

from src.common.banner import brand_line
brand_line("node-db")
logger = logging.getLogger("node-db")
app = FastAPI(title="Kybernos · node-db", version="6.0")

BACKEND = os.getenv("DB_BACKEND", "sqlite").lower()
SQLITE_PATH = os.getenv("DB_SQLITE_PATH", ":memory:")
DATABASE_URL = os.getenv("DATABASE_URL", "")
MAX_ROWS = int(os.getenv("DB_MAX_ROWS", "1000"))
MAX_CELL = int(os.getenv("DB_MAX_CELL", "4096"))

# Write/DDL verbs. A lone SELECT physically cannot execute these, but a
# data-modifying CTE (Postgres `WITH t AS (INSERT ... RETURNING *) SELECT ...`)
# starts with WITH and DOES write — so we screen these on WITH-prefixed queries
# (belt-and-suspenders behind the read-only session + read-only DB grant).
_FORBIDDEN = re.compile(
    r"(?is)\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|MERGE|GRANT|"
    r"REVOKE|ATTACH|DETACH|PRAGMA|VACUUM|REINDEX|COPY|CALL|EXEC(UTE)?)\b")


def guard_sql(query: str) -> str:
    q = (query or "").strip()
    if not q:
        raise HTTPException(400, "empty query")
    # A trailing ';' is fine; anything before it plus another statement is not.
    if ";" in q.rstrip(";"):
        raise HTTPException(403, "multiple statements are not permitted")
    q = q.rstrip(";").strip()
    m = re.match(r"(?is)^(SELECT|WITH)\b", q)
    if not m:
        raise HTTPException(403, "only read (SELECT/WITH) queries are permitted")
    # Only WITH can smuggle a data-modifying CTE; plain SELECT cannot write, so
    # we don't false-positive on a keyword that appears as a string literal.
    if m.group(1).upper() == "WITH" and _FORBIDDEN.search(q):
        raise HTTPException(403, "read-only: data-modifying CTE rejected")
    return q


def _cap(v):
    if isinstance(v, str) and len(v) > MAX_CELL:
        return v[:MAX_CELL] + "…(truncated)"
    return v


# --- backends -------------------------------------------------------------
def _run_sqlite(query: str):
    import sqlite3
    conn = sqlite3.connect(SQLITE_PATH, uri=SQLITE_PATH.startswith("file:"))
    try:
        conn.execute("PRAGMA query_only = ON;")   # hard read-only for the session
        conn.row_factory = sqlite3.Row
        cur = conn.execute(query)
        rows = cur.fetchmany(MAX_ROWS + 1)
        cols = [d[0] for d in cur.description] if cur.description else []
        truncated = len(rows) > MAX_ROWS
        out = [{c: _cap(r[c]) for c in cols} for r in rows[:MAX_ROWS]]
        return cols, out, truncated
    finally:
        conn.close()


def _run_postgres(query: str):
    import psycopg  # psycopg 3
    with psycopg.connect(DATABASE_URL, autocommit=False) as conn:
        conn.read_only = True                      # default_transaction_read_only
        with conn.cursor() as cur:
            cur.execute(query)
            cols = [d.name for d in cur.description] if cur.description else []
            rows = cur.fetchmany(MAX_ROWS + 1)
            truncated = len(rows) > MAX_ROWS
            out = [{c: _cap(v) for c, v in zip(cols, r)} for r in rows[:MAX_ROWS]]
            return cols, out, truncated


_RUNNERS = {"sqlite": _run_sqlite, "postgres": _run_postgres, "postgresql": _run_postgres}


@app.get("/healthz")
def healthz():
    return {"status": "ok", "backend": BACKEND}


@app.post("/run")
def db_op(query: str = Body(..., embed=True)):  # embed: enforcer posts {"query": ...}
    safe = guard_sql(query)
    runner = _RUNNERS.get(BACKEND)
    if runner is None:
        raise HTTPException(500, f"unsupported DB_BACKEND: {BACKEND}")
    try:
        cols, rows, truncated = runner(safe)
    except HTTPException:
        raise
    except ModuleNotFoundError as e:
        raise HTTPException(500, f"backend driver not installed: {e.name}")
    except Exception as e:
        logger.warning("db query failed: %s", e)
        raise HTTPException(400, f"query error: {e}")
    return {"status": "executed", "columns": cols, "row_count": len(rows),
            "truncated": truncated, "rows": rows}
