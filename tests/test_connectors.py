"""Adversarial unit tests for the real worker-node connectors.

node-net SSRF guard and node-db read-only SQL guard are security-critical, so
they get direct hostile inputs here (no network / no live DB needed).
"""
import os, sys, pathlib, tempfile, sqlite3

PROJ = str(pathlib.Path(__file__).resolve().parents[1])
os.chdir(PROJ); sys.path.insert(0, PROJ)
os.environ.setdefault("KYBERNOS_BANNER", "off")

from fastapi import HTTPException

p = f = 0
def ok(name, cond, detail=""):
    global p, f
    p += bool(cond); f += (not cond)
    print(f"  {'PASS' if cond else 'FAIL'}  {name}{'' if cond else '  <- ' + detail}")

def blocks(fn, *a, want=403):
    try:
        fn(*a); return False, "no exception"
    except HTTPException as e:
        return (e.status_code == want), f"status {e.status_code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


# ---------------- node-net: SSRF guard ----------------
def test_ssrf():
    print("\n=== node-net SSRF guard ===")
    from src.worker_nodes import node_net as net

    # _is_public must reject every internal / metadata range
    for ip, pub in [("8.8.8.8", True), ("1.1.1.1", True),
                    ("169.254.169.254", False),  # cloud metadata
                    ("127.0.0.1", False), ("10.0.0.5", False), ("192.168.1.1", False),
                    ("172.16.0.1", False), ("::1", False), ("fd00::1", False),
                    ("0.0.0.0", False), ("224.0.0.1", False)]:
        ok(f"_is_public({ip}) == {pub}", net._is_public(ip) == pub)

    # stub DNS so we test the guard, not the internet
    def stub(mapping):
        net._resolve = lambda host, port: set(mapping.get(host, []))

    stub({"public.example.com": ["93.184.216.34"], "evil.example.com": ["169.254.169.254"],
          "rebind.example.com": ["93.184.216.34", "10.0.0.9"], "lo.example.com": ["127.0.0.1"]})

    ok("https public host allowed", net.validate_url("https://public.example.com/x") is not None)
    b, d = blocks(net.validate_url, "https://evil.example.com/latest/meta-data"); ok("metadata IP blocked", b, d)
    b, d = blocks(net.validate_url, "https://lo.example.com/"); ok("loopback blocked", b, d)
    b, d = blocks(net.validate_url, "https://rebind.example.com/"); ok("ANY private IP in the set blocks", b, d)
    b, d = blocks(net.validate_url, "http://public.example.com/"); ok("http scheme blocked (https-only)", b, d)
    b, d = blocks(net.validate_url, "file:///etc/passwd"); ok("file:// scheme blocked", b, d)
    b, d = blocks(net.validate_url, "gopher://public.example.com/"); ok("gopher:// blocked", b, d)
    b, d = blocks(net.validate_url, "https:///nohost"); ok("missing host blocked", b, d)

    # allowlist mode
    net.ALLOWLIST = {"public.example.com"}
    b, d = blocks(net.validate_url, "https://other.example.com/"); ok("host off allowlist blocked", b, d)
    ok("host on allowlist allowed", net.validate_url("https://public.example.com/") is not None)
    net.ALLOWLIST = set()


# ---------------- node-db: read-only SQL guard ----------------
def test_sql_guard():
    print("\n=== node-db read-only SQL guard ===")
    from src.worker_nodes import node_db as db

    for q in ["SELECT id FROM users", "select * from t",
              "WITH x AS (SELECT 1 AS a) SELECT a FROM x",
              "SELECT * FROM t WHERE note = 'please DELETE this later'",  # keyword in literal, still a SELECT
              "SELECT * FROM t;"]:
        try:
            db.guard_sql(q); ok(f"allow: {q[:40]}", True)
        except HTTPException as e:
            ok(f"allow: {q[:40]}", False, f"status {e.status_code}")

    for q in ["DROP TABLE users", "INSERT INTO t VALUES (1)", "UPDATE t SET a=1",
              "DELETE FROM t", "TRUNCATE t", "PRAGMA table_info(t)",
              "SELECT 1; DROP TABLE t",                          # stacked
              "WITH w AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM w",  # data-modifying CTE
              "", "   "]:
        b, d = blocks(db.guard_sql, q, want=403) if q.strip() else blocks(db.guard_sql, q, want=400)
        ok(f"block: {q[:40]!r}", b, d)


# ---------------- node-db: actual read-only enforcement against a real DB ----------------
def test_sqlite_readonly():
    print("\n=== node-db sqlite runs SELECT + blocks writes end-to-end ===")
    from src.worker_nodes import node_db as db
    path = os.path.join(tempfile.mkdtemp(prefix="kyb-dbtest-"), "t.db")
    c = sqlite3.connect(path)
    c.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT)")
    c.execute("INSERT INTO users (name) VALUES ('Ada'), ('Alan')")
    c.commit(); c.close()
    db.BACKEND = "sqlite"; db.SQLITE_PATH = path

    res = db.db_op(query="SELECT id, name FROM users ORDER BY id")
    ok("SELECT returns real rows", res["row_count"] == 2 and res["rows"][0]["name"] == "Ada", str(res)[:120])

    # even if a write slipped past the guard, PRAGMA query_only must reject it
    try:
        db._run_sqlite("INSERT INTO users (name) VALUES ('x')")
        ok("query_only blocks write at the DB layer", False, "insert succeeded")
    except Exception as e:
        ok("query_only blocks write at the DB layer", "readonly" in str(e).lower() or "read-only" in str(e).lower(), str(e)[:80])

    # row cap + truncation flag
    db.MAX_ROWS = 1
    res = db.db_op(query="SELECT id FROM users")
    ok("row cap enforced + truncated flag", res["row_count"] == 1 and res["truncated"] is True, str(res)[:120])
    db.MAX_ROWS = 1000


if __name__ == "__main__":
    test_ssrf(); test_sql_guard(); test_sqlite_readonly()
    print(f"\n  connectors: {p} passed, {f} failed")
    sys.exit(1 if f else 0)
