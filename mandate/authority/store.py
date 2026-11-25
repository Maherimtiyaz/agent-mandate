"""SQLite storage for the Mandate authority, including the hash-chained audit log."""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

from ..crypto import canonical, sha256_hex

SCHEMA = """
CREATE TABLE IF NOT EXISTS kv (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS agents (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, public_key TEXT NOT NULL,
  owner TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mandates (
  jti TEXT PRIMARY KEY, agent_id TEXT NOT NULL, payload TEXT NOT NULL,
  token TEXT NOT NULL, status TEXT NOT NULL, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS mandate_requests (
  id TEXT PRIMARY KEY, agent_id TEXT NOT NULL, request TEXT NOT NULL,
  status TEXT NOT NULL, jti TEXT, created REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger (
  id TEXT PRIMARY KEY, jti TEXT NOT NULL, amount REAL NOT NULL,
  merchant TEXT NOT NULL, idem_key TEXT, intent TEXT NOT NULL,
  receipt TEXT NOT NULL, created REAL NOT NULL,
  UNIQUE (jti, idem_key)
);
CREATE TABLE IF NOT EXISTS approvals (
  id TEXT PRIMARY KEY, jti TEXT NOT NULL, intent_hash TEXT NOT NULL,
  intent TEXT NOT NULL, status TEXT NOT NULL, used INTEGER NOT NULL DEFAULT 0,
  created REAL NOT NULL, decided REAL
);
CREATE TABLE IF NOT EXISTS nonces (nonce TEXT PRIMARY KEY, jti TEXT NOT NULL, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, event TEXT NOT NULL,
  data TEXT NOT NULL, prev_hash TEXT NOT NULL, hash TEXT NOT NULL
);
"""

GENESIS = "0" * 64


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.RLock()
        with self.lock:
            if path != ":memory:":
                # WAL: writers don't block readers and commits don't wait for a full sync. Committed data
                # survives an app crash; a power cut can lose the last few commits (standard production trade-off).
                self.db.execute("PRAGMA journal_mode=WAL")
                self.db.execute("PRAGMA synchronous=NORMAL")
            self.db.executescript(SCHEMA)

    # -- generic helpers -------------------------------------------------
    def q(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self.lock:
            return list(self.db.execute(sql, args))

    def one(self, sql: str, args: tuple = ()) -> sqlite3.Row | None:
        rows = self.q(sql, args)
        return rows[0] if rows else None

    def x(self, sql: str, args: tuple = ()) -> None:
        with self.lock:
            self.db.execute(sql, args)

    def kv_get(self, k: str) -> str | None:
        r = self.one("SELECT v FROM kv WHERE k=?", (k,))
        return r["v"] if r else None

    def kv_set(self, k: str, v: str) -> None:
        self.x("INSERT OR REPLACE INTO kv (k, v) VALUES (?, ?)", (k, v))

    # -- replay protection ----------------------------------------------
    def use_nonce(self, nonce: str, jti: str, keep_s: float = 600) -> bool:
        """Returns False if the nonce was already used (a replayed request).

        Nonces older than keep_s are purged: proofs that old are already rejected as stale.
        """
        with self.lock:
            self._nonce_writes = getattr(self, "_nonce_writes", 0) + 1
            if self._nonce_writes % 500 == 0:
                self.db.execute("DELETE FROM nonces WHERE ts < ?", (time.time() - keep_s,))
            try:
                self.db.execute(
                    "INSERT INTO nonces (nonce, jti, ts) VALUES (?, ?, ?)",
                    (nonce, jti, time.time()),
                )
                return True
            except sqlite3.IntegrityError:
                return False

    # -- audit log -------------------------------------------------------
    def audit(self, event: str, data: dict[str, Any]) -> dict:
        with self.lock:
            last = self.db.execute("SELECT hash FROM audit ORDER BY seq DESC LIMIT 1").fetchone()
            prev = last["hash"] if last else GENESIS
            ts = round(time.time(), 6)
            body = canonical({"ts": ts, "event": event, "data": data, "prev": prev})
            h = sha256_hex(body)
            cur = self.db.execute(
                "INSERT INTO audit (ts, event, data, prev_hash, hash) VALUES (?, ?, ?, ?, ?)",
                (ts, event, json.dumps(data, sort_keys=True), prev, h),
            )
            return {"seq": cur.lastrowid, "ts": ts, "event": event, "data": data, "hash": h}

    def verify_audit(self) -> dict:
        prev = GENESIS
        n = 0
        for r in self.q("SELECT * FROM audit ORDER BY seq"):
            data = json.loads(r["data"])
            body = canonical({"ts": r["ts"], "event": r["event"], "data": data, "prev": prev})
            if r["prev_hash"] != prev or sha256_hex(body) != r["hash"]:
                return {"ok": False, "broken_at": r["seq"], "checked": n}
            prev = r["hash"]
            n += 1
        return {"ok": True, "checked": n, "head": prev}
