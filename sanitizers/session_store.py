"""
Session-state stores for the trust engine (paper §3.5).

The persistent trust state of a session is two grow-only sets:

  * ``D`` — registration identifiers (the content digest where deduplication
    applies, a fresh event identifier otherwise). The history term is
    ``H = rho ** |D|``.
  * ``T`` — tiers of the transitions that lowered the persistent tier. The
    persistent tier ``Tier_P`` is ``min(T)`` (HIGH when ``T`` is empty).

Both merge by set union, so replicas converge whatever order they learn of
registrations in (a grow-only set, as in conflict-free replicated data types).
A multi-worker deployment therefore only needs a store with atomic set insertion.

Backends:
  * ``InProcessStore`` — process memory with an LRU cap on tracked sessions. This
    is what the released runtime uses on one worker; behind a round-robin balancer
    each worker has its own copy, which is the failure §5.10 measures.
  * ``SQLiteStore`` — a file shared by processes on one host (used by the tests
    and as a dependency-free shared store).
  * ``RedisStore`` — an in-memory key-value store shared across hosts.

Every backend raises :class:`StoreUnavailable` on I/O failure; the trust engine
then fails closed and treats the session as MEDIUM.
"""

from __future__ import annotations

import sqlite3
import threading
from collections import OrderedDict
from typing import Optional, Set, Tuple

TIER_ORDER = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
TIER_NAME = {v: k for k, v in TIER_ORDER.items()}


class StoreUnavailable(RuntimeError):
    """The shared store could not be reached."""


class SessionStore:
    """Interface: two grow-only sets per session."""

    def add_registration(self, session_id: str, reg_id: str) -> bool:
        """Insert ``reg_id`` into ``D``. Returns True if it was new."""
        raise NotImplementedError

    def add_demotion(self, session_id: str, tier: str) -> None:
        """Insert ``tier`` into ``T``."""
        raise NotImplementedError

    def read(self, session_id: str) -> Tuple[int, str]:
        """Return ``(|D|, Tier_P)``."""
        raise NotImplementedError

    def registrations(self, session_id: str) -> Set[str]:
        raise NotImplementedError

    def reset_session(self, session_id: str) -> None:
        raise NotImplementedError

    def reset_all(self) -> None:
        raise NotImplementedError

    @staticmethod
    def _min_tier(tiers) -> str:
        values = [TIER_ORDER[t] for t in tiers if t in TIER_ORDER]
        return TIER_NAME[min(values)] if values else "HIGH"


class InProcessStore(SessionStore):
    """Process-local state with LRU eviction; eviction resets a session."""

    def __init__(self, max_sessions: int = 1000):
        self._lock = threading.RLock()
        self._d: "OrderedDict[str, Set[str]]" = OrderedDict()
        self._t: "OrderedDict[str, Set[str]]" = OrderedDict()
        self._max = max_sessions

    def _touch(self, session_id: str) -> None:
        for table in (self._d, self._t):
            if session_id not in table:
                table[session_id] = set()
            table.move_to_end(session_id)
        while len(self._d) > self._max:
            old, _ = self._d.popitem(last=False)
            self._t.pop(old, None)

    def add_registration(self, session_id: str, reg_id: str) -> bool:
        with self._lock:
            self._touch(session_id)
            if reg_id in self._d[session_id]:
                return False
            self._d[session_id].add(reg_id)
            return True

    def add_demotion(self, session_id: str, tier: str) -> None:
        with self._lock:
            self._touch(session_id)
            self._t[session_id].add(tier)

    def read(self, session_id: str) -> Tuple[int, str]:
        with self._lock:
            self._touch(session_id)
            return len(self._d[session_id]), self._min_tier(self._t[session_id])

    def registrations(self, session_id: str) -> Set[str]:
        with self._lock:
            self._touch(session_id)
            return set(self._d[session_id])

    def reset_session(self, session_id: str) -> None:
        with self._lock:
            self._d.pop(session_id, None)
            self._t.pop(session_id, None)

    def reset_all(self) -> None:
        with self._lock:
            self._d.clear()
            self._t.clear()


class SQLiteStore(SessionStore):
    """Shared store in one SQLite file (atomic ``INSERT OR IGNORE``)."""

    def __init__(self, path: str):
        self.path = path
        self._lock = threading.RLock()
        try:
            with self._conn() as c:
                c.execute("CREATE TABLE IF NOT EXISTS reg (session TEXT, id TEXT, PRIMARY KEY (session, id))")
                c.execute("CREATE TABLE IF NOT EXISTS dem (session TEXT, tier TEXT, PRIMARY KEY (session, tier))")
        except sqlite3.Error as exc:
            raise StoreUnavailable(str(exc)) from exc

    def _conn(self):
        return sqlite3.connect(self.path, timeout=5, isolation_level=None)

    def _run(self, fn):
        try:
            with self._lock, self._conn() as c:
                return fn(c)
        except sqlite3.Error as exc:
            raise StoreUnavailable(str(exc)) from exc

    def add_registration(self, session_id: str, reg_id: str) -> bool:
        return self._run(lambda c: c.execute(
            "INSERT OR IGNORE INTO reg VALUES (?, ?)", (session_id, reg_id)).rowcount == 1)

    def add_demotion(self, session_id: str, tier: str) -> None:
        self._run(lambda c: c.execute("INSERT OR IGNORE INTO dem VALUES (?, ?)", (session_id, tier)))

    def read(self, session_id: str) -> Tuple[int, str]:
        def q(c):
            n = c.execute("SELECT COUNT(*) FROM reg WHERE session = ?", (session_id,)).fetchone()[0]
            tiers = [r[0] for r in c.execute("SELECT tier FROM dem WHERE session = ?", (session_id,))]
            return n, self._min_tier(tiers)
        return self._run(q)

    def registrations(self, session_id: str) -> Set[str]:
        return self._run(lambda c: {r[0] for r in c.execute(
            "SELECT id FROM reg WHERE session = ?", (session_id,))})

    def reset_session(self, session_id: str) -> None:
        def q(c):
            c.execute("DELETE FROM reg WHERE session = ?", (session_id,))
            c.execute("DELETE FROM dem WHERE session = ?", (session_id,))
        self._run(q)

    def reset_all(self) -> None:
        def q(c):
            c.execute("DELETE FROM reg")
            c.execute("DELETE FROM dem")
        self._run(q)


class RedisStore(SessionStore):
    """Shared store in Redis: ``SADD`` on two keys per session."""

    def __init__(self, url: Optional[str] = None, client=None, prefix: str = "sar"):
        if client is None:
            import redis
            client = redis.Redis.from_url(url or "redis://localhost:6379/0", socket_timeout=2)
        self.r = client
        self.prefix = prefix

    def _k(self, session_id: str, kind: str) -> str:
        return f"{self.prefix}:{session_id}:{kind}"

    def _run(self, fn):
        try:
            return fn()
        except Exception as exc:  # redis.exceptions.* and socket errors
            raise StoreUnavailable(str(exc)) from exc

    def add_registration(self, session_id: str, reg_id: str) -> bool:
        return self._run(lambda: self.r.sadd(self._k(session_id, "D"), reg_id) == 1)

    def add_demotion(self, session_id: str, tier: str) -> None:
        self._run(lambda: self.r.sadd(self._k(session_id, "T"), tier))

    def read(self, session_id: str) -> Tuple[int, str]:
        def q():
            n = self.r.scard(self._k(session_id, "D"))
            tiers = [t.decode() if isinstance(t, bytes) else t
                     for t in self.r.smembers(self._k(session_id, "T"))]
            return int(n), self._min_tier(tiers)
        return self._run(q)

    def registrations(self, session_id: str) -> Set[str]:
        return self._run(lambda: {x.decode() if isinstance(x, bytes) else x
                                  for x in self.r.smembers(self._k(session_id, "D"))})

    def reset_session(self, session_id: str) -> None:
        self._run(lambda: self.r.delete(self._k(session_id, "D"), self._k(session_id, "T")))

    def reset_all(self) -> None:
        def q():
            for key in self.r.scan_iter(f"{self.prefix}:*"):
                self.r.delete(key)
        self._run(q)


def build_store(spec: str, max_sessions: int = 1000) -> SessionStore:
    """``memory`` | ``sqlite:///path`` | ``redis://host:port/db``."""
    spec = (spec or "memory").strip()
    if spec == "memory":
        return InProcessStore(max_sessions)
    if spec.startswith("sqlite:///"):
        return SQLiteStore(spec[len("sqlite:///"):])
    if spec.startswith("redis://") or spec.startswith("rediss://"):
        return RedisStore(spec)
    raise ValueError(f"Unknown session store {spec!r}")
