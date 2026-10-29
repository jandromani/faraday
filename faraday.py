"""FARADAY Gate — Build 001: proof of concept, not a production security boundary.

Stdlib only. The issuer and verifier are separate objects, not isolated services.
Real authentication and enforced tool routing are prerequisites for deployment.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from pathlib import Path
from typing import Any, Callable

AUDIENCE = "faraday-tool-executor"
HEADER = {"alg": "HS256", "typ": "FARADAY-CAP", "v": 1}
REQUIRED_CLAIMS = {"aud", "sub", "tool", "args", "iat", "exp", "jti"}
MAX_TTL_SECONDS = 300
MAX_TOKEN_BYTES = 4096


class Denied(Exception):
    """Fail-closed authorization denial."""


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False,
                      sort_keys=True, separators=(",", ":")).encode("utf-8")


def _b64_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64_decode(value: str) -> bytes:
    if not value or any(c not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for c in value):
        raise Denied("malformed token encoding")
    try:
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, base64.binascii.Error) as exc:
        raise Denied("malformed token encoding") from exc


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    obj: dict[str, Any] = {}
    for key, value in pairs:
        if key in obj:
            raise Denied("duplicate JSON key")
        obj[key] = value
    return obj


def _parse_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicate_keys,
                          parse_constant=lambda _: (_ for _ in ()).throw(Denied("nonfinite number")))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise Denied("malformed token JSON") from exc


def _invoice_policy(agent: Any, tool: Any, args: Any) -> None:
    """Explicit allowlist: no wildcard tools, agents, recipients or amounts."""
    if agent != "agent_finance" or tool != "pay_invoice":
        raise Denied("agent/tool not allowed")
    if not isinstance(args, dict) or set(args) != {"amount_cents", "currency", "recipient"}:
        raise Denied("invalid invoice argument schema")
    amount = args["amount_cents"]
    if type(amount) is not int or not 1 <= amount <= 20_000:
        raise Denied("amount is not allowed")
    if args["currency"] != "EUR" or args["recipient"] != "supplier_001":
        raise Denied("currency/recipient is not allowed")


class Issuer:
    """Issue narrowly scoped signed capabilities; protect secret outside agents."""

    def __init__(self, secret: bytes, clock: Callable[[], float] = time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("HMAC secret must be at least 32 random bytes")
        self._secret = secret
        self._clock = clock

    def issue(self, agent: str, tool: str, args: dict[str, Any], ttl: int = 60) -> str:
        if type(ttl) is not int or not 1 <= ttl <= MAX_TTL_SECONDS:
            raise Denied("TTL must be an integer from 1 through 300 seconds")
        _invoice_policy(agent, tool, args)
        now = int(self._clock())
        claims = {
            "aud": AUDIENCE,
            "sub": agent,
            "tool": tool,
            "args": args,
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_urlsafe(24),
        }
        signing_input = f"{_b64_encode(_json_bytes(HEADER))}.{_b64_encode(_json_bytes(claims))}"
        mac = hmac.new(self._secret, signing_input.encode("ascii"), hashlib.sha256).digest()
        return f"{signing_input}.{_b64_encode(mac)}"


class SQLiteReplayStore:
    """Persist atomic token consumption before any downstream side effect."""

    def __init__(self, db_path: str | Path):
        self.path = str(db_path)
        with closing(self._connect()) as con:
            con.execute("CREATE TABLE IF NOT EXISTS spent_tokens ("
                        "jti TEXT PRIMARY KEY, exp INTEGER NOT NULL, used_at INTEGER NOT NULL)")

    def _connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.execute("PRAGMA busy_timeout=10000")
        return con

    def spend(self, jti: str, exp: int, now: int) -> None:
        try:
            with closing(self._connect()) as con:
                con.execute("BEGIN IMMEDIATE")
                con.execute("INSERT INTO spent_tokens (jti, exp, used_at) VALUES (?, ?, ?)",
                            (jti, exp, now))
                con.execute("COMMIT")
        except sqlite3.IntegrityError as exc:
            raise Denied("capability already spent (replay)") from exc
        except sqlite3.Error as exc:
            raise Denied("replay store unavailable; fail closed") from exc


class Gate:
    """Validate and consume capability; does NOT invoke external tools."""

    def __init__(self, secret: bytes, replay_store: SQLiteReplayStore,
                 clock: Callable[[], float] = time.time):
        if not isinstance(secret, bytes) or len(secret) < 32:
            raise ValueError("HMAC secret must be at least 32 random bytes")
        self._secret = secret
        self._replay_store = replay_store
        self._clock = clock

    def authorize(self, token: str, *, authenticated_agent: str,
                  tool: str, args: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
            raise Denied("malformed/oversized token")
        parts = token.split(".")
        if len(parts) != 3:
            raise Denied("malformed token")
        encoded_header, encoded_claims, encoded_mac = parts
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii", errors="strict")
        actual_mac = _b64_decode(encoded_mac)
        expected_mac = hmac.new(self._secret, signing_input, hashlib.sha256).digest()
        if not hmac.compare_digest(actual_mac, expected_mac):
            raise Denied("invalid signature")
        header = _parse_json(_b64_decode(encoded_header))
        claims = _parse_json(_b64_decode(encoded_claims))
        if header != HEADER or not isinstance(claims, dict) or set(claims) != REQUIRED_CLAIMS:
            raise Denied("unsupported capability claims")
        now = int(self._clock())
        issued, expires = claims["iat"], claims["exp"]
        if (type(issued) is not int or type(expires) is not int
                or issued > now or expires <= now or expires <= issued
                or expires - issued > MAX_TTL_SECONDS):
            raise Denied("expired or invalid capability lifetime")
        if claims["aud"] != AUDIENCE:
            raise Denied("wrong audience")
        if (claims["sub"] != authenticated_agent or claims["tool"] != tool
                or _json_bytes(claims["args"]) != _json_bytes(args)):
            raise Denied("caller, tool, or arguments do not match scope")
        jti = claims["jti"]
        if not isinstance(jti, str) or not 16 <= len(jti) <= 128:
            raise Denied("invalid token identifier")
        _invoice_policy(authenticated_agent, tool, args)
        self._replay_store.spend(jti, expires, now)
        return {"decision": "allow", "tool": tool, "agent": authenticated_agent,
                "jti": jti, "note": "authorization only; no tool executed"}


def demo() -> None:
    """One allow and one replay deny with ephemeral key/database."""
    secret = secrets.token_bytes(32)
    args = {"amount_cents": 9500, "currency": "EUR", "recipient": "supplier_001"}
    with tempfile.TemporaryDirectory(prefix="faraday-") as directory:
        issuer = Issuer(secret)
        gate = Gate(secret, SQLiteReplayStore(Path(directory) / "replay.sqlite"))
        token = issuer.issue("agent_finance", "pay_invoice", args, ttl=60)
        print("First authorization:", gate.authorize(token, authenticated_agent="agent_finance",
                                                       tool="pay_invoice", args=args)["decision"])
        try:
            gate.authorize(token, authenticated_agent="agent_finance", tool="pay_invoice", args=args)
        except Denied as exc:
            print("Replay blocked:", exc)


if __name__ == "__main__":
    if sys.argv[1:] == ["demo"]:
        demo()
    else:
        raise SystemExit("Usage: python faraday.py demo")
