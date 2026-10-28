"""FARADAY Build 002: asymmetric issuer and agent proof-of-possession.

This is an authorization prototype, NOT mandatory tool-path enforcement,
real SPIFFE attestation, or a production trust boundary.
Requires cryptography>=44.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
import time
from typing import Any, Callable, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from faraday import Denied, SQLiteReplayStore

AUDIENCE = "faraday-tool-executor"
ISSUER = "faraday-issuer-v2"
HEADER_TYPE = "FARADAY-CAP"
PROOF_DOMAIN = b"FARADAY-AGENT-PROOF-v2\x00"
MAX_PROOF_TTL = 30
MAX_CAP_TTL = 300
MAX_BYTES = 8192
CLAIM_FIELDS = {"iss", "aud", "sub", "cnf", "tool", "args", "iat", "exp", "jti", "policy"}
PROOF_FIELDS = {"purpose", "agent", "tool", "args", "iat", "exp", "nonce", "cap_hash"}
ALLOWED_PURPOSES = {"faraday.issue.v2", "faraday.execute.v2"}


def canonical(obj: Any) -> bytes:
    try:
        data = json.dumps(obj, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, allow_nan=False).encode("utf-8")
    except (TypeError, ValueError, OverflowError) as exc:
        raise Denied("invalid JSON data") from exc
    if len(data) > MAX_BYTES:
        raise Denied("oversized data")
    return data


def b64(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def unb64(value: str) -> bytes:
    if (not isinstance(value, str) or not value or len(value) > MAX_BYTES * 2
            or any(ch not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for ch in value)):
        raise Denied("invalid base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as exc:
        raise Denied("invalid base64url") from exc
    if b64(raw) != value:
        raise Denied("non-canonical base64url")
    return raw


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out = {}
    for k, v in pairs:
        if k in out:
            raise Denied("duplicate JSON key")
        out[k] = v
    return out


def parse_json(raw: bytes) -> Any:
    if len(raw) > MAX_BYTES:
        raise Denied("oversized JSON")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(Denied("non-finite JSON value")))
    except (ValueError, UnicodeDecodeError) as exc:
        raise Denied("invalid JSON") from exc


def public_raw(pub: Ed25519PublicKey) -> bytes:
    return pub.public_bytes(encoding=serialization.Encoding.Raw,
                            format=serialization.PublicFormat.Raw)


def public_fingerprint(pub: Ed25519PublicKey) -> str:
    return b64(hashlib.sha256(public_raw(pub)).digest())


def enforce_policy(agent: Any, tool: Any, args: Any) -> None:
    if agent != "spiffe://faraday.local/agent/finance" or tool != "pay_invoice":
        raise Denied("principal/tool not allowlisted")
    if not isinstance(args, dict) or set(args) != {"amount_cents", "currency", "recipient"}:
        raise Denied("invalid argument schema")
    if (type(args["amount_cents"]) is not int or not 1 <= args["amount_cents"] <= 20000
            or args["currency"] != "EUR" or args["recipient"] != "supplier_001"):
        raise Denied("invoice policy denies request")


class TrustRegistry:
    """Pinned public-key identities. No workload attestation is performed."""

    def __init__(self, agents: Mapping[str, Ed25519PublicKey]):
        if not agents:
            raise ValueError("at least one trusted agent is required")
        if not all(isinstance(k, str) and isinstance(v, Ed25519PublicKey)
                   for k, v in agents.items()):
            raise ValueError("invalid trust registry")
        self._agents = dict(agents)

    def key(self, agent: str) -> Ed25519PublicKey:
        if not isinstance(agent, str) or agent not in self._agents:
            raise Denied("unknown agent identity")
        return self._agents[agent]


def make_proof(agent_key: Ed25519PrivateKey, agent: str, tool: str,
               args: dict[str, Any], *, purpose: str,
               now: int | None = None, ttl: int = 20,
               cap_hash: str | None = None, nonce: str | None = None) -> dict:
    if purpose not in ALLOWED_PURPOSES or type(ttl) is not int or not 1 <= ttl <= MAX_PROOF_TTL:
        raise ValueError("invalid proof purpose/lifetime")
    if purpose == "faraday.execute.v2" and not isinstance(cap_hash, str):
        raise ValueError("execution proof requires capability fingerprint")
    if purpose == "faraday.issue.v2" and cap_hash is not None:
        raise ValueError("issue proof cannot bind an existing capability")
    ts = int(time.time()) if now is None else now
    payload = {"purpose": purpose, "agent": agent, "tool": tool, "args": args,
               "iat": ts, "exp": ts + ttl, "nonce": nonce or secrets.token_urlsafe(24),
               "cap_hash": cap_hash}
    return {"payload": payload, "sig": b64(agent_key.sign(PROOF_DOMAIN + canonical(payload)))}


def verify_proof(proof: Any, *, purpose: str, registry: TrustRegistry,
                 now: int) -> dict:
    if (not isinstance(proof, dict) or set(proof) != {"payload", "sig"}
            or not isinstance(proof["payload"], dict)):
        raise Denied("malformed agent proof")
    payload = proof["payload"]
    if set(payload) != PROOF_FIELDS or payload["purpose"] != purpose:
        raise Denied("invalid agent proof purpose/schema")
    iat, exp = payload["iat"], payload["exp"]
    if (type(iat) is not int or type(exp) is not int or iat > now or exp <= now
            or not 1 <= exp - iat <= MAX_PROOF_TTL):
        raise Denied("agent proof expired/invalid")
    nonce = payload["nonce"]
    if not isinstance(nonce, str) or not 16 <= len(nonce) <= 128:
        raise Denied("invalid proof nonce")
    cap_hash = payload["cap_hash"]
    if purpose == "faraday.issue.v2" and cap_hash is not None:
        raise Denied("issuer proof bound to a capability")
    if purpose == "faraday.execute.v2" and (not isinstance(cap_hash, str) or len(cap_hash) != 43):
        raise Denied("execution proof missing capability fingerprint")
    pub = registry.key(payload["agent"])
    try:
        pub.verify(unb64(proof["sig"]), PROOF_DOMAIN + canonical(payload))
    except InvalidSignature as exc:
        raise Denied("invalid agent signature") from exc
    enforce_policy(payload["agent"], payload["tool"], payload["args"])
    return payload


class IssuerV2:
    """Privileged authority: only this component holds issuer signing key."""

    def __init__(self, signer: Ed25519PrivateKey, *, key_id: str,
                 registry: TrustRegistry, replay: SQLiteReplayStore,
                 clock: Callable[[], float] = time.time):
        if not isinstance(signer, Ed25519PrivateKey) or not isinstance(key_id, str) or not key_id:
            raise ValueError("invalid issuer key")
        self._signer, self._key_id, self._registry = signer, key_id, registry
        self._replay, self._clock = replay, clock

    def issue(self, signed_intent: dict, *, ttl: int = 60) -> str:
        if type(ttl) is not int or not 1 <= ttl <= MAX_CAP_TTL:
            raise Denied("invalid capability TTL")
        now = int(self._clock())
        payload = verify_proof(signed_intent, purpose="faraday.issue.v2",
                               registry=self._registry, now=now)
        self._replay.spend("issue:" + payload["agent"] + ":" + payload["nonce"],
                           payload["exp"], now)
        claims = {
            "iss": ISSUER, "aud": AUDIENCE, "sub": payload["agent"],
            "cnf": public_fingerprint(self._registry.key(payload["agent"])),
            "tool": payload["tool"], "args": payload["args"],
            "iat": now, "exp": now + ttl,
            "jti": secrets.token_urlsafe(24), "policy": "invoice-policy-v1",
        }
        header = {"alg": "EdDSA", "typ": HEADER_TYPE, "v": 2, "kid": self._key_id}
        signing_input = b64(canonical(header)) + "." + b64(canonical(claims))
        signature = self._signer.sign(signing_input.encode("ascii"))
        return signing_input + "." + b64(signature)


class GateV2:
    """Unprivileged verifier: only pinned issuer PUBLIC keys are accepted."""

    def __init__(self, *, issuer_keys: Mapping[str, Ed25519PublicKey],
                 registry: TrustRegistry, replay: SQLiteReplayStore,
                 clock: Callable[[], float] = time.time):
        if not issuer_keys or not all(isinstance(k, str) and isinstance(v, Ed25519PublicKey)
                                      for k, v in issuer_keys.items()):
            raise ValueError("invalid issuer trust roots")
        self._issuer_keys = dict(issuer_keys)
        self._registry, self._replay, self._clock = registry, replay, clock

    def authorize(self, capability: str, signed_execution: dict) -> dict:
        if not isinstance(capability, str) or len(capability) > MAX_BYTES * 2:
            raise Denied("invalid capability")
        segments = capability.split(".")
        if len(segments) != 3:
            raise Denied("malformed capability")
        h64, p64, s64 = segments
        header, claims = parse_json(unb64(h64)), parse_json(unb64(p64))
        if not isinstance(header, dict) or set(header) != {"alg", "typ", "v", "kid"}:
            raise Denied("invalid issuer header")
        if header["alg"] != "EdDSA" or header["typ"] != HEADER_TYPE or header["v"] != 2:
            raise Denied("unsupported algorithm/header")
        key_id = header["kid"]
        if not isinstance(key_id, str) or key_id not in self._issuer_keys:
            raise Denied("unknown issuer key")
        try:
            self._issuer_keys[key_id].verify(unb64(s64), (h64 + "." + p64).encode("ascii"))
        except InvalidSignature as exc:
            raise Denied("invalid issuer signature") from exc
        if not isinstance(claims, dict) or set(claims) != CLAIM_FIELDS:
            raise Denied("invalid capability schema")
        now = int(self._clock())
        issued, expires = claims["iat"], claims["exp"]
        if (type(issued) is not int or type(expires) is not int
                or issued > now or expires <= now or not 1 <= expires - issued <= MAX_CAP_TTL):
            raise Denied("expired/invalid capability lifetime")
        if claims["iss"] != ISSUER or claims["aud"] != AUDIENCE:
            raise Denied("issuer/audience mismatch")
        jti = claims["jti"]
        if not isinstance(jti, str) or not 16 <= len(jti) <= 128:
            raise Denied("invalid capability identifier")
        execution = verify_proof(signed_execution, purpose="faraday.execute.v2",
                                 registry=self._registry, now=now)
        if (execution["agent"] != claims["sub"]
                or execution["tool"] != claims["tool"]
                or canonical(execution["args"]) != canonical(claims["args"])
                or execution["cap_hash"] != b64(hashlib.sha256(capability.encode("ascii")).digest())):
            raise Denied("execution is outside capability scope")
        if claims["cnf"] != public_fingerprint(self._registry.key(execution["agent"])):
            raise Denied("capability not bound to agent key")
        if claims["policy"] != "invoice-policy-v1":
            raise Denied("unknown authorization policy")
        enforce_policy(execution["agent"], execution["tool"], execution["args"])
        self._replay.spend("cap:" + jti, expires, now)
        return {"decision": "allow", "agent": execution["agent"],
                "tool": execution["tool"], "capability_jti": jti,
                "note": "authorization only; no tool was executed"}


def capability_hash(token: str) -> str:
    return b64(hashlib.sha256(token.encode("ascii")).digest())
