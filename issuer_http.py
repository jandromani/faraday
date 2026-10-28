"""Loopback-only development issuer service; NEVER expose directly to a network.

The issuer process retains the Ed25519 private key. Clients present a signed
agent-intent proof; the Gate verifies issued capabilities with the public key.
No mTLS, SPIFFE attestation, sandboxing or network segmentation is provided.
"""
import argparse
import json
import os
import stat
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from faraday import Denied, SQLiteReplayStore
from faraday_v2 import IssuerV2, TrustRegistry, b64, parse_json, unb64

MAX_REQUEST_SIZE = 8192


def handler_for(issuer: IssuerV2):
    class Handler(BaseHTTPRequestHandler):
        def respond(self, status: int, payload: dict):
            blob = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)

        def do_GET(self):
            if self.path == "/healthz":
                self.respond(200, {"status": "up", "role": "issuer-v2-dev"})
            else:
                self.respond(404, {"error": "not found"})

        def do_POST(self):
            if self.path != "/v2/capabilities":
                return self.respond(404, {"error": "not found"})
            length = self.headers.get("Content-Length")
            if not length or not length.isdecimal() or not 1 <= int(length) <= MAX_REQUEST_SIZE:
                return self.respond(413, {"error": "invalid request size"})
            try:
                doc = parse_json(self.rfile.read(int(length)))
                if not isinstance(doc, dict) or set(doc) != {"proof", "ttl"}:
                    return self.respond(400, {"error": "invalid request schema"})
                token = issuer.issue(doc["proof"], ttl=doc["ttl"])
                return self.respond(200, {"capability": token})
            except Denied:
                return self.respond(403, {"error": "capability denied"})
            except (TypeError, ValueError):
                return self.respond(400, {"error": "invalid request"})
            except Exception:
                # Fail closed; never leak key material or internal errors.
                return self.respond(503, {"error": "issuer unavailable"})

        def log_message(self, fmt, *args):
            # Do not put credential-bearing requests in default logs.
            return

    return Handler


def read_private_key(path: str) -> Ed25519PrivateKey:
    file = Path(path)
    if os.name == "posix" and file.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ValueError("issuer private key must have file permissions 0600")
    key = serialization.load_pem_private_key(file.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("expected Ed25519 private key")
    return key


def load_registry(path: str) -> TrustRegistry:
    encoded = parse_json(Path(path).read_bytes())
    if not isinstance(encoded, dict) or not encoded:
        raise ValueError("agent registry must map identities to raw public keys")
    return TrustRegistry({name: Ed25519PublicKey.from_public_bytes(unb64(key))
                          for name, key in encoded.items()})


def main():
    p = argparse.ArgumentParser(description="FARADAY Build 002 loopback-only issuer")
    p.add_argument("--issuer-key", required=True, help="0600 PEM private key file")
    p.add_argument("--trusted-agents", required=True, help="JSON agent ID -> public key")
    p.add_argument("--db", required=True, help="SQLite replay store file")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--kid", default="issuer-dev-01")
    args = p.parse_args()
    key = read_private_key(args.issuer_key)
    registry = load_registry(args.trusted_agents)
    issuer = IssuerV2(key, key_id=args.kid, registry=registry,
                      replay=SQLiteReplayStore(args.db))
    with HTTPServer(("127.0.0.1", args.port), handler_for(issuer)) as server:
        print(f"FARADAY issuer dev listening on 127.0.0.1:{server.server_port}", flush=True)
        server.serve_forever()


if __name__ == "__main__":
    main()
