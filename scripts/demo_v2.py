"""End-to-end local demonstration with issuer running as a DIFFERENT process."""
import json
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from faraday import Denied, SQLiteReplayStore
from faraday_v2 import (GateV2, TrustRegistry, b64, capability_hash,
                        make_proof, public_raw)

ROOT = Path(__file__).resolve().parent.parent
AGENT = "spiffe://faraday.local/agent/finance"
ARGS = {"amount_cents": 9500, "currency": "EUR", "recipient": "supplier_001"}


def demo():
    issuer_key = Ed25519PrivateKey.generate()
    agent_key = Ed25519PrivateKey.generate()
    attacker_key = Ed25519PrivateKey.generate()
    with tempfile.TemporaryDirectory(prefix="faraday-build002-") as td:
        root = Path(td)
        private_key_file = root / "issuer.pem"
        private_key_file.write_bytes(issuer_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
        private_key_file.chmod(0o600)
        registry_file = root / "agents.json"
        registry_file.write_text(json.dumps({
            AGENT: b64(public_raw(agent_key.public_key()))}), encoding="utf-8")
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        command = [sys.executable, str(ROOT / "issuer_http.py"),
                   "--issuer-key", str(private_key_file),
                   "--trusted-agents", str(registry_file),
                   "--db", str(root / "issuance.db"),
                   "--kid", "issuer-dev-01", "--port", str(port)]
        proc = subprocess.Popen(command, cwd=ROOT, stdout=subprocess.DEVNULL,
                                stderr=subprocess.PIPE, text=True)
        try:
            url = f"http://127.0.0.1:{port}"
            for _ in range(40):
                if proc.poll() is not None:
                    raise RuntimeError("issuer process terminated unexpectedly")
                try:
                    with urllib.request.urlopen(url + "/healthz", timeout=0.3) as health:
                        if health.status == 200:
                            break
                except (OSError, urllib.error.URLError):
                    time.sleep(0.1)
            else:
                raise RuntimeError("issuer service did not become ready")
            proof = make_proof(agent_key, AGENT, "pay_invoice", ARGS,
                               purpose="faraday.issue.v2")
            body = json.dumps({"proof": proof, "ttl": 60}).encode()
            req = urllib.request.Request(url + "/v2/capabilities",
                                         data=body, headers={"Content-Type": "application/json"},
                                         method="POST")
            with urllib.request.urlopen(req, timeout=3) as response:
                token = json.load(response)["capability"]
            print("Issuer process: capability signed (private key isolated from verifier)")
            registry = TrustRegistry({AGENT: agent_key.public_key()})
            gate = GateV2(issuer_keys={"issuer-dev-01": issuer_key.public_key()},
                          registry=registry,
                          replay=SQLiteReplayStore(root / "gate.db"))

            def execution(private_key):
                return make_proof(private_key, AGENT, "pay_invoice", ARGS,
                                  purpose="faraday.execute.v2",
                                  cap_hash=capability_hash(token))

            try:
                gate.authorize(token, execution(attacker_key))
                raise AssertionError("stolen capability was accepted")
            except Denied:
                print("Stolen capability without agent private key: DENIED")
            authorized = gate.authorize(token, execution(agent_key))
            print("Valid signed execution intent:", authorized["decision"].upper())
            try:
                gate.authorize(token, execution(agent_key))
                raise AssertionError("replay was accepted")
            except Denied:
                print("Capability replay: DENIED")
            print("External side effects: NONE (proof of concept)")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    demo()
