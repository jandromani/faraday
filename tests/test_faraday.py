"""Build 001 security tests (standard-library unittest)."""
import base64
import json
import secrets
import tempfile
import unittest
from pathlib import Path

from faraday import Denied, Gate, Issuer, SQLiteReplayStore


class FaradayGateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.now = 1_800_000_000
        self.clock = lambda: self.now
        self.secret = secrets.token_bytes(32)
        self.issuer = Issuer(self.secret, self.clock)
        self.gate = Gate(self.secret, SQLiteReplayStore(Path(self.tmp.name) / "replay.db"), self.clock)
        self.args = {"amount_cents": 9500, "currency": "EUR", "recipient": "supplier_001"}

    def issue(self, **kwargs):
        return self.issuer.issue("agent_finance", "pay_invoice", self.args, **kwargs)

    def authorize(self, token, **kwargs):
        return self.gate.authorize(token,
                                   authenticated_agent=kwargs.get("agent", "agent_finance"),
                                   tool=kwargs.get("tool", "pay_invoice"),
                                   args=kwargs.get("args", self.args))

    def test_valid_token(self):
        self.assertEqual("allow", self.authorize(self.issue())["decision"])

    def test_replay_rejected_even_with_new_gate(self):
        token = self.issue()
        self.authorize(token)
        gate2 = Gate(self.secret, SQLiteReplayStore(Path(self.tmp.name) / "replay.db"), self.clock)
        with self.assertRaises(Denied):
            gate2.authorize(token, authenticated_agent="agent_finance", tool="pay_invoice", args=self.args)

    def test_impersonation_and_argument_scope_rejected(self):
        token = self.issue()
        with self.assertRaises(Denied):
            self.authorize(token, agent="agent_other")
        with self.assertRaises(Denied):
            self.authorize(token, args={**self.args, "amount_cents": 12_000})
        self.assertEqual("allow", self.authorize(token)["decision"])

    def test_tampered_payload_rejected(self):
        header, payload, mac = self.issue().split(".")
        obj = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        obj["args"]["amount_cents"] = 19_999
        changed = base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()
        with self.assertRaises(Denied):
            self.authorize(f"{header}.{changed}.{mac}")

    def test_expired_rejected(self):
        token = self.issue(ttl=1)
        self.now += 1
        with self.assertRaises(Denied):
            self.authorize(token)

    def test_invalid_issuance_policy_and_ttl(self):
        with self.assertRaises(Denied):
            self.issuer.issue("agent_other", "pay_invoice", self.args)
        with self.assertRaises(Denied):
            self.issuer.issue("agent_finance", "pay_invoice", {**self.args, "amount_cents": 20_001})
        with self.assertRaises(Denied):
            self.issue(ttl=301)
        with self.assertRaises(Denied):
            self.issue(ttl=True)


if __name__ == "__main__":
    unittest.main()
