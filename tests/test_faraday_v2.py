"""Adversarial authorization tests for FARADAY Build 002."""
import secrets
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from faraday import Denied, SQLiteReplayStore
from faraday_v2 import (GateV2, IssuerV2, TrustRegistry, capability_hash,
                        make_proof, public_fingerprint)

AGENT = "spiffe://faraday.local/agent/finance"
ARGS = {"amount_cents": 9500, "currency": "EUR", "recipient": "supplier_001"}


class Build002SecurityTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.now = 1_800_000_000
        self.clock = lambda: self.now
        self.agent_key = Ed25519PrivateKey.generate()
        self.attacker_key = Ed25519PrivateKey.generate()
        self.issuer_key = Ed25519PrivateKey.generate()
        self.registry = TrustRegistry({AGENT: self.agent_key.public_key()})
        self.issuer = IssuerV2(
            self.issuer_key, key_id="issuer-2026-10",
            registry=self.registry, clock=self.clock,
            replay=SQLiteReplayStore(Path(self.dir.name) / "issued.db"))
        self.store = Path(self.dir.name) / "consumed.db"
        self.gate = self.new_gate()

    def new_gate(self, **kw):
        return GateV2(issuer_keys=kw.get("keys", {"issuer-2026-10": self.issuer_key.public_key()}),
                      registry=kw.get("registry", self.registry),
                      replay=SQLiteReplayStore(self.store), clock=self.clock)

    def intent(self, *, key=None, agent=AGENT, tool="pay_invoice", args=None, ttl=20):
        return make_proof(key or self.agent_key, agent, tool, args or ARGS,
                          purpose="faraday.issue.v2", now=self.now, ttl=ttl)

    def token(self, *, intent=None, ttl=60):
        return self.issuer.issue(intent or self.intent(), ttl=ttl)

    def execution(self, token, *, key=None, agent=AGENT, tool="pay_invoice",
                  args=None, cap_hash=None, ttl=20):
        return make_proof(key or self.agent_key, agent, tool, args or ARGS,
                          purpose="faraday.execute.v2", now=self.now, ttl=ttl,
                          cap_hash=cap_hash or capability_hash(token))

    def test_valid_issuer_and_gate(self):
        token = self.token()
        result = self.gate.authorize(token, self.execution(token))
        self.assertEqual(result["decision"], "allow")

    def test_issuer_only_has_private_signer_and_gate_only_public(self):
        token = self.token()
        self.assertFalse(hasattr(self.gate, "_signer"))
        self.assertEqual(self.gate.authorize(token, self.execution(token))["decision"], "allow")

    def test_issuer_does_not_trust_string_identity(self):
        with self.assertRaises(Denied):
            self.token(intent=self.intent(key=self.attacker_key))

    def test_gate_requires_private_agent_key_possession(self):
        token = self.token()
        with self.assertRaises(Denied):
            self.gate.authorize(token, self.execution(token, key=self.attacker_key))
        # A failed attempt does not consume an otherwise valid capability.
        self.assertEqual(self.gate.authorize(token, self.execution(token))["decision"], "allow")

    def test_wrong_agent_identity_denied(self):
        with self.assertRaises(Denied):
            self.token(intent=self.intent(agent="spiffe://faraday.local/agent/evil"))

    def test_issuance_proof_replay_denied(self):
        request = self.intent()
        self.token(intent=request)
        with self.assertRaises(Denied):
            self.token(intent=request)

    def test_capability_replay_denied_across_gate_instances(self):
        token = self.token()
        proof = self.execution(token)
        self.gate.authorize(token, proof)
        with self.assertRaises(Denied):
            self.new_gate().authorize(token, proof)

    def test_expired_capability_denied(self):
        token = self.token(ttl=2)
        self.now += 2
        with self.assertRaises(Denied):
            self.gate.authorize(token, self.execution(token))

    def test_expired_agent_proof_denied(self):
        token = self.token()
        proof = self.execution(token, ttl=1)
        self.now += 1
        with self.assertRaises(Denied):
            self.gate.authorize(token, proof)

    def test_wrong_arguments_denied(self):
        token = self.token()
        with self.assertRaises(Denied):
            self.gate.authorize(token, self.execution(token, args={**ARGS, "amount_cents": 11000}))

    def test_wrong_capability_fingerprint_denied(self):
        token = self.token()
        with self.assertRaises(Denied):
            self.gate.authorize(token, self.execution(token, cap_hash="a" * 43))

    def test_unknown_issuer_denied(self):
        token = self.token()
        bogus_gate = self.new_gate(keys={"issuer-2026-10": Ed25519PrivateKey.generate().public_key()})
        with self.assertRaises(Denied):
            bogus_gate.authorize(token, self.execution(token))

    def test_tampered_capability_denied(self):
        token = self.token()
        h, p, s = token.split(".")
        damaged = h + "." + p[:-2] + ("A" if p[-2] != "A" else "B") + p[-1] + "." + s
        with self.assertRaises(Denied):
            self.gate.authorize(damaged, self.execution(damaged))

    def test_algorithm_confusion_denied(self):
        token = self.token()
        h, p, s = token.split(".")
        with self.assertRaises(Denied):
            self.gate.authorize("bm9uZQ." + p + "." + s, self.execution(token))

    def test_invoice_policy_default_deny(self):
        with self.assertRaises(Denied):
            self.issuer.issue(self.intent(args={**ARGS, "amount_cents": 20001}))
        with self.assertRaises(Denied):
            self.issuer.issue(self.intent(tool="transfer_all_funds"))

    def test_key_rotation_removes_authority(self):
        token = self.token()
        rotated = TrustRegistry({AGENT: Ed25519PrivateKey.generate().public_key()})
        gate = self.new_gate(registry=rotated)
        with self.assertRaises(Denied):
            gate.authorize(token, self.execution(token))

    def test_policy_cannot_be_bypassed_with_boolean_amount(self):
        with self.assertRaises(Denied):
            self.issuer.issue(self.intent(args={**ARGS, "amount_cents": True}))

    def test_agent_public_key_fingerprint_is_stable(self):
        self.assertEqual(public_fingerprint(self.agent_key.public_key()),
                         public_fingerprint(self.agent_key.public_key()))

    def test_issuer_refuses_invalid_ttl(self):
        with self.assertRaises(Denied):
            self.token(ttl=301)


if __name__ == "__main__":
    unittest.main()
