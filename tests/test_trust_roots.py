"""Tests for certificate-chain / trust-root validation.

Three layers:
  1. Deterministic unit tests on the path/validity/EKU logic, using
     self-generated certs (no network).
  2. An offline end-to-end test against a REAL freetsa token + freetsa CA
     fixture (no network at test time).
  3. A live round-trip against freetsa (skipped offline).
"""
import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from irp_attest_pro.trust import (
    _build_path,
    _has_timestamping_eku,
    _issued_by,
    _valid_at,
    load_trust_anchors,
    verify_with_trust_roots,
)

FIXT = Path(__file__).parent / "fixtures"
UTC = timezone.utc


def _online() -> bool:
    try:
        socket.create_connection(("freetsa.org", 443), timeout=5).close()
        return True
    except OSError:
        return False


# ── cert factory (self-signed test PKI) ────────────────────────────────────

def _make_ca(name, nb, na):
    key = ec.generate_private_key(ec.SECP256R1())
    subj = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subj).issuer_name(subj)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _make_leaf(name, ca_key, ca_cert, nb, na, eku=True):
    key = ec.generate_private_key(ec.SECP256R1())
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(nb).not_valid_after(na)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]), critical=True)
    return key, b.sign(ca_key, hashes.SHA256())


NB = datetime(2026, 1, 1)
NA = datetime(2027, 1, 1)


class TestPathLogic:
    def setup_method(self):
        self.ca_key, self.ca = _make_ca("Test CA", NB, NA)
        self.other_key, self.other_ca = _make_ca("Unrelated CA", NB, NA)
        self.leaf_key, self.leaf = _make_leaf("Test TSA", self.ca_key, self.ca, NB, NA)

    def test_issued_by_true_and_false(self):
        assert _issued_by(self.leaf, self.ca) is True
        assert _issued_by(self.leaf, self.other_ca) is False

    def test_build_path_to_anchor(self):
        path, anchor = _build_path(self.leaf, [], [self.ca])
        assert [c.subject for c in path] == [self.leaf.subject]
        assert anchor.subject == self.ca.subject

    def test_build_path_no_anchor(self):
        path, anchor = _build_path(self.leaf, [], [self.other_ca])
        assert path is None and anchor is None

    def test_valid_at(self):
        assert _valid_at(self.leaf, datetime(2026, 6, 1, tzinfo=UTC)) is True
        assert _valid_at(self.leaf, datetime(2025, 6, 1, tzinfo=UTC)) is False
        assert _valid_at(self.leaf, datetime(2028, 6, 1, tzinfo=UTC)) is False

    def test_timestamping_eku(self):
        _, no_eku = _make_leaf("No EKU", self.ca_key, self.ca, NB, NA, eku=False)
        assert _has_timestamping_eku(self.leaf) is True
        assert _has_timestamping_eku(no_eku) is False

    def test_load_anchors_from_list_of_certs(self):
        anchors = load_trust_anchors([self.ca, self.other_ca])
        assert len(anchors) == 2


# ── offline end-to-end against a REAL freetsa token + CA fixture ────────────

@pytest.mark.skipif(
    not (FIXT / "freetsa-token.tsr").exists() or not (FIXT / "freetsa-cacert.pem").exists(),
    reason="freetsa token/CA fixtures not present",
)
class TestRealFreetsaChainOffline:
    def _load(self):
        token = (FIXT / "freetsa-token.tsr").read_bytes()
        digest = bytes.fromhex(json.loads((FIXT / "freetsa-token.meta.json").read_text())["digest_hex"])
        cacert = FIXT / "freetsa-cacert.pem"
        return token, digest, cacert

    def test_trusted_against_freetsa_ca(self):
        token, digest, cacert = self._load()
        r = verify_with_trust_roots(token, digest, cacert)
        assert r["cryptographically_valid"] is True
        # The freetsa CA must cover the fixture token's genTime for TRUSTED.
        assert r["trust_root"] == "TRUSTED", r["trust_reason"]
        assert r["anchor"] is not None
        assert r["timestamping_eku"] is True

    def test_untrusted_against_unrelated_anchor(self):
        token, digest, _ = self._load()
        _, unrelated = _make_ca("Unrelated CA", NB, NA)
        r = verify_with_trust_roots(token, digest, [unrelated])
        assert r["trust_root"] == "UNTRUSTED"
        assert "no path" in r["trust_reason"]

    def test_revocation_requested_is_failclosed(self):
        token, digest, cacert = self._load()
        r = verify_with_trust_roots(token, digest, cacert, check_revocation=True)
        assert r["trust_root"] == "UNTRUSTED"
        assert "revocation" in r["trust_reason"]


# ── live round-trip (skipped offline) ──────────────────────────────────────

@pytest.mark.skipif(not _online(), reason="freetsa.org not reachable")
class TestLive:
    def test_fresh_token_trusted_against_fetched_ca(self, tmp_path):
        import hashlib
        import urllib.request
        from irp.integrity.rfc3161 import request_timestamp

        digest = hashlib.sha256(b"irp-attest-pro live trust-root test").digest()
        token = request_timestamp(digest, "https://freetsa.org/tsr", timeout=20)

        cacert = tmp_path / "freetsa-cacert.pem"
        cacert.write_bytes(urllib.request.urlopen("https://freetsa.org/files/cacert.pem", timeout=20).read())

        r = verify_with_trust_roots(token, digest, cacert)
        assert r["trust_root"] == "TRUSTED", r["trust_reason"]
        assert r["timestamping_eku"] is True
