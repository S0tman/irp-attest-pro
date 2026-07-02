"""Certificate-chain and trust-root validation for RFC 3161 timestamp tokens.

Wraps the MIT verifier (`irp.integrity.rfc3161.verify_token`) and adds the piece
the MIT core reports as NOT PERFORMED: does the token's signing certificate chain
to a trust anchor the verifier accepts, and was every certificate in that path
valid at the token's genTime (not merely "now").

Design rules, mirroring the MIT core's honesty:
  - Trust anchors are ALWAYS supplied by the caller. Nothing is baked in.
  - The result is never a bare boolean. On failure the caller gets a specific
    reason: no path / expired-at-genTime / missing timeStamping EKU / signature
    invalid.
  - This module depends on the MIT core and is never imported by it (BSL layer).
"""
from __future__ import annotations

from datetime import timezone
from pathlib import Path
from typing import Any, Optional, Union

from asn1crypto import cms
from cryptography import x509
from cryptography.x509.oid import ExtendedKeyUsageOID

from irp.integrity.rfc3161 import read_tst_info, verify_token

AnchorSource = Union[str, Path, x509.Certificate, list]
_MAX_DEPTH = 10


# ── loading ────────────────────────────────────────────────────────────────

def load_trust_anchors(source: AnchorSource) -> list[x509.Certificate]:
    """Load trust anchors from a cert object, a PEM/DER file, a directory of
    them, or a list mixing any of those. PEM bundles (multiple certs in one
    file) are supported."""
    anchors: list[x509.Certificate] = []
    if isinstance(source, x509.Certificate):
        return [source]
    if isinstance(source, (list, tuple)):
        for item in source:
            anchors.extend(load_trust_anchors(item))
        return anchors

    p = Path(source)
    files = sorted(f for f in p.iterdir() if f.is_file()) if p.is_dir() else [p]
    for f in files:
        data = f.read_bytes()
        try:
            anchors.extend(x509.load_pem_x509_certificates(data))
        except ValueError:
            anchors.append(x509.load_der_x509_certificate(data))
    return anchors


# ── certificate extraction from the token ──────────────────────────────────

def _certs_from_token(token_der: bytes) -> list[x509.Certificate]:
    info = cms.ContentInfo.load(token_der)
    signed = info["content"]
    out: list[x509.Certificate] = []
    for choice in signed["certificates"]:
        try:
            out.append(x509.load_der_x509_certificate(choice.chosen.dump()))
        except Exception:
            continue
    return out


def _find_signer(token_der: bytes, certs: list[x509.Certificate]) -> Optional[x509.Certificate]:
    """Identify the signer cert from the SignerInfo `sid` (serial or SKI).
    Serial number is unique within a token, so it is a reliable key."""
    info = cms.ContentInfo.load(token_der)
    sid = info["content"]["signer_infos"][0]["sid"]
    if sid.name == "issuer_and_serial_number":
        serial = sid.chosen["serial_number"].native
        for c in certs:
            if c.serial_number == serial:
                return c
    else:  # subject_key_identifier
        ski = sid.chosen.native
        for c in certs:
            try:
                if c.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest == ski:
                    return c
            except x509.ExtensionNotFound:
                continue
    return certs[0] if certs else None


# ── path building ───────────────────────────────────────────────────────────

def _issued_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    """True if `parent` directly issued `child` (name match + signature).
    Uses cryptography's verify_directly_issued_by, which checks the issuer/subject
    names line up and that the parent's key signed the child."""
    try:
        child.verify_directly_issued_by(parent)
        return True
    except Exception:
        return False


def _build_path(
    signer: x509.Certificate,
    intermediates: list[x509.Certificate],
    anchors: list[x509.Certificate],
) -> tuple[Optional[list[x509.Certificate]], Optional[x509.Certificate]]:
    """Return (path_from_signer_to_leaf_of_anchor, anchor) or (None, None).

    The path is [signer, ...intermediates], not including the anchor itself.
    """
    # The signer may itself be one of the anchors (self-issued TSA).
    for a in anchors:
        if a.fingerprint(signer.signature_hash_algorithm) == signer.fingerprint(signer.signature_hash_algorithm):
            return [signer], a

    path = [signer]
    current = signer
    pool = [c for c in intermediates if c is not signer]
    for _ in range(_MAX_DEPTH):
        for a in anchors:
            if _issued_by(current, a):
                return path, a
        nxt = next((c for c in pool if _issued_by(current, c)), None)
        if nxt is None:
            return None, None
        path.append(nxt)
        pool.remove(nxt)
        current = nxt
    return None, None


# ── checks ──────────────────────────────────────────────────────────────────

def _valid_at(cert: x509.Certificate, when) -> bool:
    return cert.not_valid_before_utc <= when <= cert.not_valid_after_utc


def _has_timestamping_eku(cert: x509.Certificate) -> bool:
    try:
        eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        return ExtendedKeyUsageOID.TIME_STAMPING in eku
    except x509.ExtensionNotFound:
        return False


def _subj(cert: x509.Certificate) -> str:
    return cert.subject.rfc4514_string()


# ── public API ────────────────────────────────────────────────────────────

def verify_with_trust_roots(
    token_der: bytes,
    expected_digest: bytes,
    trust_anchors: AnchorSource,
    *,
    require_timestamping_eku: bool = True,
    check_revocation: bool = False,
) -> dict[str, Any]:
    """Verify an RFC 3161 token AND validate its cert chain to a trust anchor.

    Returns the MIT `verify_token` result extended with:
      trust_root:   "TRUSTED" | "UNTRUSTED"
      trust_reason: specific reason (never a bare boolean)
      chain:        subject strings, signer up to (not incl.) the anchor
      anchor:       anchor subject, or None
      timestamping_eku: bool
      validated_at: genTime the chain was validated at
    """
    base = verify_token(token_der, expected_digest)
    result: dict[str, Any] = dict(base)
    result.update({
        "trust_root": "UNTRUSTED",
        "trust_reason": None,
        "chain": [],
        "anchor": None,
        "timestamping_eku": None,
    })

    if not base.get("cryptographically_valid"):
        result["trust_reason"] = "token signature not cryptographically valid (MIT layer)"
        return result

    if check_revocation:
        # Revocation (CRL / OCSP) is a later feature in this BSL module. Fail
        # closed rather than silently claim TRUSTED without checking it.
        result["trust_reason"] = "revocation checking (CRL/OCSP) requested but not implemented in this version"
        return result

    anchors = load_trust_anchors(trust_anchors)
    if not anchors:
        result["trust_reason"] = "no trust anchors supplied"
        return result

    gen_time = read_tst_info(token_der)["gen_time"]
    if gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=timezone.utc)

    certs = _certs_from_token(token_der)
    if not certs:
        result["trust_reason"] = "token embeds no certificates to build a path from"
        return result

    signer = _find_signer(token_der, certs)
    path, anchor = _build_path(signer, certs, anchors)
    if path is None:
        result["trust_reason"] = "no path from the signer certificate to any supplied trust anchor"
        return result

    result["chain"] = [_subj(c) for c in path]
    result["anchor"] = _subj(anchor)

    for cert in path + [anchor]:
        if not _valid_at(cert, gen_time):
            result["trust_reason"] = (
                f"certificate '{_subj(cert)}' was not valid at genTime {gen_time.isoformat()} "
                f"(valid {cert.not_valid_before_utc.isoformat()} to {cert.not_valid_after_utc.isoformat()})"
            )
            return result

    result["timestamping_eku"] = _has_timestamping_eku(signer)
    if require_timestamping_eku and not result["timestamping_eku"]:
        result["trust_reason"] = "signer certificate lacks the id-kp-timeStamping extended key usage (RFC 3161 requires it)"
        return result

    result["trust_root"] = "TRUSTED"
    eku_note = "; timeStamping EKU present" if result["timestamping_eku"] else ""
    result["trust_reason"] = (
        f"valid path to a supplied trust anchor; all certificates valid at genTime {gen_time.isoformat()}{eku_note}"
    )
    result["validated_at"] = gen_time.isoformat()
    return result
