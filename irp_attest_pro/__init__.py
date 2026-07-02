"""irp-attest-pro: advanced attestation for IRP (BSL 1.1, source-available).

The MIT core (`irp-capture[integrity]`) proves that an RFC 3161 timestamp
signature is cryptographically valid, and reports `trust-root validation:
NOT PERFORMED` honestly. This module adds the missing layer: does the timestamp
chain to a trust anchor the verifier accepts, and was every certificate valid at
the time of issue (genTime). It never bakes in a trust root; anchors are always
supplied by the caller.

This is the BSL layer. It DEPENDS ON the MIT core and is never imported by it.
"""
from .trust import (
    load_trust_anchors,
    verify_with_trust_roots,
)

__all__ = ["verify_with_trust_roots", "load_trust_anchors"]
__version__ = "0.1.0"
