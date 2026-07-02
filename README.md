# irp-attest-pro

Advanced attestation for [IRP](https://github.com/S0tman/irp-capture). Source-available under the Business Source License 1.1.

The MIT core (`irp-capture[integrity]`) proves that an RFC 3161 timestamp signature is cryptographically valid, and reports `trust-root validation: NOT PERFORMED` honestly. This module adds the layer the core deliberately leaves to the verifier: **does the timestamp chain to a trust anchor you accept, and was every certificate valid at the time it was issued.** That is the difference between "witnessed" and "witnessed by an authority a regulator recognises."

It **depends on** the MIT core and is **never imported by it**. The trust boundary stays clean: anchors are always supplied by you, never baked in.

## What it checks

Given a token, the expected digest, and your trust anchors, `verify_with_trust_roots`:

1. Runs the MIT verifier (signature validity over the token).
2. Builds a path from the token's signing certificate to one of your anchors.
3. Confirms every certificate in the path was valid **at the token's genTime** (not just now).
4. Confirms the signer carries the `id-kp-timeStamping` extended key usage RFC 3161 requires.
5. Optionally (later): revocation via CRL / OCSP. Requesting it today fails closed rather than pretending.

The result is never a bare boolean. On failure you get the specific reason: no path, expired-at-genTime, missing timeStamping EKU, or signature invalid.

## Usage

```python
from irp_attest_pro import verify_with_trust_roots

# anchors: a PEM/DER file, a directory of them, or a list of certs you accept
result = verify_with_trust_roots(token_der, expected_digest, "trust/freetsa-cacert.pem")

if result["trust_root"] == "TRUSTED":
    print("witnessed by", result["anchor"], "at", result["validated_at"])
else:
    print("not trusted:", result["trust_reason"])
```

## Boundary and honesty

- `TRUSTED` means: valid signature, a path to an anchor **you** supplied, all certificates valid at genTime, and (by default) the timeStamping EKU present. It does not assert completeness, authorship, or the truth of the underlying record. Those limits are the same as the MIT core's `TRUST.md`.
- Trust-anchor policy is yours. This tool never chooses which authorities to trust for you.

## License

Business Source License 1.1. You may use, copy, modify, and self-host this for any purpose, including internal production, **except** offering it to third parties as a hosted or managed attestation or timestamping service. Each release converts to MIT three years after publication. See [LICENSE](LICENSE). For a commercial license (including running it as a service, SLA, support, or qualified-TSA needs), contact the Licensor.
