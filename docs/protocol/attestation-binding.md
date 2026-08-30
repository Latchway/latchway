# Canonical attestation binding version 1

The `AttestationBinding` binds a one-time server challenge, verified principal and installation DPoP key to platform evidence. Its JSON shape is normative in `api/attestation-binding.schema.json`.

## Construction

1. The server verifies the external identity and the challenge-request DPoP proof.
2. The server creates a cryptographically random challenge ID and nonce, records the resolved application/environment/principal, RFC 7638 JWK thumbprint, platform, issuance time and expiry, and returns only the public challenge fields.
3. The SDK constructs exactly the nine version-1 fields. It must not add, omit, coerce or rename a field.
4. Validate the object against the schema.
5. Serialize with the JSON Canonicalization Scheme (RFC 8785/JCS), encoded directly as UTF-8 with no BOM.
6. Hash those bytes with SHA-256. Encode as unpadded base64url only where a provider API requires text.
7. Bind provider evidence to that digest and submit it with the challenge ID. The server independently reconstructs the binding from stored authoritative values; it never trusts client-supplied binding fields.

All identifiers and nonces in version 1 are restricted to ASCII by schema, avoiding Unicode normalization ambiguity. `issued_at` is an integer Unix timestamp in seconds. JCS does not permit insignificant whitespace and sorts object member names according to RFC 8785.

## Provider mapping

- Apple App Attest uses the 32 digest bytes as `clientDataHash` for attestation or assertion generation and validates the corresponding nonce/signature server-side.
- Google Play Integrity uses the unpadded base64url digest as the standard-request `requestHash` and verifies the returned request details and freshness.
- Debug evidence signs a domain-separated structure containing `binding_version`, `binding_hash` and expiry using the configured test-only verifier key.
- Web risk and App Check adapters must document and test the provider-supported binding channel before they can produce a trust result. A provider incapable of cryptographically covering the digest can contribute only a weaker risk signal paired with the atomically consumed challenge; it cannot claim native app/device trust.

The challenge is consumed atomically during session exchange. Expired, already-consumed, cross-application, cross-environment, cross-principal, cross-key, wrong-platform or digest-mismatched evidence fails with `attestation_invalid` or a more specific stable code.

## Vectors

`api/test-vectors/attestation-binding/v1.json` intentionally presents input members in different orders. Implementations must produce the exact `canonical_json`, UTF-8 bytes and SHA-256 values. The vector set contains no live identifier, credential or provider evidence.
