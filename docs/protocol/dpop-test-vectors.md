# RFC 9449 DPoP test vectors

`api/test-vectors/dpop/v1.json` is the cross-language fixture set for wire protocol 1. Its format is defined by the adjacent `vector.schema.json`.

## Required calculations

- Public installation keys are EC P-256 JWKs with `kty`, `crv`, `x` and `y` only.
- RFC 7638 thumbprints hash the UTF-8 bytes of exactly `{"crv":"P-256","kty":"EC","x":"...","y":"..."}` with SHA-256 and encode the digest as unpadded base64url.
- DPoP protected headers require `typ: dpop+jwt`, `alg: ES256` and the public JWK. Remote key references and private members are forbidden.
- `htm` is the uppercase effective HTTP method. `htu` follows RFC 9449 URI comparison and excludes fragment/userinfo; trusted proxy configuration determines the external origin.
- `iat` must fall inside the configured bounded skew at the vector's `reference_time`; `jti` is unique per proof.
- For protected requests, `ath` is unpadded base64url of SHA-256 over the exact access-token ASCII bytes.
- If the server issued a DPoP nonce, the proof must contain that exact nonce.
- ES256 compact JWS signatures use the 64-byte JOSE `R || S` representation, not ASN.1 DER.

Verification order may avoid unnecessary cryptography, but externally observable failures remain safe stable errors. A syntactically valid proof is not accepted until method, URI, time, access-token hash, nonce, token `cnf.jkt`, signature and replay insertion all pass.

The fixture private JWK exists solely so SDKs can reproduce or independently sign assertions. It is public test material, must never be accepted as a production credential, and must never be copied into examples marketed as secure storage.
