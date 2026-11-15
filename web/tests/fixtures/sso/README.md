# SSO test vector

`vector.json` is a deterministic test vector for the cvengine.live single sign-on tokens. The cvENGINE (Django) side
can load it to check its verifier against exactly what the signer in `src/lib/sso.js` produces.

Ed25519 signatures (RFC 8032) are deterministic, so the same seed and the same bytes always give the same signature.

| Field | Meaning |
| --- | --- |
| `seed_hex` | 32-byte Ed25519 seed (`01 02 ... 20`). TEST ONLY. |
| `pkcs8_b64` | The same key as base64 PKCS8 (the format of `SSO_SIGNING_KEYS`). |
| `kid` | Key id used in the JWS header. |
| `jwks` | Public key as it appears in `/etc/cvl/sso-keys.json` (`kid`, `kty` OKP, `crv` Ed25519, `x`, `status` current). |
| `assertion.claims` / `assertion.jws` | An assertion payload and its compact JWS (`typ` `cvl-sso+jwt`). `aud` is `https://s-ab12cd34.cvengine.live`. |
| `assertion.now` | A unix time at which the assertion is valid (`iat` 1800000100, `exp` = `iat` + 60). |
| `logout.claims` / `logout.jws` | A back-channel logout token (`typ` `cvl-logout+jwt`) and its `now`. |

Expected behaviour of a verifier given `jwks`:

- The assertion verifies at `assertion.now` with audience `https://s-ab12cd34.cvengine.live`, and is rejected for any
  other audience, before `iat - 30 s`, or at or after `exp + 30 s`.
- Header is exactly `{"alg":"EdDSA","typ":"cvl-sso+jwt","kid":"vector-key-1"}` (serialised without spaces); any other
  header member, alg or typ is rejected.
- The signature covers the ASCII bytes of `b64url(header) + "." + b64url(payload)`, 64 bytes, base64url without padding.
- Flipping any bit of header, payload or signature must fail verification.
- The logout token verifies the same way with `typ` `cvl-logout+jwt` and is not accepted as an assertion.

`test/sso-lib.test.mjs` regenerates the vector and fails when the file differs. To rewrite it after an intentional
change: `SSO_WRITE_VECTOR=1 node --test test/sso-lib.test.mjs`.
