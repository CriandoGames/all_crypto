# Security

## Recommended format: `CryptEnvelope` + `AllCrypto`

Use `AllCrypto.encryptText`/`encryptBytes` to encrypt and `AllCrypto.decryptText`/`decryptBytes` to decrypt. The result is a `CryptEnvelope`, which serializes **only** the algorithm, ciphertext, nonce/IV, tag, and AAD — the key is **never** included in `toJson()`/`toBase64()`. Every decryption requires the key as an explicit parameter, supplied by you from an external vault (`flutter_secure_storage`, OS keychain, KMS, a secure environment variable). The envelope carries an explicit `version` field (currently `2`); `CryptEnvelope.fromJson`/`fromBase64` reject a missing, non-numeric, or unsupported version, and reject unknown algorithms — always with a clear `ArgumentError`, never silent decoding.

## Preexisting flaw in the legacy format — key embedded in the payload

`EncryptedPayload.toJson()`/`toBase64()` (and the `CryptUtil.encryptToBase64()`/`decryptFromBase64()` shortcuts) serialize the symmetric key **inside** the encrypted payload itself. This is a **preexisting** behavior from before this package's extraction (inherited from the `all_validations_br` aggregator), reproduced and proven in `test/legacy_vulnerability_test.dart`: anyone who obtains the legacy Base64/JSON can extract the key and decrypt the content, without needing to know it beforehand. This format **never provided confidentiality against whoever holds the payload** — in practice, it only protects data when the storage itself is already the security boundary (e.g., a mobile app keeping the Base64 in its disk sandbox, where the OS prevents other apps from reading the file).

These APIs remain available and still decode historical payloads correctly (they were not removed, nor was the format silently changed), but they are marked `@Deprecated` with a message explaining the issue and pointing to the replacement. **Do not use the legacy format in new code.** Use `AllCrypto.migrateLegacy` to convert an existing `EncryptedPayload` into a `CryptEnvelope` (no key) plus the key extracted separately — and consider rotating the key if the legacy Base64 has already circulated outside trusted storage.

Removal is planned for `all_crypto` 2.0.0 (semver compatibility policy).

## Envelope versioning

`CryptEnvelope.version` is the schema of the serialized format, independent of the Dart package version (`pubspec.yaml`) — the two numbers evolve separately. Current version: `2`. The legacy format (`EncryptedPayload`, no version field) is treated as "v1" only for migration/documentation purposes; it never actually had a real `version` field, and that gap is also reproduced in a test.

## Protection scope

ChaCha20-Poly1305 and AES-GCM can provide confidentiality and integrity when used with strong secret keys, managed outside the payload, and unique nonces. HMAC-SHA256 authenticates messages. SHA-256 produces digests. AES-CBC and AES-CTR only provide confidentiality and require independent authentication (see below).

## AES-CBC and AES-CTR — limits of the unauthenticated modes

Neither AES-CBC nor AES-CTR produce an authentication tag — the `tag` field of these payloads/envelopes is always empty. This means:

- tampered CBC ciphertext can decrypt to corrupted data that is silently accepted (a broken PKCS#7 padding does not always raise an error for every tampering pattern) and is never detected by the cryptography itself — only by the application, if it validates the content;
- tampered CTR ciphertext decrypts to a plaintext altered at the corresponding bytes, with no error signal at all — CTR is simply XOR with the keystream, so bit flips in the ciphertext become predictable bit flips in the plaintext;
- reusing the same (key, IV/counter) pair in CTR completely defeats confidentiality for both ciphertexts (XORing the two ciphertexts reveals the XOR of the two plaintexts).

For any scenario where tampering is a relevant threat — the common case — prefer ChaCha20-Poly1305 or AES-GCM (AEAD). If you must interoperate with CBC/CTR because of an external system, pair it with a clearly specified encrypt-then-MAC protocol (e.g., HMAC-SHA256 over the ciphertext, verified in constant time before decrypting) — do not invent your own composition without expert review.

## Out of scope

The package does not store, distribute, rotate, or revoke keys; replace TLS; authenticate users; act as a secret manager; or provide a dedicated password key-derivation function. Plain SHA-256 and the legacy `HelperUtil` password hash are unsuitable for password storage.

## Keys, nonces, and IVs

- Generate keys with `AllCrypto.generateKey()`/`generateKey128()` (secure random source) and keep them out of source code, out of the repository, and — in the recommended format — out of the encrypted payload itself.
- Never reuse a nonce/counter with the same key for ChaCha20-Poly1305, AES-GCM, or AES-CTR. Let the API generate the nonce automatically (omit `nonce`) whenever possible.
- AES-CBC needs an unpredictable IV; an IV is not a key and does not need to be secret, only unique and unpredictable per message.
- Enforce the length requirements of the API (the API itself rejects invalid sizes with `ArgumentError`) and plan key rotation before persisting data for long periods.

## Logs and errors

Do not log keys, sensitive-context nonces, plaintext, passwords, tokens, full payment-card numbers, full CPF/CNPJ values, or the complete cryptographic payload (a full `CryptEnvelope`/`EncryptedPayload`, including as a string/Base64) in application logs, crash reporters, or telemetry. Exception messages (`CryptException.message`, `ArgumentError` messages) are for internal diagnostics, not authorization decisions or direct end-user display.

## Limitations and audit status

The test suite includes published vectors (RFC 8439 for ChaCha20-Poly1305, NIST SP 800-38A/38D and FIPS 197 for AES, RFC 4231 for HMAC-SHA256, NIST for SHA-256), negative tests (tampering, wrong key, invalid sizes, truncated/malformed payload, unknown version and algorithm), and differential tests cross-verified against the OpenSSL backend exposed by Node.js's `crypto` module — but this **is not equivalent to a formal external audit**. The project does not claim to be audited or automatically suitable for any regulatory requirement (GDPR/LGPD, PCI-DSS, etc.); assess fitness for your use case with your own experts.

## Responsible disclosure

Do not publish exploitable details in a public issue. Use the GitHub repository's private security channel or contact the maintainer through the publisher profile. Include version, algorithm, impact, a minimal reproduction without real data, and a suggested mitigation. Coordinate before public disclosure.
