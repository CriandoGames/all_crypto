# Changelog

## Unreleased

- **Security fix (preexisting format issue, not a regression from the extraction)**: `EncryptedPayload.toJson()`/`toBase64()` serialized the symmetric key alongside the ciphertext, so whoever held the payload could decrypt it. Added `CryptEnvelope` — a secure, versioned format (explicit `version` field, currently `2`) that never serializes the key — and the `AllCrypto` facade (`encryptText`, `decryptText`, `encryptBytes`, `decryptBytes`, `migrateLegacy`, `generateKey`, `generateKey128`, `generateNonce`, `generateIv`).
- `CryptEnvelope.fromJson`/`fromBase64` reject a missing/unknown version and an unknown algorithm with a clear `ArgumentError`.
- `EncryptedPayload.toJson()`, `EncryptedPayload.toBase64()`, `CryptUtil.encryptToBase64()`, and `CryptUtil.decryptFromBase64()` marked `@Deprecated`, with a message explaining the issue, the replacement, and the correct package/import. Kept functional for compatibility and reading historical payloads — no removal in this release.
- `AllCrypto.migrateLegacy` converts a legacy `EncryptedPayload` into a `CryptEnvelope` plus the key extracted separately.
- New tests: reproduction of the preexisting flaw (`test/legacy_vulnerability_test.dart`), the official RFC 8439 §2.8.2 vector for ChaCha20-Poly1305 (`test/vectors/rfc8439_test.dart`), differential tests cross-verified against OpenSSL/Node.js (`test/differential/openssl_cross_check_test.dart`), a full `CryptEnvelope`/`AllCrypto` suite — per-algorithm round-trip, tampering, invalid key/nonce, malformed/truncated payload, migration, a frozen historical Base64 fixture (`test/crypt_envelope_test.dart`).
- PT-BR/EN documentation updated and equalized: `README.md`/`README.en.md` (motivation, badges, recommended vs. legacy format), `SECURITY.md`/`SECURITY.en.md` (preexisting flaw, versioning, CBC/CTR limits, what not to log), new `doc/pt-BR/formato-seguro.md` + `doc/en/secure-format.md`, `doc/pt-BR/crypt_util.md` corrected to stop recommending the embedded-key pattern + new `doc/en/crypt_util.md` (previously only a minimal summary existed in English), `doc/pt-BR/uso.md`/`doc/en/usage.md` updated.
- Main example (`example/all_crypto_example.dart`) and documentation test updated to use exclusively `AllCrypto`/`CryptEnvelope`.

## 1.0.0

- Extracted the cryptographic implementation from `all_validations_br` 4.5.2.
- Preserved `CryptUtil`, payloads, algorithms, and existing formats.
- Added vector, round-trip, tampering, wrong-key, and invalid-size tests.
- Added bilingual documentation and security guidance.

