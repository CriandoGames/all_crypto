# all_crypto

[🇧🇷 Português](README.md) | 🇺🇸 English

[![Dart](https://img.shields.io/badge/Dart-3.0%2B-0175C2)](https://dart.dev)
[![Pure Dart](https://img.shields.io/badge/Flutter-not%20required-informational)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Keyless envelope](https://img.shields.io/badge/CryptEnvelope-never%20serializes%20the%20key-success)](#recommended-format-cryptenvelope--allcrypto)

Pure Dart cryptography and hashing extracted from `all_validations_br`, usable independently without Flutter.

## Motivation

This package exists to provide authenticated encryption (AEAD) and hashing in pure Dart, with no Flutter dependency, no native plugins, and no reimplementation across every project in the `all_validations_br` ecosystem. The extraction was also the opportunity to fix a preexisting issue in the original payload format: `EncryptedPayload.toJson()`/`toBase64()` serialized the symmetric key alongside the ciphertext, which never provided confidentiality against anyone who obtained the payload. As of this version, the package has a recommended format — `CryptEnvelope`, produced by the `AllCrypto` facade — that **never serializes the key** and is **explicitly versioned**. The old format still works (compatibility), but it is now marked legacy. See [SECURITY.en.md](SECURITY.en.md) for the full account.

## Features

- ChaCha20-Poly1305 and AES-GCM authenticated encryption.
- AES-CBC with PKCS#7 and AES-CTR for legacy interoperability.
- SHA-256 and HMAC-SHA256.
- `CryptEnvelope`: **secure, versioned** envelope (key never serialized) — recommended format, via `AllCrypto`.
- `EncryptedPayload`: **legacy** format (key embedded in the payload), kept for compatibility and marked deprecated at its serialization points.
- Explicit migration from legacy payloads to the new format (`AllCrypto.migrateLegacy`).
- Compatibility with the historical `CryptUtil` API and existing payloads.

## Installation

```yaml
dependencies:
  all_crypto: ^1.0.0
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## First example — recommended format

```dart
final key = AllCrypto.generateKey();               // keep it in a secure vault (keychain, etc.)
final envelope = AllCrypto.encryptText('secret', key: key);
final b64 = envelope.toBase64();                    // does NOT contain the key — safe to persist/log

// ... later, with the key retrieved from the vault:
final restored = CryptEnvelope.fromBase64(b64);
final plainText = AllCrypto.decryptText(restored, key: key);
```

The executable example is in `example/all_crypto_example.dart`, and the snippet is covered by a test in `test/documentation/readme_example_test.dart`.

## Recommended format: `CryptEnvelope` + `AllCrypto`

`CryptEnvelope` serializes **only** the algorithm, ciphertext, nonce/IV, tag, and AAD — never the key. The key must be managed externally (`flutter_secure_storage`, keychain, KMS) and supplied explicitly for every decryption via `AllCrypto`. The envelope carries an explicit `version` field (currently `2`); unknown versions are rejected with a clear `ArgumentError`, as are unknown algorithms.

```dart
final envelope = AllCrypto.encryptBytes(
  data,
  key: key,
  algorithm: CryptAlgorithm.aesGcm, // default: chacha20Poly1305
  aad: utf8.encode('user_id:42'),   // optional, AEAD modes only
);
final original = AllCrypto.decryptBytes(envelope, key: key);
```

See [doc/en/secure-format.md](doc/en/secure-format.md) for the full reference.

## Legacy format: `CryptUtil` + `EncryptedPayload`

Preserved for compatibility. `EncryptedPayload.toJson()`/`toBase64()` and the `CryptUtil.encryptToBase64()`/`decryptFromBase64()` shortcuts are marked `@Deprecated` — they keep working, but **should not be used in new code** because they embed the key in the serialized payload. Use them only to read data already emitted in that format, and migrate with `AllCrypto.migrateLegacy`:

```dart
final legacy = EncryptedPayload.fromBase64(oldToken); // reads a historical payload
final migrated = AllCrypto.migrateLegacy(legacy);      // splits envelope and key
// migrated.envelope -> persist/transmit (no key)
// migrated.key      -> move to an external vault
```

See [doc/en/crypt_util.md](doc/en/crypt_util.md) for the full legacy-format reference.

## Algorithms

| Feature | Recommended use | Note |
|---|---|---|
| ChaCha20-Poly1305 | default for new data | AEAD; authenticates ciphertext and AAD |
| AES-GCM | AEAD interoperability | 12-byte nonce |
| AES-CBC | legacy compatibility | unauthenticated; pair with a MAC at protocol level |
| AES-CTR | compatibility/streaming | unauthenticated; never reuse a counter with the same key |
| SHA-256 | digest | neither encryption nor password storage |
| HMAC-SHA256 | authentication | requires a suitable secret key |

## Errors

Structurally invalid inputs, an unknown envelope version, or an unknown algorithm throw `ArgumentError`. Authentication failures, incompatible payloads, or invalid cryptographic formats throw `CryptException`. Malformed Base64/JSON throws `FormatException`. Do not make error text part of a security protocol.

## Compatibility and migration

Previous code:

```dart
import 'package:all_validations_br/crypt.dart';
```

New code:

```dart
import 'package:all_crypto/all_crypto.dart';
```

The `CryptUtil` name and methods remain available — the aggregator keeps re-exporting this API. For new data, prefer `AllCrypto`/`CryptEnvelope`; see the migration section above.

## Performance

The implementation is pure Dart and prioritizes portability and verifiable behavior. Benchmark on the actual device and workload before selecting it for intensive processing; no hardware-acceleration guarantee is made.

## Security

Read [SECURITY.en.md](SECURITY.en.md). Prefer `AllCrypto`/`CryptEnvelope` and AEAD algorithms, generate nonces/IVs through the API, keep keys outside source code, and never log keys, sensitive plaintext, or full payloads. This project does not claim an external cryptographic audit.

## Limitations

- No key vault, rotation service, password KDF, TLS, or identity-signature protocol is provided.
- AES-CBC and AES-CTR do not authenticate data on their own.
- System security depends on consumer key management and protocol design.

## Roadmap

The roadmap prioritizes additional interoperability vectors, documented formats, and explicit migrations without breaking existing payloads. Re-evaluating this package's publish-readiness after this security review is the responsibility of whichever AI/maintainer picks up the next handoff — see `HANDOFF_1_CRYPTO_FORMS.md`.

## Contributing, license, and ecosystem

See [CONTRIBUTING.en.md](CONTRIBUTING.en.md). MIT licensed under [LICENSE](LICENSE). This package belongs to the `all_validations_br` ecosystem but does not depend on its aggregator, Flutter, logging, validations, or `Result`.

