# all_crypto

[🇧🇷 Português](https://github.com/CriandoGames/all_crypto/blob/main/README.md) | 🇺🇸 English

[![pub package](https://img.shields.io/pub/v/all_crypto.svg)](https://pub.dev/packages/all_crypto)
[![CI](https://github.com/CriandoGames/all_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/CriandoGames/all_crypto/actions/workflows/ci.yml)
[![pub points](https://img.shields.io/pub/points/all_crypto?label=pub%20points)](https://pub.dev/packages/all_crypto/score)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE)

Authenticated encryption, AES, SHA-256, and HMAC-SHA256 in pure Dart, with a
versioned envelope that never serializes the key and keeps secret management
under application control.

![all_crypto hero](https://raw.githubusercontent.com/CriandoGames/all_crypto/main/documentation/images/hero.png)

## Why use it

Encrypting bytes is only part of the problem: applications must also carry the
algorithm, nonce, tag, and metadata without placing the key next to the
ciphertext. `all_crypto` provides that contract through a pure Dart API and a
versioned envelope designed for persistence or transport.

- Authenticated encryption by default: confidentiality and tamper detection.
- Keys are always supplied externally and never serialized in the v2 envelope.
- One stable format for local databases, backends, queues, or files.
- The same API for text and bytes, with no native plugins or Flutter coupling.
- Primitives for integrity, message authentication, and interoperability.
- Explicit migration for applications that still hold historical payloads.

## Features

- ChaCha20-Poly1305 (default) and AES-GCM, both AEAD.
- AES-CBC/PKCS#7 and AES-CTR for legacy interoperability.
- SHA-256, HMAC-SHA256, and constant-time MAC comparison.
- `AllCrypto` + `CryptEnvelope` for keyless payloads with a v2 schema.
- Explicit reading and migration of historical `EncryptedPayload` payloads.
- Pure Dart, with no Flutter, native plugins, or production dependencies.

## Quick selection

| Need | Recommended API |
|---|---|
| Encrypt new data | `AllCrypto` with ChaCha20-Poly1305, the package default |
| Interoperate with authenticated AES systems | `AllCrypto` with `CryptAlgorithm.aesGcm` |
| Persist or transport ciphertext | `CryptEnvelope.toJson()` or `toBase64()` |
| Encrypt files or binary content | `encryptBytes` and `decryptBytes` |
| Compute an integrity digest | `sha256` |
| Authenticate a message | `hmacSha256` and `hmacEqual` |
| Read historical data | `EncryptedPayload.fromJson`/`fromBase64` |
| Separate the key from a historical payload | `AllCrypto.migrateLegacy`, followed by key rotation |

For new code, use `AllCrypto` and `CryptEnvelope`. `CryptUtil` remains only for
compatibility with existing integrations.

## Installing

```yaml
dependencies:
  all_crypto: ^1.0.1
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## Real-world examples

### Data at rest with an external key

```dart
import 'dart:convert';

import 'package:all_crypto/all_crypto.dart';

final key = AllCrypto.generateKey(); // store in a keychain, KMS, or vault
final aad = utf8.encode('tenant:acme|record:42|schema:1');
final envelope = AllCrypto.encryptText(
  'secret',
  key: key,
  aad: aad,
);
final encoded = envelope.toBase64(); // never contains the key

final restored = CryptEnvelope.fromBase64(encoded);
final value = AllCrypto.decryptText(restored, key: key);
```

AAD is not encrypted, but it is authenticated with the content. It can bind a
ciphertext to a tenant, record, or schema version; changing it makes AEAD
verification fail. Do not put sensitive information in AAD.

### AES-GCM interoperability

```dart
final aesKey = AllCrypto.generateKey();
final order = {'id': 'order_42', 'totalInCents': 15990};
final envelope = AllCrypto.encryptText(
  jsonEncode(order),
  key: aesKey,
  algorithm: CryptAlgorithm.aesGcm,
  aad: utf8.encode('orders:v1'),
);

final token = envelope.toBase64();
```

The receiving system must share the exact protocol: algorithm, key size,
nonce, tag, AAD, and encoding. The envelope organizes these fields, but does
not distribute the key.

### Files and binary content

```dart
final encrypted = AllCrypto.encryptBytes(fileBytes, key: key);
await storage.write(encrypted.toBase64());

final restored = CryptEnvelope.fromBase64(await storage.read());
final originalBytes = AllCrypto.decryptBytes(restored, key: key);
```

### Integrity and message authentication

```dart
final bytes = utf8.encode(payload);
final digest = sha256(bytes); // integrity, not authentication

final expectedMac = hmacSha256(macKey, bytes);
final authentic = hmacEqual(expectedMac, receivedMac);
```

SHA-256 detects accidental changes when the expected digest comes from a
trusted source. HMAC-SHA256 proves knowledge of the shared key; compare tags
with `hmacEqual`.

## Complete example

The [runnable example](https://github.com/CriandoGames/all_crypto/blob/main/example/all_crypto_example.dart) combines workflows that
can be adapted directly to an application:

- a JSON record protected with an external key and AAD;
- AES-GCM interoperability;
- binary content such as attachments and files;
- a SHA-256 digest for comparison with a trusted source;
- webhook signing and verification with HMAC-SHA256;
- rejection of tampered ciphertext through AEAD authentication.

Run it with:

```bash
dart run example/all_crypto_example.dart
```

The example prints verification results only—never keys, plaintext, or tokens—
and its scenarios are covered under `test/documentation/`.

## Secure v2 envelope

`CryptEnvelope.toJson()` produces the fields below, in this order, and has no
`key` field:

```json
{
  "version": 2,
  "algorithm": "chacha20-poly1305",
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "tag": "<base64>",
  "aad": "<base64>"
}
```

The key is required by `AllCrypto.decryptText`/`decryptBytes`. Missing or
unknown versions, unknown algorithms, and invalid structural fields are
rejected; changes to ciphertext, tag, nonce, or AAD fail authentication in
AEAD modes.

## Legacy payload

`EncryptedPayload.toJson()`/`toBase64()` and
`CryptUtil.encryptToBase64()`/`decryptFromBase64()` include the key inside the
payload. This is a preexisting issue in the historical format: anyone with the
Base64 can recover the key and decrypt the content. Base64 is encoding, not
protection.

These APIs remain available for compatibility, are deprecated, and are planned
for removal in `all_crypto` 2.0.0. Do not use them for new data.

```dart
final legacy = EncryptedPayload.fromBase64(oldToken);
final migrated = AllCrypto.migrateLegacy(legacy);

final newToken = migrated.envelope.toBase64(); // no key
final key = migrated.key; // move to an external vault
```

If the legacy payload has left trusted storage, treat its key as compromised
and re-encrypt with a new key.

## Security and limitations

- Prefer ChaCha20-Poly1305 or AES-GCM. CBC and CTR do not authenticate data.
- Never reuse the same key/nonce or key/IV pair.
- Do not log keys, plaintext, sensitive AAD, or complete payloads.
- The package does not provide a vault, key rotation, a password KDF, TLS, or identity.
- The project does not claim an external cryptographic audit.

Read [SECURITY.en.md](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.en.md) before production use.

## When to use it

Use `all_crypto` when you control key management and need to encrypt text or
bytes in pure Dart, store a versioned envelope, authenticate messages, or
interoperate with the provided algorithms. It is suitable for infrastructure
components and libraries that need an explicit cryptographic contract.

Do not use the package as a replacement for TLS, a secret vault, user
authentication, or password derivation. Regulatory requirements and custom
protocols require specialist review. The test suite is extensive, but the
project does not claim an external cryptographic audit.

## Documentation

- [Secure format and API](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/secure-format.md)
- [Usage and migration](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/usage.md)
- [`CryptUtil` compatibility](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/crypt_util.md)
- [Security policy](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.en.md)
- [Contributing](https://github.com/CriandoGames/all_crypto/blob/main/CONTRIBUTING.en.md)

[MIT](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE) licensed.
