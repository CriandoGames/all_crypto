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

## Features

- ChaCha20-Poly1305 (default) and AES-GCM, both AEAD.
- AES-CBC/PKCS#7 and AES-CTR for legacy interoperability.
- SHA-256, HMAC-SHA256, and constant-time MAC comparison.
- `AllCrypto` + `CryptEnvelope` for keyless payloads with a v2 schema.
- Explicit reading and migration of historical `EncryptedPayload` payloads.
- Pure Dart, with no Flutter, native plugins, or production dependencies.

## Installing

```yaml
dependencies:
  all_crypto: ^1.0.0
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## Usage

```dart
final key = AllCrypto.generateKey(); // store in a keychain, KMS, or vault
final envelope = AllCrypto.encryptText('secret', key: key);
final encoded = envelope.toBase64(); // never contains the key

final restored = CryptEnvelope.fromBase64(encoded);
final value = AllCrypto.decryptText(restored, key: key);
```

The same snippet lives in [example/all_crypto_example.dart](https://github.com/CriandoGames/all_crypto/blob/main/example/all_crypto_example.dart)
and is covered under `test/documentation/`.

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

## Documentation

- [Secure format and API](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/secure-format.md)
- [Usage and migration](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/usage.md)
- [`CryptUtil` compatibility](https://github.com/CriandoGames/all_crypto/blob/main/doc/en/crypt_util.md)
- [Security policy](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.en.md)
- [Contributing](https://github.com/CriandoGames/all_crypto/blob/main/CONTRIBUTING.en.md)

[MIT](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE) licensed.
