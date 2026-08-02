# CryptUtil — Authenticated Encryption (legacy format)

> ⚠️ **This document describes the legacy format** (`EncryptedPayload`, key embedded in the serialized payload). For new code, use `AllCrypto`/`CryptEnvelope` — see [secure-format.md](secure-format.md). `CryptUtil` still works and is the internal base reused by `AllCrypto`, but `EncryptedPayload.toJson()`/`toBase64()` and the `encryptToBase64()`/`decryptFromBase64()` shortcuts are marked `@Deprecated`, with removal planned for `all_crypto` 2.0.0.

`CryptUtil` implements **ChaCha20-Poly1305** (RFC 8439) in pure Dart, with no external dependencies. The algorithm is AEAD (_Authenticated Encryption with Associated Data_): confidentiality + integrity in a single operation. Any tampering — of the ciphertext, the tag, or the AAD — is automatically detected on decryption.

```dart
import 'package:all_crypto/all_crypto.dart';
```

---

## How it works

```
plaintext + key(32B) + nonce(12B) ──► ChaCha20 ──► ciphertext
ciphertext + AAD + key            ──► Poly1305 ──► tag(16B)

Stored result: EncryptedPayload { ciphertext, key, nonce, tag, aad }
```

- **ChaCha20** encrypts the plaintext as a stream using key + nonce.
- **Poly1305** generates a 16-byte authentication tag over the ciphertext and the AAD.
- On decryption, the tag is recomputed and compared in **constant time** — any difference throws `CryptException` before any byte is returned.

---

## Basic usage — text

```dart
// 1. Generate a secure 32-byte key (Random.secure)
final key = CryptUtil.generateKey();

// 2. Encrypt — random nonce generated automatically
final payload = CryptUtil.encryptText('Sensitive data', key: key);

// 3. Decrypt
final text = CryptUtil.decryptText(payload);
print(text); // 'Sensitive data'
```

If `key` is omitted, a random key is generated internally — keep it yourself (`payload.key`) before discarding the reference. If you then call `payload.toJson()`/`toBase64()`, that generated key gets serialized along with the result (see [Key embedded in the payload](#key-embedded-in-the-payload--a-preexisting-flaw-not-a-recommendation) below) — which is almost never what you want.

---

## Basic usage — bytes

```dart
final data = Uint8List.fromList([1, 2, 3, 4, 5]);
final key  = CryptUtil.generateKey();

final payload            = CryptUtil.encryptBytes(data, key: key);
final List<int> restored = CryptUtil.decryptBytes(payload);
```

`encryptBytes` accepts any `List<int>` — including `Uint8List`.

---

## Serialization and storage

### Via base64 (legacy format — embedded key)

> ⚠️ `encryptToBase64`/`decryptFromBase64` and `toJson`/`toBase64` are `@Deprecated`. For new code, use `AllCrypto.encryptText(...).toBase64()` — see [secure-format.md](secure-format.md). The section below documents the legacy format for anyone who still needs to read it.

`encryptToBase64` is a shortcut for `encryptText(...).toBase64()`:

```dart
// Encrypt and serialize as a single string
final encoded = CryptUtil.encryptToBase64('secret', key: key);
// e.g.: 'eyJjaXBoZXJ0ZXh0IjoiL...' (JSON embedded in base64)

// Store `encoded` wherever you want (SharedPreferences, database, API...)

// Restore and decrypt
final original = CryptUtil.decryptFromBase64(encoded);
```

> `decryptFromBase64` throws `FormatException` if `encoded` is not valid base64,
> and `CryptException` if the data was tampered with.

### Via JSON (for APIs and relational databases)

```dart
// Serializes as a Map with every field base64-encoded
final Map<String, dynamic> json = payload.toJson();
// {
//   'ciphertext': '<base64>',
//   'key':        '<base64>',
//   'tag':        '<base64>',
//   'nonce':      '<base64>',
//   'aad':        '<base64>',
// }

// Restore from the Map
final payload2 = EncryptedPayload.fromJson(json);
final text     = CryptUtil.decryptText(payload2);
```

### Directly on EncryptedPayload

`toBase64` and `fromBase64` are also available directly on `EncryptedPayload`:

```dart
final encoded  = payload.toBase64();
final restored = EncryptedPayload.fromBase64(encoded);
```

---

## Key embedded in the payload — a preexisting flaw, not a recommendation

> ⚠️ **`EncryptedPayload.toJson()`/`toBase64()` serialize the key alongside the ciphertext.** Whoever has access to the serialized payload **also has access to the key** and can decrypt the content without needing to know it beforehand. This is **not** at-rest data protection — it is the complete absence of separation between secret and encrypted data. Whatever "protection" exists in that scenario comes entirely from another layer (e.g., the OS sandbox preventing other apps from reading the file), never from the cryptography itself. See [SECURITY.en.md](../../SECURITY.en.md#preexisting-flaw-in-the-legacy-format--key-embedded-in-the-payload) for the full analysis and `test/legacy_vulnerability_test.dart` for the proven reproduction.

```dart
// DO NOT DO THIS in new code — kept only to read historical payloads.
final encoded = CryptUtil.encryptToBase64('local data'); // ⚠️ deprecated
// This Base64 contains the embedded key. Any process, log, or backup
// that captures this value also captures the key.
```

**Use `AllCrypto`/`CryptEnvelope` instead** — see [secure-format.md](secure-format.md). It produces exactly the separation this document used to describe as an "advanced scenario," but as the sole, default path:

```dart
final key = AllCrypto.generateKey();
// Store `key` in flutter_secure_storage / keychain

final envelope = AllCrypto.encryptText('data', key: key);
final noKey = envelope.toBase64(); // never contains the key — always safe

// To decrypt: retrieve the key from the keychain
final text = AllCrypto.decryptText(
  CryptEnvelope.fromBase64(noKey),
  key: key, // retrieved from the keychain
);
```

If you already have legacy payloads in production, migrate them with `AllCrypto.migrateLegacy` (see [secure-format.md](secure-format.md#migrating-legacy-payloads)) instead of continuing to generate new payloads with an embedded key.

---

## With AAD (Additional Authenticated Data)

AAD is **authenticated but not encrypted** — useful for binding metadata to the ciphertext without exposing it encrypted. If the AAD is altered after encryption, `CryptException` is thrown on decryption.

```dart
import 'dart:convert';

// Example: bind the ciphertext to a specific user
final aad     = utf8.encode('user_id:42');
final payload = CryptUtil.encryptText('private data', key: key, aad: aad);

// The AAD is stored in the payload and reused automatically on decryption
final text = CryptUtil.decryptText(payload); // OK

// If someone alters the AAD in the stored payload → CryptException
```

AAD use cases: user identifier, schema version, session ID — any metadata that should not be encrypted, but must guarantee the payload is only accepted in the correct context.

---

## Tamper detection

```dart
try {
  final text = CryptUtil.decryptText(payload);
  print(text);
} on CryptException catch (e) {
  print(e.message);
  // 'Invalid authentication tag. The data may have been
  //  corrupted or the key is incorrect.'
} on FormatException catch (e) {
  // Only in decryptFromBase64 — malformed base64
  print('Invalid base64: $e');
}
```

Tag comparison uses **constant time** (`constantTimeCompare`) — no information leak via timing attack.

---

## EncryptedPayload — full structure

```dart
class EncryptedPayload {
  final Uint8List ciphertext; // encrypted data
  final Uint8List key;        // 32-byte key
  final Uint8List tag;        // 16-byte Poly1305 tag
  final Uint8List nonce;      // 12-byte nonce
  final Uint8List aad;        // AAD (empty if unused)
}
```

| Method | Description |
|--------|-----------|
| `toJson()` | Serializes to `Map<String, dynamic>` with base64 fields |
| `fromJson(map)` | Deserializes from `Map<String, dynamic>` |
| `toBase64()` | Serializes to a base64 string (embedded JSON) |
| `fromBase64(encoded)` | Deserializes from a base64 string |
| `toString()` | `EncryptedPayload(ciphertext: N bytes, key: 32 bytes, ...)` |

---

## CryptException

```dart
class CryptException implements Exception {
  final String message; // descriptive message
  // default: 'Authentication failed.'
}

// Message generated by the algorithm when the tag check fails:
// 'Invalid authentication tag. The data may have been
//  corrupted or the key is incorrect.'

try {
  CryptUtil.decryptText(payload);
} on CryptException catch (e) {
  print(e);         // 'CryptException: Invalid authentication tag...'
  print(e.message); // just the message, no prefix
}
```

---

## Possible exceptions

| Situation | Exception |
|----------|---------|
| Key size ≠ 32 bytes | `ArgumentError` |
| Nonce size ≠ 12 bytes | `ArgumentError` |
| Tampered ciphertext or wrong key | `CryptException` |
| `decryptFromBase64` with invalid base64 | `FormatException` |

---

## API reference — CryptUtil

| Method | Return | Description |
|--------|---------|-----------|
| `encryptText(text, {key?, nonce?, aad?})` | `EncryptedPayload` | Encrypts a String (UTF-8) |
| `decryptText(payload)` | `String` | Decrypts and returns a String |
| `encryptBytes(bytes, {key?, nonce?, aad?})` | `EncryptedPayload` | Encrypts a `List<int>` |
| `decryptBytes(payload)` | `List<int>` | Decrypts and returns bytes |
| `encryptToBase64(text, {key?, nonce?, aad?})` ⚠️`@Deprecated` | `String` | Shortcut: `encryptText(...).toBase64()` — embeds the key |
| `decryptFromBase64(encoded)` ⚠️`@Deprecated` | `String` | Shortcut: `EncryptedPayload.fromBase64(e)` + `decryptText` |
| `generateKey()` | `Uint8List` | Secure 32-byte key (`Random.secure`) |
| `generateNonce()` | `Uint8List` | Secure 12-byte nonce (`Random.secure`) |

---

## Algorithm constants

| Constant | Value | Description |
|-----------|-------|-----------|
| `ChaCha20Poly1305.keyLength` | `32` | Required key size (bytes) |
| `ChaCha20Poly1305.nonceLength` | `12` | Required nonce size (bytes) |
| `ChaCha20Poly1305.tagLength` | `16` | Poly1305 tag size (bytes) |

---

## Best practices

- **Key in a secure location** — use `flutter_secure_storage` / keychain / TEE. Never in plain-text `SharedPreferences`.
- **Don't reuse (key, nonce)** — a repeated nonce with the same key breaks ChaCha20's confidentiality. The automatic default `generateNonce()` eliminates this risk.
- **Always handle `CryptException`** — decrypting without a `try/catch` around `CryptException` can let tampered data pass silently if you don't check the return value.
- **AAD for context** — bind the payload to its usage context (e.g., `userId`, `sessionId`) to prevent a valid payload from being reused in another context.
- **Overhead per payload** — besides the ciphertext, each payload carries 32 (key) + 12 (nonce) + 16 (tag) = 60 extra bytes plus the AAD. Consider this when storing many small payloads.

---

← [Back to README](../../README.en.md)
