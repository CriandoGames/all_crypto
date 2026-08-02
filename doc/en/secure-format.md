# CryptEnvelope + AllCrypto — Recommended Secure Format

`AllCrypto` is the recommended facade for encrypting and decrypting data in this package. Unlike `CryptUtil` (legacy format, see [crypt_util.md](crypt_util.md)), `AllCrypto` produces and consumes `CryptEnvelope` — an envelope that **never serializes the key** and is **explicitly versioned**.

```dart
import 'package:all_crypto/all_crypto.dart';
```

---

## Why a new format

The historical format (`EncryptedPayload.toJson()`/`toBase64()`) includes the `key` field in the serialized JSON. This means any system, log, database, or person that obtains that Base64/JSON also obtains the key and can decrypt the content — the format never provided confidentiality against whoever holds the payload. See `test/legacy_vulnerability_test.dart` for the proven reproduction and [SECURITY.en.md](../../SECURITY.en.md) for the full analysis.

`CryptEnvelope` fixes this: it serializes only the algorithm, ciphertext, nonce/IV, tag, and AAD. The key never appears in `toJson()`/`toBase64()` output — it must be supplied externally (keychain, `flutter_secure_storage`, KMS, a secure environment variable) every time you decrypt.

---

## How it works

```
plaintext + key (external) + nonce ──► chosen algorithm ──► ciphertext + tag

Serializable result: CryptEnvelope { version, algorithm, ciphertext, nonce, tag, aad }
                                      (NO "key" field)
```

Internally, `AllCrypto` reuses the exact same algorithm implementations used by `CryptUtil` (ChaCha20-Poly1305, AES-GCM, AES-CBC, AES-CTR) — no cryptographic logic is duplicated between the two paths.

---

## Basic usage — text

```dart
// 1. Generate a secure 32-byte key and keep it in a safe place
final key = AllCrypto.generateKey();

// 2. Encrypt — random nonce generated automatically
final envelope = AllCrypto.encryptText('Sensitive data', key: key);

// 3. Serialize (does NOT contain the key) — safe to persist, transmit, or log
final b64 = envelope.toBase64();

// 4. Later, with the key retrieved from the external vault:
final restored = CryptEnvelope.fromBase64(b64);
final text = AllCrypto.decryptText(restored, key: key);
print(text); // 'Sensitive data'
```

---

## Basic usage — bytes

```dart
final data = Uint8List.fromList([1, 2, 3, 4, 5]);
final key = AllCrypto.generateKey();

final envelope = AllCrypto.encryptBytes(data, key: key);
final List<int> restored = AllCrypto.decryptBytes(envelope, key: key);
```

---

## Choosing the algorithm

```dart
final envelope = AllCrypto.encryptBytes(
  data,
  key: key,
  algorithm: CryptAlgorithm.aesGcm, // default: CryptAlgorithm.chacha20Poly1305
);
```

| Algorithm | Authenticated (AEAD) | Note |
|---|---|---|
| `CryptAlgorithm.chacha20Poly1305` (default) | ✅ | RFC 8439; recommended for new data |
| `CryptAlgorithm.aesGcm` | ✅ | interoperability with AES systems |
| `CryptAlgorithm.aesCbc` | ❌ | compatibility only; pair with an external HMAC |
| `CryptAlgorithm.aesCtr` | ❌ | compatibility only; pair with an external HMAC |

`AllCrypto` **rejects** a non-empty AAD with AES-CBC/AES-CTR (`ArgumentError`) — those modes don't authenticate, so silently accepting AAD would give a false sense of integrity.

---

## Envelope version

```dart
print(CryptEnvelope.currentVersion); // 2
```

`CryptEnvelope.toJson()` always includes `'version': 2`. `CryptEnvelope.fromJson`/`fromBase64` reject:

- a missing version;
- a version that isn't an integer;
- any version other than `currentVersion` (including `1`, reserved for the keyed legacy format — it is not read by `CryptEnvelope.fromJson`, only by `EncryptedPayload.fromJson`).

```dart
final json = envelope.toJson()..['version'] = 99;
CryptEnvelope.fromJson(json); // throws ArgumentError
```

This makes future format evolutions explicit: a hypothetical version `3` would require updating this package before being able to read the new format, instead of silently decoding fields it doesn't understand.

---

## With AAD (Additional Authenticated Data)

Same idea as the legacy format, but AEAD modes only:

```dart
final aad = utf8.encode('user_id:42');
final envelope = AllCrypto.encryptText('private data', key: key, aad: aad);

final text = AllCrypto.decryptText(envelope, key: key); // OK

// If the envelope's AAD is altered before decryption → CryptException
```

---

## Tamper detection

```dart
try {
  final text = AllCrypto.decryptText(envelope, key: key);
} on CryptException catch (e) {
  print(e.message); // e.g. 'Invalid authentication tag...'
} on FormatException catch (e) {
  // Malformed Base64/JSON in CryptEnvelope.fromBase64
} on ArgumentError catch (e) {
  // Unknown version/algorithm, or invalid key/nonce size
}
```

---

## Migrating legacy payloads

```dart
// 1. Read the historical payload with the legacy API (decoder, not deprecated)
final legacy = EncryptedPayload.fromBase64(oldToken);

// 2. Migrate: splits envelope (no key) and extracted key
final migrated = AllCrypto.migrateLegacy(legacy);

// 3. Persist the envelope normally (it does not contain the key)
final newToken = migrated.envelope.toBase64();

// 4. Move migrated.key to an external vault (flutter_secure_storage, etc.)
//    If the legacy Base64 already circulated outside trusted storage,
//    rotate the key (re-encrypt with a new one) instead of just migrating.
```

`migrateLegacy` neither decrypts nor re-encrypts the data — it only restructures how the key is transported.

---

## `CryptEnvelope` — full structure

```dart
class CryptEnvelope {
  final int version;             // envelope schema; current: 2
  final CryptAlgorithm algorithm;
  final Uint8List ciphertext;
  final Uint8List nonce;         // nonce/IV/ICB, depends on the algorithm
  final Uint8List tag;           // empty for AES-CBC/AES-CTR
  final Uint8List aad;           // empty if unused
  // NO "key" field
}
```

| Method | Description |
|--------|-----------|
| `toJson()` | Serializes to `Map<String, dynamic>` (no key) |
| `fromJson(map)` | Deserializes; rejects unknown version/algorithm |
| `toBase64()` | Serializes to a Base64 string (no key) |
| `fromBase64(encoded)` | Deserializes from a Base64 string |

---

## API reference — AllCrypto

| Method | Return | Description |
|--------|---------|-----------|
| `encryptText(text, {required key, algorithm?, nonce?, aad?})` | `CryptEnvelope` | Encrypts a String (UTF-8) |
| `decryptText(envelope, {required key})` | `String` | Decrypts and returns a String |
| `encryptBytes(bytes, {required key, algorithm?, nonce?, aad?})` | `CryptEnvelope` | Encrypts a `List<int>` |
| `decryptBytes(envelope, {required key})` | `List<int>` | Decrypts and returns bytes |
| `migrateLegacy(legacyPayload)` | `({CryptEnvelope envelope, Uint8List key})` | Migrates a legacy `EncryptedPayload` |
| `generateKey()` | `Uint8List` | Secure 32-byte key |
| `generateKey128()` | `Uint8List` | Secure 16-byte key (AES-128) |
| `generateNonce()` | `Uint8List` | Secure 12-byte nonce |
| `generateIv()` | `Uint8List` | Secure 16-byte IV/ICB |

---

## Best practices

- **Key always external** — never committed, never stored alongside the serialized envelope.
- **Don't reuse (key, nonce)** — leave `nonce` omitted to auto-generate.
- **Prefer AEAD** — ChaCha20-Poly1305 (default) or AES-GCM detect tampering; CBC/CTR don't.
- **Handle `CryptException`, `FormatException`, and `ArgumentError` separately** — each signals a different class of problem (authentication, malformed format, invalid parameter).
- **Migrate legacy payloads** as soon as possible with `migrateLegacy`, and rotate keys that already circulated in the old format.

---

← [Back to README](../../README.en.md) · See also: [crypt_util.md](crypt_util.md) (legacy format)
