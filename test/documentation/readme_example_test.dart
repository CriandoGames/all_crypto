import 'dart:convert';

import 'package:all_crypto/all_crypto.dart';
import 'package:test/test.dart';

void main() {
  test('exemplo principal (README) faz round-trip com CryptEnvelope', () {
    final key = AllCrypto.generateKey();
    final envelope = AllCrypto.encryptText('segredo', key: key);

    final b64 = envelope.toBase64();
    expect(b64.contains(String.fromCharCodes(key)), isFalse);

    final restored = CryptEnvelope.fromBase64(b64);
    expect(AllCrypto.decryptText(restored, key: key), 'segredo');
  });

  test('exemplo executável (example/all_crypto_example.dart) usa AllCrypto',
      () {
    final key = AllCrypto.generateKey();
    final aad = utf8.encode('tenant:demo|record:42|schema:1');
    final envelope = AllCrypto.encryptText(
      'mensagem confidencial',
      key: key,
      aad: aad,
    );
    final b64 = envelope.toBase64();
    final restored = CryptEnvelope.fromBase64(b64);
    final decoded = AllCrypto.decryptText(restored, key: key);

    final digest = sha256(utf8.encode(decoded));
    final macKey = AllCrypto.generateKey();
    final mac = hmacSha256(macKey, utf8.encode(decoded));

    expect(decoded, 'mensagem confidencial');
    expect(restored.aad, aad);
    expect(digest, hasLength(32));
    expect(hmacEqual(mac, hmacSha256(macKey, utf8.encode(decoded))), isTrue);
  });
}
