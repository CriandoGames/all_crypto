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
    final envelope = AllCrypto.encryptText('mensagem confidencial', key: key);
    final b64 = envelope.toBase64();
    final restored = CryptEnvelope.fromBase64(b64);
    final decoded = AllCrypto.decryptText(restored, key: key);
    expect(decoded, 'mensagem confidencial');
  });
}
