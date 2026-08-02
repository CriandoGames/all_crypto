import 'dart:typed_data';

import 'package:all_crypto/all_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('CryptException', () {
    test('toString() inclui a mensagem', () {
      const e = CryptException('mensagem customizada');
      expect(e.toString(), 'CryptException: mensagem customizada');
    });

    test('mensagem padrão quando omitida', () {
      const e = CryptException();
      expect(e.message, 'Autenticação falhou.');
    });
  });

  group('EncryptedPayload', () {
    test('toString() resume os tamanhos dos campos', () {
      // ignore: deprecated_member_use_from_same_package
      final payload = CryptUtil.encryptText(
        'x',
        key: CryptUtil.generateKey(),
      );
      final text = payload.toString();
      expect(text, contains('EncryptedPayload('));
      expect(text, contains('algorithm: chacha20-poly1305'));
      expect(text, contains('key: 32 bytes'));
    });
  });

  group('CryptEnvelope', () {
    test('construtor sem tag/aad usa Uint8List(0) por padrão', () {
      final envelope = CryptEnvelope(
        algorithm: CryptAlgorithm.chacha20Poly1305,
        ciphertext: Uint8List.fromList([1, 2, 3]),
        nonce: Uint8List(12),
      );
      expect(envelope.tag, isEmpty);
      expect(envelope.aad, isEmpty);
    });

    test('toString() resume os tamanhos dos campos', () {
      final key = AllCrypto.generateKey();
      final envelope = AllCrypto.encryptText('x', key: key);
      final text = envelope.toString();
      expect(text, contains('CryptEnvelope(version: 2'));
      expect(text, contains('algorithm: chacha20-poly1305'));
    });
  });
}
