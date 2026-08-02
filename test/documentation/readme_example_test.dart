import 'dart:convert';
import 'dart:typed_data';

import 'package:all_crypto/all_crypto.dart';
import 'package:test/test.dart';

import '../../example/all_crypto_example.dart' as example;

void main() {
  group('exemplo executável', () {
    test('protege e restaura um registro com chave externa e AAD', () {
      final key = AllCrypto.generateKey();
      final token = example.protectCustomerRecord(key);
      final envelope = CryptEnvelope.fromBase64(token);
      final record = example.restoreCustomerRecord(token, key);

      expect(record, containsPair('id', 42));
      expect(record, containsPair('plan', 'pro'));
      expect(utf8.decode(envelope.aad), contains('collection:customers'));
      expect(envelope.toJson(), isNot(contains('key')));
    });

    test('interopera com AES-GCM usando envelope serializado', () {
      final key = AllCrypto.generateKey();
      final token = example.protectOrderWithAesGcm(key);
      final envelope = CryptEnvelope.fromBase64(token);

      expect(envelope.algorithm, CryptAlgorithm.aesGcm);
      expect(example.restoreOrder(token, key), containsPair('status', 'paid'));
    });

    test('protege conteúdo binário sem alterar os bytes', () {
      final key = AllCrypto.generateKey();
      final original = Uint8List.fromList([0, 1, 2, 127, 128, 254, 255]);

      final token = example.protectAttachment(original, key);
      final restored = example.restoreAttachment(token, key);

      expect(restored, orderedEquals(original));
      expect(example.trustedContentDigest(restored), hasLength(32));
    });

    test('HMAC aceita mensagem original e rejeita mensagem alterada', () {
      final key = AllCrypto.generateKey();
      final body = utf8.encode('{"event":"invoice.paid"}');
      final signature = example.signWebhook(body, key);

      expect(example.verifyWebhook(body, signature, key), isTrue);
      expect(
        example.verifyWebhook(
            utf8.encode('{"event":"invoice.refunded"}'), signature, key),
        isFalse,
      );
    });

    test('AEAD rejeita ciphertext adulterado', () {
      final key = AllCrypto.generateKey();
      final token = example.protectCustomerRecord(key);

      expect(example.rejectsTamperedToken(token, key), isTrue);
    });
  });
}
