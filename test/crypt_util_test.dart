import 'dart:convert';
import 'dart:typed_data';

import 'package:all_crypto/all_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('CryptUtil', () {
    late Uint8List key;

    setUp(() {
      key = CryptUtil.generateKey();
    });

    // -------------------------------------------------------------------------
    // generateKey / generateNonce
    // -------------------------------------------------------------------------
    group('generateKey', () {
      test('retorna 32 bytes', () {
        expect(CryptUtil.generateKey().length, 32);
      });

      test('gera valores diferentes a cada chamada', () {
        final k1 = CryptUtil.generateKey();
        final k2 = CryptUtil.generateKey();
        expect(k1, isNot(equals(k2)));
      });
    });

    group('generateNonce', () {
      test('retorna 12 bytes', () {
        expect(CryptUtil.generateNonce().length, 12);
      });

      test('gera valores diferentes a cada chamada', () {
        final n1 = CryptUtil.generateNonce();
        final n2 = CryptUtil.generateNonce();
        expect(n1, isNot(equals(n2)));
      });
    });

    // -------------------------------------------------------------------------
    // encryptText / decryptText
    // -------------------------------------------------------------------------
    group('encryptText / decryptText', () {
      test('round-trip simples', () {
        const plaintext = 'Olá, Brasil!';
        final payload = CryptUtil.encryptText(plaintext, key: key);
        expect(CryptUtil.decryptText(payload), plaintext);
      });

      test('round-trip com string vazia', () {
        final payload = CryptUtil.encryptText('', key: key);
        expect(CryptUtil.decryptText(payload), '');
      });

      test('round-trip com string longa (> 64 bytes)', () {
        final longText = 'A' * 256;
        final payload = CryptUtil.encryptText(longText, key: key);
        expect(CryptUtil.decryptText(payload), longText);
      });

      test('round-trip com caracteres especiais UTF-8', () {
        const text = 'Criptografia: çãõüé 🔒';
        final payload = CryptUtil.encryptText(text, key: key);
        expect(CryptUtil.decryptText(payload), text);
      });

      test('gera nonce aleatório quando não fornecido', () {
        final p1 = CryptUtil.encryptText('teste', key: key);
        final p2 = CryptUtil.encryptText('teste', key: key);
        // Ciphertexts diferentes por nonces diferentes
        expect(p1.nonce, isNot(equals(p2.nonce)));
        expect(p1.ciphertext, isNot(equals(p2.ciphertext)));
      });

      test('aceita nonce fixo', () {
        final nonce = CryptUtil.generateNonce();
        final p1 = CryptUtil.encryptText('teste', key: key, nonce: nonce);
        final p2 = CryptUtil.encryptText('teste', key: key, nonce: nonce);
        expect(p1.ciphertext, equals(p2.ciphertext));
      });

      test('ciphertext é diferente do plaintext', () {
        const text = 'dado secreto';
        final payload = CryptUtil.encryptText(text, key: key);
        expect(payload.ciphertext, isNot(equals(utf8.encode(text))));
      });
    });

    // -------------------------------------------------------------------------
    // encryptBytes / decryptBytes
    // -------------------------------------------------------------------------
    group('encryptBytes / decryptBytes', () {
      test('round-trip com bytes arbitrários', () {
        final data = List<int>.generate(100, (i) => i);
        final payload = CryptUtil.encryptBytes(data, key: key);
        expect(CryptUtil.decryptBytes(payload), equals(data));
      });

      test('round-trip com lista vazia', () {
        final payload = CryptUtil.encryptBytes([], key: key);
        expect(CryptUtil.decryptBytes(payload), isEmpty);
      });
    });

    // -------------------------------------------------------------------------
    // AAD (Additional Authenticated Data)
    // -------------------------------------------------------------------------
    group('AAD', () {
      test('round-trip com AAD', () {
        final aad = utf8.encode('contexto:usuario_42');
        const text = 'dado privado';
        final payload = CryptUtil.encryptText(text, key: key, aad: aad);
        expect(CryptUtil.decryptText(payload), text);
      });

      test('decryptText falha com AAD adulterado', () {
        final aad = utf8.encode('contexto:usuario_42');
        const text = 'dado privado';
        final payload = CryptUtil.encryptText(text, key: key, aad: aad);

        // Adultera o AAD no payload
        final tampered = EncryptedPayload(
          ciphertext: payload.ciphertext,
          key: payload.key,
          tag: payload.tag,
          nonce: payload.nonce,
          aad: Uint8List.fromList(utf8.encode('contexto:usuario_99')),
        );

        expect(
          () => CryptUtil.decryptText(tampered),
          throwsA(isA<CryptException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Detecção de adulteração
    // -------------------------------------------------------------------------
    group('detecção de adulteração', () {
      test('lança CryptException se ciphertext for modificado', () {
        final payload = CryptUtil.encryptText('dado', key: key);

        final tamperedCiphertext = Uint8List.fromList(payload.ciphertext)
          ..[0] ^= 0xFF; // Flipa bits do primeiro byte

        final tampered = EncryptedPayload(
          ciphertext: tamperedCiphertext,
          key: payload.key,
          tag: payload.tag,
          nonce: payload.nonce,
          aad: payload.aad,
        );

        expect(
          () => CryptUtil.decryptText(tampered),
          throwsA(isA<CryptException>()),
        );
      });

      test('lança CryptException se tag for modificada', () {
        final payload = CryptUtil.encryptText('dado', key: key);

        final tamperedTag = Uint8List.fromList(payload.tag)..[0] ^= 0xFF;

        final tampered = EncryptedPayload(
          ciphertext: payload.ciphertext,
          key: payload.key,
          tag: tamperedTag,
          nonce: payload.nonce,
          aad: payload.aad,
        );

        expect(
          () => CryptUtil.decryptText(tampered),
          throwsA(isA<CryptException>()),
        );
      });

      test('lança CryptException se nonce for modificado', () {
        final payload = CryptUtil.encryptText('dado', key: key);

        final tamperedNonce = Uint8List.fromList(payload.nonce)..[0] ^= 0xFF;

        final tampered = EncryptedPayload(
          ciphertext: payload.ciphertext,
          key: payload.key,
          tag: payload.tag,
          nonce: tamperedNonce,
          aad: payload.aad,
        );

        expect(
          () => CryptUtil.decryptText(tampered),
          throwsA(isA<CryptException>()),
        );
      });

      test('lança CryptException com chave errada', () {
        final payload = CryptUtil.encryptText('dado', key: key);

        final wrongKey = CryptUtil.generateKey();
        final tampered = EncryptedPayload(
          ciphertext: payload.ciphertext,
          key: wrongKey,
          tag: payload.tag,
          nonce: payload.nonce,
          aad: payload.aad,
        );

        expect(
          () => CryptUtil.decryptText(tampered),
          throwsA(isA<CryptException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Serialização (toBase64 / fromBase64)
    // -------------------------------------------------------------------------
    group('serialização', () {
      test('toJson / fromJson round-trip', () {
        const text = 'serialização JSON';
        final payload = CryptUtil.encryptText(text, key: key);
        final restored = EncryptedPayload.fromJson(payload.toJson());
        expect(CryptUtil.decryptText(restored), text);
      });

      test('toBase64 / fromBase64 round-trip', () {
        const text = 'serialização base64';
        final payload = CryptUtil.encryptText(text, key: key);
        final encoded = payload.toBase64();
        final restored = EncryptedPayload.fromBase64(encoded);
        expect(CryptUtil.decryptText(restored), text);
      });

      test('encryptToBase64 / decryptFromBase64 round-trip', () {
        const text = 'atalho base64';
        final encoded = CryptUtil.encryptToBase64(text, key: key);
        expect(CryptUtil.decryptFromBase64(encoded), text);
      });

      test('toBase64 retorna string não vazia', () {
        final payload = CryptUtil.encryptText('x', key: key);
        expect(payload.toBase64(), isNotEmpty);
      });

      test('round-trip preserva Unicode e emoji', () {
        const text = 'Olá, 世界 🔐';
        final encoded = CryptUtil.encryptToBase64(text, key: key);
        expect(CryptUtil.decryptFromBase64(encoded), text);
      });

      test('payload legado sem algorithm permanece compatível', () {
        const text = 'formato anterior';
        final json = CryptUtil.encryptText(text, key: key).toJson()
          ..remove('algorithm');
        final restored = EncryptedPayload.fromJson(json);
        expect(restored.algorithm, CryptAlgorithm.chacha20Poly1305);
        expect(CryptUtil.decryptText(restored), text);
      });

      test('algorithm desconhecido é rejeitado', () {
        final json = CryptUtil.encryptText('x', key: key).toJson()
          ..['algorithm'] = 'versao-desconhecida';
        expect(
          () => EncryptedPayload.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('payload base64 truncado é rejeitado', () {
        final encoded = CryptUtil.encryptText('x', key: key).toBase64();
        expect(
          () => EncryptedPayload.fromBase64(encoded.substring(0, 12)),
          throwsA(isA<FormatException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Validação de parâmetros
    // -------------------------------------------------------------------------
    group('validação de parâmetros', () {
      test('lança ArgumentError com chave de tamanho errado', () {
        final badKey = Uint8List(16); // deve ser 32
        expect(
          () => CryptUtil.encryptText('x', key: badKey),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('lança ArgumentError com nonce de tamanho errado', () {
        final badNonce = Uint8List(8); // deve ser 12
        expect(
          () => CryptUtil.encryptText('x', key: key, nonce: badNonce),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Geração automática de material quando key/nonce/iv são omitidos
    // -------------------------------------------------------------------------
    group('geração automática quando parâmetros são omitidos', () {
      test('encryptBytes gera key e nonce quando ambos omitidos', () {
        final payload = CryptUtil.encryptBytes([1, 2, 3]);
        expect(payload.key.length, 32);
        expect(payload.nonce.length, 12);
        expect(CryptUtil.decryptBytes(payload), equals([1, 2, 3]));
      });

      test('encryptAesGcm gera key e nonce quando ambos omitidos', () {
        final payload = CryptUtil.encryptAesGcm([4, 5, 6]);
        expect(payload.key.length, 32);
        expect(payload.nonce.length, 12);
        expect(CryptUtil.decryptAesGcm(payload), equals([4, 5, 6]));
      });

      test('encryptAesCbc gera key e iv quando ambos omitidos', () {
        final payload = CryptUtil.encryptAesCbc([7, 8, 9]);
        expect(payload.key.length, 32);
        expect(payload.nonce.length, 16);
        expect(CryptUtil.decryptAesCbc(payload), equals([7, 8, 9]));
      });

      test(
          'encryptAesCtr gera key e initialCounterBlock quando ambos '
          'omitidos', () {
        final payload = CryptUtil.encryptAesCtr([10, 11, 12]);
        expect(payload.key.length, 32);
        expect(payload.nonce.length, 16);
        expect(CryptUtil.decryptAesCtr(payload), equals([10, 11, 12]));
      });
    });
  });
}
