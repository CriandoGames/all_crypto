import 'dart:convert';
import 'dart:typed_data';

import 'package:all_crypto/all_crypto.dart';
import 'package:test/test.dart';

void main() {
  group('CryptEnvelope — formato seguro versionado', () {
    late Uint8List key;

    setUp(() {
      key = AllCrypto.generateKey();
    });

    // -------------------------------------------------------------------------
    // Versão
    // -------------------------------------------------------------------------
    group('versão', () {
      test('nunca serializa a chave em toJson()', () {
        final envelope = AllCrypto.encryptText('segredo', key: key);
        expect(envelope.toJson().containsKey('key'), isFalse);
      });

      test('nunca serializa a chave em toBase64()', () {
        final envelope = AllCrypto.encryptText('segredo', key: key);
        final decoded = utf8.decode(base64.decode(envelope.toBase64()));
        expect(decoded.contains(base64.encode(key)), isFalse);
      });

      test('toJson() inclui "version": 2', () {
        final envelope = AllCrypto.encryptText('x', key: key);
        expect(envelope.toJson()['version'], 2);
        expect(envelope.version, 2);
        expect(CryptEnvelope.currentVersion, 2);
      });

      test('fromJson rejeita versão ausente', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..remove('version');
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromJson rejeita versão não inteira', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['version'] = '2';
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromJson rejeita versão desconhecida (0)', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['version'] = 0;
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromJson rejeita versão desconhecida (1 — formato legado)', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['version'] = 1;
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromJson rejeita versão futura desconhecida (99)', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['version'] = 99;
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromBase64 também rejeita versão desconhecida', () {
        final envelope = AllCrypto.encryptText('x', key: key);
        final json = envelope.toJson()..['version'] = 42;
        final tamperedB64 = base64.encode(utf8.encode(jsonEncode(json)));
        expect(
          () => CryptEnvelope.fromBase64(tamperedB64),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('construtor rejeita versão desconhecida', () {
        expect(
          () => CryptEnvelope(
            version: 3,
            algorithm: CryptAlgorithm.chacha20Poly1305,
            ciphertext: Uint8List(0),
            nonce: Uint8List(12),
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Algoritmo
    // -------------------------------------------------------------------------
    group('algoritmo', () {
      test('fromJson rejeita algoritmo desconhecido', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['algorithm'] = 'algoritmo-inexistente';
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('fromJson rejeita algoritmo ausente com FormatException', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..remove('algorithm');
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<FormatException>()),
        );
      });

      test('AllCrypto.encryptBytes aceita algorithm explícito (aes-gcm)', () {
        final envelope = AllCrypto.encryptBytes(
          [1, 2, 3],
          key: key,
          algorithm: CryptAlgorithm.aesGcm,
        );
        expect(envelope.algorithm, CryptAlgorithm.aesGcm);
        expect(envelope.toJson()['algorithm'], 'aes-gcm');
      });

      test('AES-CBC/AES-CTR rejeitam AAD não vazio (modo não autenticado)', () {
        expect(
          () => AllCrypto.encryptBytes(
            [1, 2, 3],
            key: Uint8List(32),
            algorithm: CryptAlgorithm.aesCbc,
            aad: utf8.encode('meta'),
          ),
          throwsA(isA<ArgumentError>()),
        );
        expect(
          () => AllCrypto.encryptBytes(
            [1, 2, 3],
            key: Uint8List(32),
            algorithm: CryptAlgorithm.aesCtr,
            aad: utf8.encode('meta'),
          ),
          throwsA(isA<ArgumentError>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Round-trip — todos os algoritmos
    // -------------------------------------------------------------------------
    group('round-trip por algoritmo', () {
      for (final algorithm in CryptAlgorithm.values) {
        test('${algorithm.value} — texto simples', () {
          final envelope = AllCrypto.encryptText(
            'dado confidencial',
            key: key,
            algorithm: algorithm,
          );
          expect(envelope.algorithm, algorithm);
          expect(
            AllCrypto.decryptText(envelope, key: key),
            'dado confidencial',
          );
        });

        test('${algorithm.value} — bytes arbitrários', () {
          final data = List<int>.generate(80, (i) => i % 256);
          final envelope =
              AllCrypto.encryptBytes(data, key: key, algorithm: algorithm);
          expect(AllCrypto.decryptBytes(envelope, key: key), equals(data));
        });

        test('${algorithm.value} — vazio', () {
          final envelope =
              AllCrypto.encryptBytes([], key: key, algorithm: algorithm);
          expect(AllCrypto.decryptBytes(envelope, key: key), isEmpty);
        });

        test('${algorithm.value} — Unicode e emoji', () {
          const text = 'Olá, 世界 🔐🇧🇷';
          final envelope = AllCrypto.encryptText(
            text,
            key: key,
            algorithm: algorithm,
          );
          expect(AllCrypto.decryptText(envelope, key: key), text);
        });

        test('${algorithm.value} — toJson/fromJson round-trip', () {
          final envelope = AllCrypto.encryptText(
            'json',
            key: key,
            algorithm: algorithm,
          );
          final restored = CryptEnvelope.fromJson(envelope.toJson());
          expect(AllCrypto.decryptText(restored, key: key), 'json');
        });

        test('${algorithm.value} — toBase64/fromBase64 round-trip', () {
          final envelope = AllCrypto.encryptText(
            'base64',
            key: key,
            algorithm: algorithm,
          );
          final restored = CryptEnvelope.fromBase64(envelope.toBase64());
          expect(AllCrypto.decryptText(restored, key: key), 'base64');
        });
      }
    });

    // -------------------------------------------------------------------------
    // Chave errada / tamanhos inválidos
    // -------------------------------------------------------------------------
    group('chave', () {
      test('chave errada falha na decifragem (AEAD → CryptException)', () {
        final envelope = AllCrypto.encryptText('dado', key: key);
        final wrongKey = AllCrypto.generateKey();
        expect(
          () => AllCrypto.decryptText(envelope, key: wrongKey),
          throwsA(isA<CryptException>()),
        );
      });

      test('chave de tamanho inválido → ArgumentError', () {
        expect(
          () => AllCrypto.encryptText('x', key: Uint8List(5)),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('AES-GCM aceita chave de 16 bytes (AES-128)', () {
        final key128 = AllCrypto.generateKey128();
        final envelope = AllCrypto.encryptText(
          'aes-128',
          key: key128,
          algorithm: CryptAlgorithm.aesGcm,
        );
        expect(AllCrypto.decryptText(envelope, key: key128), 'aes-128');
      });
    });

    group('geração de material — AllCrypto', () {
      test('generateNonce retorna 12 bytes', () {
        expect(AllCrypto.generateNonce().length, 12);
      });

      test('generateIv retorna 16 bytes', () {
        expect(AllCrypto.generateIv().length, 16);
      });
    });

    // -------------------------------------------------------------------------
    // Nonce/IV inválido
    // -------------------------------------------------------------------------
    group('nonce/IV', () {
      test('nonce de tamanho inválido → ArgumentError (ChaCha20)', () {
        expect(
          () => AllCrypto.encryptText('x', key: key, nonce: Uint8List(4)),
          throwsA(isA<ArgumentError>()),
        );
      });

      test('gera nonce aleatório quando omitido', () {
        final e1 = AllCrypto.encryptText('mesmo texto', key: key);
        final e2 = AllCrypto.encryptText('mesmo texto', key: key);
        expect(e1.nonce, isNot(equals(e2.nonce)));
        expect(e1.ciphertext, isNot(equals(e2.ciphertext)));
      });
    });

    // -------------------------------------------------------------------------
    // Adulteração
    // -------------------------------------------------------------------------
    group('adulteração', () {
      CryptEnvelope tamper(
        CryptEnvelope e, {
        Uint8List? ciphertext,
        Uint8List? tag,
        Uint8List? nonce,
        Uint8List? aad,
      }) =>
          CryptEnvelope(
            version: e.version,
            algorithm: e.algorithm,
            ciphertext: ciphertext ?? e.ciphertext,
            nonce: nonce ?? e.nonce,
            tag: tag ?? e.tag,
            aad: aad ?? e.aad,
          );

      test('ciphertext adulterado → CryptException', () {
        final envelope = AllCrypto.encryptText('dado', key: key);
        final bad = tamper(
          envelope,
          ciphertext: Uint8List.fromList(envelope.ciphertext)..[0] ^= 0xff,
        );
        expect(
          () => AllCrypto.decryptText(bad, key: key),
          throwsA(isA<CryptException>()),
        );
      });

      test('tag adulterada → CryptException', () {
        final envelope = AllCrypto.encryptText('dado', key: key);
        final bad = tamper(
          envelope,
          tag: Uint8List.fromList(envelope.tag)..[0] ^= 0xff,
        );
        expect(
          () => AllCrypto.decryptText(bad, key: key),
          throwsA(isA<CryptException>()),
        );
      });

      test('nonce adulterado → CryptException (AEAD)', () {
        final envelope = AllCrypto.encryptText('dado', key: key);
        final bad = tamper(
          envelope,
          nonce: Uint8List.fromList(envelope.nonce)..[0] ^= 0xff,
        );
        expect(
          () => AllCrypto.decryptText(bad, key: key),
          throwsA(isA<CryptException>()),
        );
      });

      test('AAD adulterado → CryptException', () {
        final aad = utf8.encode('contexto:42');
        final envelope = AllCrypto.encryptText('dado', key: key, aad: aad);
        final bad = tamper(
          envelope,
          aad: Uint8List.fromList(utf8.encode('contexto:99')),
        );
        expect(
          () => AllCrypto.decryptText(bad, key: key),
          throwsA(isA<CryptException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Payload truncado / malformado
    // -------------------------------------------------------------------------
    group('payload malformado', () {
      test('base64 truncado → FormatException', () {
        final b64 = AllCrypto.encryptText('x', key: key).toBase64();
        expect(
          () => CryptEnvelope.fromBase64(b64.substring(0, 10)),
          throwsA(isA<FormatException>()),
        );
      });

      test('base64 não é base64 válido → FormatException', () {
        expect(
          () => CryptEnvelope.fromBase64('%%% não é base64 %%%'),
          throwsA(isA<FormatException>()),
        );
      });

      test('JSON interno malformado (não é Map) → FormatException', () {
        final b64 = base64.encode(utf8.encode(jsonEncode([1, 2, 3])));
        expect(
          () => CryptEnvelope.fromBase64(b64),
          throwsA(isA<FormatException>()),
        );
      });

      test('campo ciphertext ausente → FormatException', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..remove('ciphertext');
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<FormatException>()),
        );
      });

      test('campos binários obrigatórios ausentes → FormatException', () {
        for (final field in ['nonce', 'tag', 'aad']) {
          final json = AllCrypto.encryptText('x', key: key).toJson()
            ..remove(field);
          expect(
            () => CryptEnvelope.fromJson(json),
            throwsA(isA<FormatException>()),
            reason: field,
          );
        }
      });

      test('campo ciphertext com base64 inválido → FormatException', () {
        final json = AllCrypto.encryptText('x', key: key).toJson()
          ..['ciphertext'] = 'não-é-base64!!';
        expect(
          () => CryptEnvelope.fromJson(json),
          throwsA(isA<FormatException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // AES-CBC: payload truncado / tamanho inválido
    // -------------------------------------------------------------------------
    group('AES-CBC — payload truncado', () {
      test('ciphertext com tamanho não múltiplo de 16 → CryptException', () {
        final envelope = AllCrypto.encryptBytes(
          List.generate(50, (i) => i),
          key: key,
          algorithm: CryptAlgorithm.aesCbc,
        );
        final truncated = CryptEnvelope(
          version: envelope.version,
          algorithm: envelope.algorithm,
          ciphertext:
              envelope.ciphertext.sublist(0, envelope.ciphertext.length - 3),
          nonce: envelope.nonce,
          tag: envelope.tag,
          aad: envelope.aad,
        );
        expect(
          () => AllCrypto.decryptBytes(truncated, key: key),
          throwsA(isA<CryptException>()),
        );
      });
    });

    // -------------------------------------------------------------------------
    // Migração do formato legado
    // -------------------------------------------------------------------------
    group('migração legado → CryptEnvelope', () {
      test('migra payload legado preservando o resultado decifrado', () {
        const secret = 'dado migrado do formato antigo';
        final legacy = CryptUtil.encryptText(secret, key: key);

        final migrated = AllCrypto.migrateLegacy(legacy);

        expect(migrated.envelope.toJson().containsKey('key'), isFalse);
        expect(migrated.key, equals(key));
        expect(
          AllCrypto.decryptText(migrated.envelope, key: migrated.key),
          secret,
        );
      });

      test('migração preserva algoritmo original (AES-GCM)', () {
        final legacy = CryptUtil.encryptAesGcm([1, 2, 3], key: key);
        final migrated = AllCrypto.migrateLegacy(legacy);
        expect(migrated.envelope.algorithm, CryptAlgorithm.aesGcm);
        expect(
          AllCrypto.decryptBytes(migrated.envelope, key: migrated.key),
          equals([1, 2, 3]),
        );
      });

      test('migração a partir de Base64 legado histórico', () {
        const secret = 'histórico';
        final legacyB64 = CryptUtil.encryptToBase64(secret, key: key);
        final legacyPayload = EncryptedPayload.fromBase64(legacyB64);

        final migrated = AllCrypto.migrateLegacy(legacyPayload);
        final newB64 = migrated.envelope.toBase64();

        // O novo Base64 não contém a chave, diferente do legado.
        expect(
          utf8.decode(base64.decode(newB64)).contains(base64.encode(key)),
          isFalse,
        );
        expect(
          AllCrypto.decryptText(
            CryptEnvelope.fromBase64(newB64),
            key: migrated.key,
          ),
          secret,
        );
      });
    });

    // -------------------------------------------------------------------------
    // Fixture Base64 histórica fixa (não gerada durante o teste)
    // -------------------------------------------------------------------------
    group('fixture histórica fixa', () {
      // Congelada uma única vez fora deste teste (não é recomputada aqui),
      // com:
      //   key   = bytes 0..31 (Uint8List.fromList(List.generate(32, (i) => i)))
      //   nonce = bytes 100..111 (Uint8List.fromList(List.generate(12, (i) => i + 100)))
      //   texto = 'fixture histórica congelada em 2026-08-02'
      // via CryptUtil.encryptText(texto, key: key, nonce: nonce).toBase64().
      //
      // Comprova que EncryptedPayload.fromBase64 continua lendo payloads
      // legados reais emitidos por versões anteriores do pacote — não
      // apenas payloads recém-gerados no próprio teste.
      const fixedFixtureBase64 =
          'eyJhbGdvcml0aG0iOiJjaGFjaGEyMC1wb2x5MTMwNSIsImNpcGhlcnRleHQiOiJVbmpEdnUzWEUzS'
          '1R0MllMTVRxcStoT25zbGZ3UG96SXFsNlMwOXBYb2RQNGlZRFdnZ3B5WHEvZCIsImtleSI6IkFBRU'
          'NBd1FGQmdjSUNRb0xEQTBPRHhBUkVoTVVGUllYR0JrYUd4d2RIaDg9IiwidGFnIjoiUzhsKzRscHZ'
          'kSjhDUWlnWURBS0tMQT09Iiwibm9uY2UiOiJaR1ZtWjJocGFtdHNiVzV2IiwiYWFkIjoiIn0=';

      const fixedKeyBytes = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, //
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
      ];

      const fixtureText = 'fixture histórica congelada em 2026-08-02';

      test('decodifica e decifra a fixture congelada', () {
        final legacy = EncryptedPayload.fromBase64(fixedFixtureBase64);

        expect(legacy.key, equals(Uint8List.fromList(fixedKeyBytes)));
        expect(CryptUtil.decryptText(legacy), fixtureText);
      });

      test('fixture congelada é migrável para CryptEnvelope', () {
        final legacy = EncryptedPayload.fromBase64(fixedFixtureBase64);
        final migrated = AllCrypto.migrateLegacy(legacy);

        expect(migrated.envelope.toJson().containsKey('key'), isFalse);
        expect(
          AllCrypto.decryptText(migrated.envelope, key: migrated.key),
          fixtureText,
        );
      });
    });
  });
}
