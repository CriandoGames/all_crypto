// ---------------------------------------------------------------------------
// RFC 8439 §2.8.2 — vetor oficial de AEAD_CHACHA20_POLY1305.
//
// Fonte: RFC 8439 "ChaCha20 and Poly1305 for IETF Protocols", seção 2.8.2
// ("Example and Test Vector for AEAD_CHACHA20_POLY1305").
//
// Cross-verificado de forma independente com o cipher nativo do Node.js
// ("chacha20-poly1305", backend OpenSSL) na criação deste teste:
//
//   node -e '
//     const crypto = require("crypto");
//     const key = Buffer.from("808182838485868788898a8b8c8d8e8f" +
//       "909192939495969798999a9b9c9d9e9f", "hex");
//     const nonce = Buffer.from("070000004041424344454647", "hex");
//     const aad = Buffer.from("50515253c0c1c2c3c4c5c6c7", "hex");
//     const pt = Buffer.from("Ladies and Gentlemen of the class of " +
//       "\x2799: If I could offer you only one tip for the future, " +
//       "sunscreen would be it.", "utf8");
//     const cipher = crypto.createCipheriv("chacha20-poly1305", key, nonce,
//       {authTagLength: 16});
//     cipher.setAAD(aad, {plaintextLength: pt.length});
//     const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
//     console.log(ct.toString("hex"));
//     console.log(cipher.getAuthTag().toString("hex"));
//   '
//
// Saída do Node/OpenSSL bateu byte a byte com o vetor publicado no RFC,
// confirmando tanto o vetor quanto a implementação pura-Dart abaixo.
// ---------------------------------------------------------------------------

import 'dart:typed_data';

import 'package:all_crypto/src/algorithms/chacha20_poly1305.dart';
import 'package:all_crypto/src/models/crypt_exception.dart';
import 'package:all_crypto/src/models/encrypted_payload.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final src = s.replaceAll(' ', '').replaceAll('\n', '');
  final out = Uint8List(src.length ~/ 2);
  for (int i = 0; i < out.length; i++) {
    out[i] = int.parse(src.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

// Vetor canônico (ciphertext + tag), verificado byte a byte contra o
// RFC 8439 §2.8.2 e contra Node.js/OpenSSL — ver cabeçalho do arquivo.
const _rfcCiphertextHex = 'd31a8d34648e60db7b86afbc53ef7ec2'
    'a4aded51296e08fea9e2b5a736ee62d6'
    '3dbea45e8ca9671282fafb69da92728b'
    '1a71de0a9e060b2905d6a5b67ecd3b369'
    '2ddbd7f2d778b8c9803aee328091b58fa'
    'b324e4fad675945585808b4831d7bc3ff'
    '4def08e4b7a9de576d26586cec64b6116';

const _rfcTagHex = '1ae10b594f09e26a7e902ecbd0600691';

void main() {
  group('RFC 8439 §2.8.2 — ChaCha20-Poly1305 (AEAD)', () {
    // Plaintext exato do RFC (114 bytes), incluindo o apóstrofo em "'99".
    final plaintext = "Ladies and Gentlemen of the class of '99: "
        'If I could offer you only one tip for the future, '
        'sunscreen would be it.';

    final key = _hex(
      '80818283 84858687 88898a8b 8c8d8e8f'
      '90919293 94959697 98999a9b 9c9d9e9f',
    );
    final nonce = _hex('07000000 40414243 44454647');
    final aad = _hex('50515253 c0c1c2c3 c4c5c6c7');

    test('plaintext do RFC tem exatamente 114 bytes', () {
      expect(plaintext.codeUnits.length, 114);
    });

    test('vetor oficial — ciphertext e tag batem byte a byte', () {
      final plaintextBytes = Uint8List.fromList(plaintext.codeUnits);
      final cipher = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);
      final payload = cipher.encrypt(plaintextBytes);

      expect(_toHex(payload.ciphertext), _rfcCiphertextHex);
      expect(_toHex(payload.tag), _rfcTagHex);
    });

    test('vetor oficial — decifra de volta ao plaintext original', () {
      final plaintextBytes = Uint8List.fromList(plaintext.codeUnits);
      final cipher = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);
      final payload = cipher.encrypt(plaintextBytes);

      final decrypted = cipher.decrypt(payload);
      expect(String.fromCharCodes(decrypted), plaintext);
    });

    test('tag adulterada no vetor oficial é rejeitada', () {
      final plaintextBytes = Uint8List.fromList(plaintext.codeUnits);
      final cipher = ChaCha20Poly1305(key: key, nonce: nonce, aad: aad);
      final payload = cipher.encrypt(plaintextBytes);

      final tamperedTag = Uint8List.fromList(payload.tag)..[0] ^= 0xff;
      final tampered = EncryptedPayload(
        algorithm: payload.algorithm,
        ciphertext: payload.ciphertext,
        key: payload.key,
        tag: tamperedTag,
        nonce: payload.nonce,
        aad: payload.aad,
      );

      expect(() => cipher.decrypt(tampered), throwsA(isA<CryptException>()));
    });
  });
}
