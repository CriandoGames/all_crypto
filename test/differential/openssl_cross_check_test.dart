// ---------------------------------------------------------------------------
// Testes diferenciais — vetores gerados e cross-verificados de forma
// independente com o backend OpenSSL exposto pelo módulo `crypto` do
// Node.js (sem qualquer dependência de produção ou de teste adicionada a
// este pacote — os vetores foram computados uma única vez, offline, e
// hardcoded abaixo).
//
// Objetivo: comprovar que a implementação Dart-pura deste pacote concorda
// byte a byte com uma implementação de referência amplamente auditada
// (OpenSSL), para entradas além dos vetores oficiais (NIST/RFC) já cobertos
// em outros arquivos de teste.
//
// Chaves/nonces/IVs foram derivados deterministicamente via SHA-256 de um
// rótulo (não são segredos, servem só para reprodutibilidade).
//
// Script usado para gerar cada vetor (Node.js >= 15, OpenSSL >= 1.1.1):
//
//   node -e '
//     const crypto = require("crypto");
//     function bytesN(label, n) {
//       let out = Buffer.alloc(0), seed = label;
//       while (out.length < n) {
//         const h = crypto.createHash("sha256").update(seed).digest();
//         out = Buffer.concat([out, h]);
//         seed = h;
//       }
//       return out.slice(0, n);
//     }
//     // ... ver cada bloco abaixo para o cipher/label específico
//   '
// ---------------------------------------------------------------------------

import 'dart:convert';
import 'dart:typed_data';

import 'package:all_crypto/src/algorithms/aes_cbc.dart';
import 'package:all_crypto/src/algorithms/aes_ctr.dart';
import 'package:all_crypto/src/algorithms/aes_gcm.dart';
import 'package:all_crypto/src/algorithms/chacha20_poly1305.dart';
import 'package:test/test.dart';

Uint8List _hex(String s) {
  final out = Uint8List(s.length ~/ 2);
  for (int i = 0; i < out.length; i++) {
    out[i] = int.parse(s.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

String _toHex(List<int> b) =>
    b.map((x) => x.toRadixString(16).padLeft(2, '0')).join();

void main() {
  group('Diferencial vs. OpenSSL (Node.js crypto) — ChaCha20-Poly1305', () {
    // Label: "all_crypto-diff-chacha-key" / "-nonce"; AAD ASCII;
    // pt = 'O rapido cachorro marrom pula sobre o cao preguicoso.' (53 bytes)
    test('key/nonce derivados, AAD, texto PT-BR sem acentos (53 bytes)', () {
      final key = _hex(
        'f902040577a66802595f0389dea789f'
        '46a8758712fdd09015c92b60aa2ddbbb6',
      );
      final nonce = _hex('79d0bbba4ef53a4cc9a5f294');
      final aad = utf8.encode('all_crypto-differential-aad');
      final pt = utf8.encode(
        'O rapido cachorro marrom pula sobre o cao preguicoso.',
      );
      expect(pt.length, 53);

      final cipher = ChaCha20Poly1305(
        key: key,
        nonce: nonce,
        aad: Uint8List.fromList(aad),
      );
      final payload = cipher.encrypt(pt);

      expect(
        _toHex(payload.ciphertext),
        'd499e553023630b2077ac97f449a75cf'
        '1be051e519c5e22a9513522d8d9cdf20c'
        '1676a3734a0de20223528f7e9f003391'
        '352898cfb',
      );
      expect(_toHex(payload.tag), '963b1a28679cd0079c8d5e2dd1048444');

      // Round-trip usando a mesma instância — comprova consistência interna.
      expect(cipher.decrypt(payload), equals(pt));
    });
  });

  group('Diferencial vs. OpenSSL (Node.js crypto) — AES-256-GCM', () {
    // Label: "all_crypto-diff-gcm256-key" / "-nonce"; sem AAD;
    // pt = 'Payload de teste diferencial AES-256-GCM.' (41 bytes)
    test('key/nonce derivados, sem AAD, 41 bytes', () {
      final key = _hex(
        '33fc08d2e7327abff14df72f2c0fe97'
        'f8ee057f6fc260f4f7b6969ddbc3dca97',
      );
      final nonce = _hex('87954ee0520475a924ed659b');
      final pt = utf8.encode('Payload de teste diferencial AES-256-GCM.');
      expect(pt.length, 41);

      final gcm = AesGcm(key: key, nonce: nonce, aad: Uint8List(0));
      final payload = gcm.encrypt(pt);

      expect(
        _toHex(payload.ciphertext),
        '7e64cc7098596eb0653e4d4010fc4377'
        '0a6bdb3c839a1614ab344744e7575e61'
        '4b175bb3e2b77b31ee',
      );
      expect(_toHex(payload.tag), 'e133f3fdf33a6049a8511bd77b313d60');
      expect(gcm.decrypt(payload), equals(pt));
    });
  });

  group('Diferencial vs. OpenSSL (Node.js crypto) — AES-128-CBC', () {
    // Label: "all_crypto-diff-cbc128-key" / "-iv"; PKCS#7;
    // pt = 'Texto de tamanho nao multiplo de 16!' (36 bytes -> 48 CT)
    test('key/iv derivados, PKCS#7, 36 bytes de plaintext', () {
      final key = _hex('94cd7aa02543e9ba6b1dc241c4265520');
      final iv = _hex('71ace59307d6c45fd4b434d35c0bfbb6');
      final pt = utf8.encode('Texto de tamanho nao multiplo de 16!');
      expect(pt.length, 36);

      final cbc = AesCbc(key: key, iv: iv);
      final payload = cbc.encrypt(pt);

      expect(payload.ciphertext.length, 48);
      expect(
        _toHex(payload.ciphertext),
        'a61c1c6167210e2068c2a99b0d58a31d'
        'b1795bf0501efbe2aab59db8d6640058'
        'f49a3fd285eba60def302dfa7ec6def7',
      );
      expect(cbc.decrypt(payload), equals(pt));
    });
  });

  group('Diferencial vs. OpenSSL (Node.js crypto) — AES-256-CTR', () {
    // Label: "all_crypto-diff-ctr256-key" / "-icb";
    // pt = 'Contador AES-256-CTR com bloco parcial.' (39 bytes)
    test('key/icb derivados, 39 bytes (bloco final parcial)', () {
      final key = _hex(
        '6fd0a6b8faab7ddbdf42bd2c1f5ab072'
        '11c2981c878b8c810db879a804c8cd3f',
      );
      final icb = _hex('82e4ed266a895965e27892613adeb237');
      final pt = utf8.encode('Contador AES-256-CTR com bloco parcial.');
      expect(pt.length, 39);

      final ctr = AesCtr(key: key, initialCounterBlock: icb);
      final payload = ctr.encrypt(pt);

      expect(payload.ciphertext.length, 39);
      expect(
        _toHex(payload.ciphertext),
        '0f7affeeb65bd1e1bb4512a7a2d34b2d'
        '097eb87fe0157fb95be39b1dec3eabee'
        '04391a643742d3',
      );
      expect(ctr.decrypt(payload), equals(pt));
    });
  });
}
