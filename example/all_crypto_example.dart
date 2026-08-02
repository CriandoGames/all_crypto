import 'dart:convert';

import 'package:all_crypto/all_crypto.dart';

void main() {
  // A chave deve vir de um keychain, KMS ou cofre externo.
  final key = AllCrypto.generateKey();
  final aad = utf8.encode('tenant:demo|record:42|schema:1');
  final envelope = AllCrypto.encryptText(
    'mensagem confidencial',
    key: key,
    aad: aad,
  );

  // O token transporta algoritmo, nonce, tag e AAD, nunca a chave.
  final token = envelope.toBase64();
  final restored = CryptEnvelope.fromBase64(token);
  final decoded = AllCrypto.decryptText(restored, key: key);

  final digest = sha256(utf8.encode(decoded));
  final macKey = AllCrypto.generateKey(); // chave separada para o HMAC
  final mac = hmacSha256(macKey, utf8.encode(decoded));
  final authentic = hmacEqual(
    mac,
    hmacSha256(macKey, utf8.encode(decoded)),
  );

  // Não imprima chave, plaintext ou envelope completo em produção.
  print(
    'Round-trip autenticado: $authentic; SHA-256 bytes: ${digest.length}',
  );
}
