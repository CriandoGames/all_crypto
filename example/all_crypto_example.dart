import 'dart:convert';

import 'package:all_crypto/all_crypto.dart';

void main() {
  // Formato recomendado: a chave nunca é serializada.
  final key = AllCrypto.generateKey(); // guarde em local seguro
  final envelope = AllCrypto.encryptText('mensagem confidencial', key: key);

  final b64 = envelope.toBase64(); // seguro para persistir, transmitir ou logar
  final restored = CryptEnvelope.fromBase64(b64);
  final decoded = AllCrypto.decryptText(restored, key: key);

  final digest = sha256(utf8.encode(decoded));

  print('Texto: $decoded; SHA-256 bytes: ${digest.length}');
}
