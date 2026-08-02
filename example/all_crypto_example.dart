import 'dart:convert';
import 'dart:typed_data';

import 'package:all_crypto/all_crypto.dart';

void main() {
  // Em produção, recupere estas chaves de um keychain, KMS ou cofre externo.
  final storageKey = AllCrypto.generateKey();
  final webhookKey = AllCrypto.generateKey();

  final customerToken = protectCustomerRecord(storageKey);
  final customer = restoreCustomerRecord(customerToken, storageKey);

  final orderToken = protectOrderWithAesGcm(storageKey);
  final order = restoreOrder(orderToken, storageKey);

  final attachment = Uint8List.fromList([0, 1, 2, 3, 254, 255]);
  final attachmentToken = protectAttachment(attachment, storageKey);
  final attachmentRestored = restoreAttachment(attachmentToken, storageKey);
  final attachmentDigest = trustedContentDigest(attachmentRestored);

  final webhookBody = utf8.encode('{"event":"invoice.paid","id":"evt_42"}');
  final signature = signWebhook(webhookBody, webhookKey);

  // Exiba somente resultados operacionais; nunca chaves, plaintext ou tokens.
  print('Registro restaurado: ${customer['id'] == 42}');
  print('AES-GCM restaurado: ${order['status'] == 'paid'}');
  print('Bytes restaurados: ${bytesEqual(attachment, attachmentRestored)}');
  print('Digest SHA-256 gerado: ${attachmentDigest.length == 32}');
  print(
      'Webhook autêntico: ${verifyWebhook(webhookBody, signature, webhookKey)}');
  print(
      'Adulteração bloqueada: ${rejectsTamperedToken(customerToken, storageKey)}');
}

/// Protege um registro antes de persisti-lo em banco, cache ou arquivo.
String protectCustomerRecord(Uint8List key) {
  final record = <String, Object?>{
    'id': 42,
    'document': '12345678909',
    'plan': 'pro',
  };
  final aad = utf8.encode('tenant:demo|collection:customers|schema:1');

  return AllCrypto.encryptText(
    jsonEncode(record),
    key: key,
    aad: aad,
  ).toBase64();
}

Map<String, dynamic> restoreCustomerRecord(String token, Uint8List key) {
  final envelope = CryptEnvelope.fromBase64(token);
  final plaintext = AllCrypto.decryptText(envelope, key: key);
  return jsonDecode(plaintext) as Map<String, dynamic>;
}

/// Usa AES-GCM quando o protocolo de outro sistema exige AES autenticado.
String protectOrderWithAesGcm(Uint8List key) {
  final order = <String, Object?>{
    'id': 'order_42',
    'totalInCents': 15990,
    'status': 'paid',
  };

  return AllCrypto.encryptText(
    jsonEncode(order),
    key: key,
    algorithm: CryptAlgorithm.aesGcm,
    aad: utf8.encode('orders:v1'),
  ).toBase64();
}

Map<String, dynamic> restoreOrder(String token, Uint8List key) {
  final envelope = CryptEnvelope.fromBase64(token);
  final plaintext = AllCrypto.decryptText(envelope, key: key);
  return jsonDecode(plaintext) as Map<String, dynamic>;
}

/// O mesmo envelope também transporta conteúdo binário sem conversão para texto.
String protectAttachment(List<int> bytes, Uint8List key) {
  return AllCrypto.encryptBytes(
    bytes,
    key: key,
    aad: utf8.encode('attachments:v1'),
  ).toBase64();
}

List<int> restoreAttachment(String token, Uint8List key) {
  return AllCrypto.decryptBytes(
    CryptEnvelope.fromBase64(token),
    key: key,
  );
}

/// Gera um digest para comparação com um valor obtido de uma fonte confiável.
Uint8List trustedContentDigest(List<int> bytes) => sha256(bytes);

/// Assina mensagens que precisam de autenticidade, mas não de confidencialidade.
Uint8List signWebhook(List<int> body, Uint8List key) => hmacSha256(key, body);

bool verifyWebhook(List<int> body, List<int> receivedMac, Uint8List key) {
  final expectedMac = hmacSha256(key, body);
  return hmacEqual(expectedMac, receivedMac);
}

/// Demonstra que qualquer alteração no ciphertext invalida a autenticação AEAD.
bool rejectsTamperedToken(String token, Uint8List key) {
  final original = CryptEnvelope.fromBase64(token);
  final changedCiphertext = Uint8List.fromList(original.ciphertext);
  changedCiphertext[0] ^= 1;

  final tampered = CryptEnvelope(
    algorithm: original.algorithm,
    ciphertext: changedCiphertext,
    nonce: Uint8List.fromList(original.nonce),
    tag: Uint8List.fromList(original.tag),
    aad: Uint8List.fromList(original.aad),
  );

  try {
    AllCrypto.decryptBytes(tampered, key: key);
    return false;
  } on CryptException {
    return true;
  }
}

bool bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) return false;
  for (var index = 0; index < left.length; index++) {
    if (left[index] != right[index]) return false;
  }
  return true;
}
