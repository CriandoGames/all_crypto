import 'dart:convert';
import 'dart:typed_data';

import 'crypt_util.dart';
import 'models/crypt_envelope.dart';

/// Fachada segura recomendada para cifrar/decifrar usando [CryptEnvelope].
///
/// Diferente de [CryptUtil.encryptToBase64] / [CryptUtil.decryptFromBase64],
/// **a chave nunca é serializada**. Toda operação de decifragem exige a
/// chave como parâmetro explícito — ela deve vir de um cofre externo
/// (`flutter_secure_storage`, keychain, KMS, variável de ambiente segura).
///
/// Internamente reaproveita as mesmas implementações de algoritmo usadas por
/// [CryptUtil] (ChaCha20-Poly1305, AES-GCM, AES-CBC, AES-CTR) — nenhuma
/// lógica criptográfica é duplicada.
///
/// ## Uso rápido
///
/// ```dart
/// final key = AllCrypto.generateKey();               // guarde em local seguro
/// final envelope = AllCrypto.encryptText('segredo', key: key);
/// final b64 = envelope.toBase64();                   // seguro para persistir/logar
///
/// // ... depois, com a chave recuperada do cofre:
/// final restored = CryptEnvelope.fromBase64(b64);
/// final texto = AllCrypto.decryptText(restored, key: key);
/// ```
///
/// ## Migração de payloads legados
///
/// Use [migrateLegacy] para converter um [EncryptedPayload] histórico (com
/// chave embutida) em um [CryptEnvelope] (sem chave) mais a chave extraída
/// separadamente. Rotacione a chave depois da migração sempre que o payload
/// legado já tiver circulado fora de um armazenamento confiável, pois ela
/// esteve embutida no formato serializado.
class AllCrypto {
  AllCrypto._();

  // ===========================================================================
  // Texto
  // ===========================================================================

  /// Cifra [text] (UTF-8) e retorna um [CryptEnvelope] sem chave.
  ///
  /// - [key]       : obrigatória; tamanho depende de [algorithm].
  /// - [algorithm] : padrão [CryptAlgorithm.chacha20Poly1305] (AEAD).
  /// - [nonce]     : nonce/IV/ICB; se omitido, gerado aleatoriamente.
  /// - [aad]       : dados autenticados não cifrados (apenas modos AEAD).
  static CryptEnvelope encryptText(
    String text, {
    required Uint8List key,
    CryptAlgorithm algorithm = CryptAlgorithm.chacha20Poly1305,
    Uint8List? nonce,
    List<int>? aad,
  }) =>
      encryptBytes(
        utf8.encode(text),
        key: key,
        algorithm: algorithm,
        nonce: nonce,
        aad: aad,
      );

  /// Decifra [envelope] com [key] fornecida externamente e retorna a string
  /// original.
  ///
  /// Lança [CryptException] se a autenticação falhar (modos AEAD) ou o
  /// ciphertext/padding for inválido (AES-CBC).
  static String decryptText(CryptEnvelope envelope, {required Uint8List key}) =>
      utf8.decode(decryptBytes(envelope, key: key));

  // ===========================================================================
  // Bytes
  // ===========================================================================

  /// Cifra [bytes] e retorna um [CryptEnvelope] sem chave.
  static CryptEnvelope encryptBytes(
    List<int> bytes, {
    required Uint8List key,
    CryptAlgorithm algorithm = CryptAlgorithm.chacha20Poly1305,
    Uint8List? nonce,
    List<int>? aad,
  }) {
    final legacy = _encryptViaAlgorithm(
      bytes,
      key: key,
      algorithm: algorithm,
      nonce: nonce,
      aad: aad,
    );
    return CryptEnvelope(
      algorithm: legacy.algorithm,
      ciphertext: legacy.ciphertext,
      nonce: legacy.nonce,
      tag: legacy.tag,
      aad: legacy.aad,
    );
  }

  /// Decifra [envelope] com [key] fornecida externamente e retorna os bytes
  /// originais.
  static List<int> decryptBytes(CryptEnvelope envelope,
      {required Uint8List key}) {
    final legacy = EncryptedPayload(
      algorithm: envelope.algorithm,
      ciphertext: envelope.ciphertext,
      key: key,
      nonce: envelope.nonce,
      tag: envelope.tag,
      aad: envelope.aad,
    );
    return CryptUtil.decryptAny(legacy);
  }

  // ===========================================================================
  // Migração do formato legado (EncryptedPayload, com chave embutida)
  // ===========================================================================

  /// Converte um [EncryptedPayload] legado (v1, com chave embutida) em um
  /// [CryptEnvelope] (v2, sem chave) mais a chave extraída separadamente.
  ///
  /// Não decifra nem recifra os dados — apenas reestrutura a serialização.
  /// O ciphertext permanece o mesmo; somente a forma de transportar a chave
  /// muda (de "dentro do payload" para "gerenciamento externo").
  ///
  /// ```dart
  /// final legacy = EncryptedPayload.fromBase64(oldToken);
  /// final migrated = AllCrypto.migrateLegacy(legacy);
  /// await secureStorage.write(key: 'k', value: base64.encode(migrated.key));
  /// await db.save(migrated.envelope.toBase64());
  /// ```
  ///
  /// ⚠️ Se o Base64 legado já foi transmitido ou armazenado fora de um local
  /// confiável, considere a chave comprometida e rotacione-a (recifrando com
  /// uma chave nova) em vez de apenas migrar o formato.
  static ({CryptEnvelope envelope, Uint8List key}) migrateLegacy(
    EncryptedPayload legacyPayload,
  ) {
    final envelope = CryptEnvelope(
      algorithm: legacyPayload.algorithm,
      ciphertext: legacyPayload.ciphertext,
      nonce: legacyPayload.nonce,
      tag: legacyPayload.tag,
      aad: legacyPayload.aad,
    );
    return (envelope: envelope, key: Uint8List.fromList(legacyPayload.key));
  }

  // ===========================================================================
  // Geração de material criptográfico (reexporta CryptUtil)
  // ===========================================================================

  /// Gera uma chave criptograficamente segura de 32 bytes.
  static Uint8List generateKey() => CryptUtil.generateKey();

  /// Gera uma chave criptograficamente segura de 16 bytes (AES-128).
  static Uint8List generateKey128() => CryptUtil.generateKey128();

  /// Gera um nonce criptograficamente seguro de 12 bytes.
  static Uint8List generateNonce() => CryptUtil.generateNonce();

  /// Gera um IV/ICB criptograficamente seguro de 16 bytes.
  static Uint8List generateIv() => CryptUtil.generateIv();

  // ===========================================================================
  // Privado — despacho por algoritmo reaproveitando CryptUtil
  // ===========================================================================

  static EncryptedPayload _encryptViaAlgorithm(
    List<int> bytes, {
    required Uint8List key,
    required CryptAlgorithm algorithm,
    Uint8List? nonce,
    List<int>? aad,
  }) {
    switch (algorithm) {
      case CryptAlgorithm.chacha20Poly1305:
        return CryptUtil.encryptBytes(bytes, key: key, nonce: nonce, aad: aad);
      case CryptAlgorithm.aesGcm:
        return CryptUtil.encryptAesGcm(bytes, key: key, nonce: nonce, aad: aad);
      case CryptAlgorithm.aesCbc:
        _rejectAadForUnauthenticatedMode(algorithm, aad);
        return CryptUtil.encryptAesCbc(bytes, key: key, iv: nonce);
      case CryptAlgorithm.aesCtr:
        _rejectAadForUnauthenticatedMode(algorithm, aad);
        return CryptUtil.encryptAesCtr(
          bytes,
          key: key,
          initialCounterBlock: nonce,
        );
    }
  }

  static void _rejectAadForUnauthenticatedMode(
    CryptAlgorithm algorithm,
    List<int>? aad,
  ) {
    if (aad != null && aad.isNotEmpty) {
      throw ArgumentError(
        '${algorithm.value}: modo não autenticado, não suporta AAD. '
        'Use ChaCha20-Poly1305 ou AES-GCM se precisar autenticar metadados.',
      );
    }
  }
}
