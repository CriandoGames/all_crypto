import 'dart:convert';
import 'dart:typed_data';

import 'crypt_algorithm.dart';
import 'encrypted_payload.dart';

/// Envelope **seguro e versionado** para dados cifrados — nunca serializa a
/// chave.
///
/// Substituto recomendado para [EncryptedPayload.toJson] / [EncryptedPayload.toBase64]
/// quando o payload for persistido ou transmitido segundo o protocolo da
/// aplicação. Não registre envelopes completos em logs. Use-o através da
/// fachada `AllCrypto`, que gerencia a chave externamente.
///
/// ## Por que um novo formato
///
/// [EncryptedPayload.toJson] inclui o campo `key` — qualquer sistema que
/// receba esse JSON/Base64 recebe também a chave e consegue decifrar o
/// conteúdo. Esse formato legado nunca ofereceu confidencialidade contra
/// quem possui o payload; ele só protege dados em repouso quando o próprio
/// armazenamento é a fronteira de segurança (ex.: sandbox do app). Veja
/// `SECURITY.md` para detalhes.
///
/// [CryptEnvelope] corrige isso: serializa apenas algoritmo, ciphertext,
/// nonce/IV, tag e AAD. A chave **nunca** é serializada — deve ser fornecida
/// externamente (keychain, `flutter_secure_storage`, variável de ambiente,
/// KMS) no momento da decifragem.
///
/// ## Versionamento
///
/// [version] identifica o schema do envelope, independente da versão do
/// pacote Dart. A versão atual é [currentVersion] (`2`). Payloads legados do
/// [EncryptedPayload] (sem campo de versão, com chave embutida) são tratados
/// como "v1" apenas para fins de migração — veja `AllCrypto.migrateLegacy`.
///
/// [fromJson] e [fromBase64] rejeitam:
/// - versão ausente ou diferente de [currentVersion] — `ArgumentError`;
/// - algoritmo desconhecido — `ArgumentError` (via [CryptAlgorithm.fromString]);
/// - JSON/Base64 malformado — `FormatException`.
///
/// ## Exemplo
///
/// ```dart
/// final key = AllCrypto.generateKey();
/// final envelope = AllCrypto.encryptText('segredo', key: key);
/// final b64 = envelope.toBase64(); // NÃO contém a chave
///
/// final restored = CryptEnvelope.fromBase64(b64);
/// final texto = AllCrypto.decryptText(restored, key: key); // chave externa
/// ```
class CryptEnvelope {
  /// Versão atual do schema de envelope. Incrementada apenas quando o
  /// formato serializado muda de forma incompatível.
  static const int currentVersion = 2;

  /// Versão do schema deste envelope específico.
  final int version;

  /// Algoritmo usado na cifragem.
  final CryptAlgorithm algorithm;

  /// Dados cifrados.
  final Uint8List ciphertext;

  /// Nonce, IV ou bloco de contador inicial — mesma semântica de
  /// [EncryptedPayload.nonce], depende do algoritmo.
  final Uint8List nonce;

  /// Tag de autenticação (MAC). Vazia para AES-CBC/AES-CTR (não autenticados).
  final Uint8List tag;

  /// Dados autenticados adicionais. `Uint8List(0)` quando não houver AAD.
  final Uint8List aad;

  /// Cria um [CryptEnvelope]. Não aceita chave — por design, este tipo
  /// nunca carrega material de chave.
  CryptEnvelope({
    this.version = currentVersion,
    required this.algorithm,
    required this.ciphertext,
    required this.nonce,
    Uint8List? tag,
    Uint8List? aad,
  })  : tag = tag ?? Uint8List(0),
        aad = aad ?? Uint8List(0) {
    if (version != currentVersion) {
      throw ArgumentError(
        'CryptEnvelope: unsupported envelope version $version; '
        'supported version: $currentVersion.',
      );
    }
  }

  /// Serializa para `Map<String, dynamic>`. Nunca inclui chave.
  ///
  /// ```dart
  /// envelope.toJson();
  /// // {'version': 2, 'algorithm': 'chacha20-poly1305', 'ciphertext': '...', ...}
  /// ```
  Map<String, dynamic> toJson() => {
        'version': version,
        'algorithm': algorithm.value,
        'ciphertext': base64.encode(ciphertext),
        'nonce': base64.encode(nonce),
        'tag': base64.encode(tag),
        'aad': base64.encode(aad),
      };

  /// Reconstrói um [CryptEnvelope] a partir de um `Map` JSON.
  ///
  /// Lança [ArgumentError] se `version` estiver ausente, não for inteiro, ou
  /// for diferente de [currentVersion]. Lança [ArgumentError] se `algorithm`
  /// for desconhecido. Lança [TypeError]/[FormatException] para campos
  /// estruturalmente inválidos.
  factory CryptEnvelope.fromJson(Map<String, dynamic> json) {
    final rawVersion = json['version'];
    if (rawVersion is! int) {
      throw ArgumentError(
        'CryptEnvelope: campo "version" ausente ou inválido '
        '(esperado inteiro, recebido: ${rawVersion.runtimeType}). '
        'Payloads legados do EncryptedPayload não possuem "version" — use '
        'AllCrypto.migrateLegacy para convertê-los.',
      );
    }
    if (rawVersion != currentVersion) {
      throw ArgumentError(
        'CryptEnvelope: versão de envelope desconhecida: $rawVersion. '
        'Versão suportada por esta versão do pacote: $currentVersion.',
      );
    }

    final rawAlgorithm = json['algorithm'];
    if (rawAlgorithm is! String) {
      throw const FormatException(
        'CryptEnvelope: missing or invalid "algorithm" field.',
      );
    }

    return CryptEnvelope(
      version: rawVersion,
      algorithm: CryptAlgorithm.fromString(rawAlgorithm),
      ciphertext: _decodeBytes(json, 'ciphertext'),
      nonce: _decodeBytes(json, 'nonce'),
      tag: _decodeBytes(json, 'tag'),
      aad: _decodeBytes(json, 'aad'),
    );
  }

  /// Serializa o envelope completo como uma string Base64 única
  /// (JSON → UTF-8 → Base64). Nunca inclui a chave.
  String toBase64() => base64.encode(utf8.encode(jsonEncode(toJson())));

  /// Reconstrói um [CryptEnvelope] a partir de uma string produzida por
  /// [toBase64].
  ///
  /// Lança [FormatException] se [encoded] não for Base64/JSON válido.
  /// Lança [ArgumentError] para versão ou algoritmo desconhecidos.
  factory CryptEnvelope.fromBase64(String encoded) {
    final json = jsonDecode(utf8.decode(base64.decode(encoded)));
    if (json is! Map<String, dynamic>) {
      throw const FormatException(
        'CryptEnvelope: inner JSON must be an object.',
      );
    }
    return CryptEnvelope.fromJson(json);
  }

  static Uint8List _decodeBytes(Map<String, dynamic> json, String field) {
    final value = json[field];
    if (value is! String) {
      throw FormatException(
        'CryptEnvelope: missing or invalid "$field" field.',
      );
    }
    try {
      return base64.decode(value);
    } on FormatException catch (error) {
      throw FormatException(
        'CryptEnvelope: "$field" is not valid Base64.',
        error.source,
        error.offset,
      );
    }
  }

  @override
  String toString() => 'CryptEnvelope(version: $version, '
      'algorithm: ${algorithm.value}, '
      'ciphertext: ${ciphertext.length} bytes, '
      'nonce: ${nonce.length} bytes, tag: ${tag.length} bytes, '
      'aad: ${aad.length} bytes)';
}
