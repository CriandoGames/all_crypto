# CryptEnvelope + AllCrypto — Formato Seguro Recomendado

`AllCrypto` é a fachada recomendada para cifrar e decifrar dados neste pacote. Ao contrário de `CryptUtil` (formato legado, veja [crypt_util.md](crypt_util.md)), `AllCrypto` produz e consome `CryptEnvelope` — um envelope que **nunca serializa a chave** e é **explicitamente versionado**.

```dart
import 'package:all_crypto/all_crypto.dart';
```

---

## Por que um formato novo

O formato histórico (`EncryptedPayload.toJson()`/`toBase64()`) inclui o campo `key` no JSON serializado. Isso significa que qualquer sistema, log, banco de dados ou pessoa que obtenha esse Base64/JSON também obtém a chave e consegue decifrar o conteúdo — o formato nunca ofereceu confidencialidade contra quem possui o payload. Veja `test/legacy_vulnerability_test.dart` para a reprodução comprovada e [SECURITY.md](../../SECURITY.md) para a análise completa.

`CryptEnvelope` corrige isso: serializa apenas algoritmo, ciphertext, nonce/IV, tag e AAD. A chave nunca aparece na saída de `toJson()`/`toBase64()` — ela deve ser fornecida externamente (keychain, `flutter_secure_storage`, KMS, variável de ambiente segura) toda vez que você for decifrar.

---

## Como funciona

```
plaintext + key (externa) + nonce ──► algoritmo escolhido ──► ciphertext + tag

Resultado serializável: CryptEnvelope { version, algorithm, ciphertext, nonce, tag, aad }
                                        (SEM campo "key")
```

Internamente, `AllCrypto` reaproveita exatamente as mesmas implementações de algoritmo usadas por `CryptUtil` (ChaCha20-Poly1305, AES-GCM, AES-CBC, AES-CTR) — nenhuma lógica criptográfica é duplicada entre os dois caminhos.

---

## Uso básico — texto

```dart
// 1. Gera chave segura de 32 bytes e guarde-a em local seguro
final key = AllCrypto.generateKey();

// 2. Criptografa — nonce aleatório gerado automaticamente
final envelope = AllCrypto.encryptText('Dados sensíveis', key: key);

// 3. Serializa (NÃO contém a chave) — seguro para persistir, transmitir ou logar
final b64 = envelope.toBase64();

// 4. Depois, com a chave recuperada do cofre externo:
final restored = CryptEnvelope.fromBase64(b64);
final texto = AllCrypto.decryptText(restored, key: key);
print(texto); // 'Dados sensíveis'
```

---

## Uso básico — bytes

```dart
final data = Uint8List.fromList([1, 2, 3, 4, 5]);
final key = AllCrypto.generateKey();

final envelope = AllCrypto.encryptBytes(data, key: key);
final List<int> restored = AllCrypto.decryptBytes(envelope, key: key);
```

---

## Escolhendo o algoritmo

```dart
final envelope = AllCrypto.encryptBytes(
  dados,
  key: key,
  algorithm: CryptAlgorithm.aesGcm, // padrão: CryptAlgorithm.chacha20Poly1305
);
```

| Algoritmo | Autenticado (AEAD) | Observação |
|---|---|---|
| `CryptAlgorithm.chacha20Poly1305` (padrão) | ✅ | RFC 8439; recomendado para novos dados |
| `CryptAlgorithm.aesGcm` | ✅ | interoperabilidade com sistemas AES |
| `CryptAlgorithm.aesCbc` | ❌ | apenas para compatibilidade; combine com HMAC externo |
| `CryptAlgorithm.aesCtr` | ❌ | apenas para compatibilidade; combine com HMAC externo |

`AllCrypto` **rejeita** AAD não vazio com AES-CBC/AES-CTR (`ArgumentError`) — esses modos não autenticam, então aceitar AAD silenciosamente daria uma falsa sensação de integridade.

---

## Versão do envelope

```dart
print(CryptEnvelope.currentVersion); // 2
```

`CryptEnvelope.toJson()` sempre inclui `'version': 2`. `CryptEnvelope.fromJson`/`fromBase64` rejeitam:

- versão ausente;
- versão que não seja um inteiro;
- qualquer versão diferente de `currentVersion` (incluindo `1`, reservado para o formato legado sem chave — ele não é lido por `CryptEnvelope.fromJson`, apenas por `EncryptedPayload.fromJson`).

```dart
final json = envelope.toJson()..['version'] = 99;
CryptEnvelope.fromJson(json); // lança ArgumentError
```

Isso torna evoluções futuras do formato explícitas: uma versão `3` (hipotética) exigiria atualizar este pacote antes de conseguir ler o novo formato, em vez de decodificar silenciosamente campos que ela não entende.

---

## Com AAD (Additional Authenticated Data)

Igual ao formato legado, mas só em modos AEAD:

```dart
final aad = utf8.encode('user_id:42');
final envelope = AllCrypto.encryptText('dado privado', key: key, aad: aad);

final texto = AllCrypto.decryptText(envelope, key: key); // OK

// Se o AAD do envelope for alterado antes da decifragem → CryptException
```

---

## Detecção de adulteração

```dart
try {
  final texto = AllCrypto.decryptText(envelope, key: key);
} on CryptException catch (e) {
  print(e.message); // ex.: 'Tag de autenticação inválida...'
} on FormatException catch (e) {
  // Base64/JSON malformado em CryptEnvelope.fromBase64
} on ArgumentError catch (e) {
  // versão/algoritmo desconhecido, ou tamanho de chave/nonce inválido
}
```

---

## Migrando payloads legados

```dart
// 1. Leia o payload histórico com a API legada (decoder, não deprecado)
final legacy = EncryptedPayload.fromBase64(oldToken);

// 2. Migre: separa envelope (sem chave) e chave extraída
final migrated = AllCrypto.migrateLegacy(legacy);

// 3. Persista o envelope normalmente (não contém a chave)
final newToken = migrated.envelope.toBase64();

// 4. Mova migrated.key para um cofre externo (flutter_secure_storage, etc.)
//    Se o Base64 legado já circulou fora de um local confiável, rotacione
//    a chave (recifre com uma chave nova) em vez de apenas migrar.
```

`migrateLegacy` não decifra nem recifra os dados — apenas reestrutura como a chave é transportada.

---

## `CryptEnvelope` — estrutura completa

```dart
class CryptEnvelope {
  final int version;             // schema do envelope; atual: 2
  final CryptAlgorithm algorithm;
  final Uint8List ciphertext;
  final Uint8List nonce;         // nonce/IV/ICB, depende do algoritmo
  final Uint8List tag;           // vazia em AES-CBC/AES-CTR
  final Uint8List aad;           // vazia se não usado
  // SEM campo "key"
}
```

| Método | Descrição |
|--------|-----------|
| `toJson()` | Serializa para `Map<String, dynamic>` (sem chave) |
| `fromJson(map)` | Deserializa; rejeita versão/algoritmo desconhecidos |
| `toBase64()` | Serializa para string Base64 (sem chave) |
| `fromBase64(encoded)` | Deserializa de string Base64 |

---

## Referência da API — AllCrypto

| Método | Retorno | Descrição |
|--------|---------|-----------|
| `encryptText(text, {required key, algorithm?, nonce?, aad?})` | `CryptEnvelope` | Cifra String (UTF-8) |
| `decryptText(envelope, {required key})` | `String` | Decifra e retorna String |
| `encryptBytes(bytes, {required key, algorithm?, nonce?, aad?})` | `CryptEnvelope` | Cifra `List<int>` |
| `decryptBytes(envelope, {required key})` | `List<int>` | Decifra e retorna bytes |
| `migrateLegacy(legacyPayload)` | `({CryptEnvelope envelope, Uint8List key})` | Migra um `EncryptedPayload` legado |
| `generateKey()` | `Uint8List` | Chave segura de 32 bytes |
| `generateKey128()` | `Uint8List` | Chave segura de 16 bytes (AES-128) |
| `generateNonce()` | `Uint8List` | Nonce seguro de 12 bytes |
| `generateIv()` | `Uint8List` | IV/ICB seguro de 16 bytes |

---

## Boas práticas

- **Chave sempre externa** — nunca commitada, nunca no mesmo local do envelope serializado.
- **Não reutilize (key, nonce)** — deixe `nonce` omitido para gerar automaticamente.
- **Prefira AEAD** — ChaCha20-Poly1305 (padrão) ou AES-GCM detectam adulteração; CBC/CTR não.
- **Trate `CryptException`, `FormatException` e `ArgumentError`** separadamente — cada um sinaliza uma classe diferente de problema (autenticação, formato malformado, parâmetro inválido).
- **Migre payloads legados** assim que possível com `migrateLegacy`, e rotacione chaves que já circularam no formato antigo.

---

← [Voltar ao README](../../README.md) · Veja também: [crypt_util.md](crypt_util.md) (formato legado)
