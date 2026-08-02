# all_crypto

🇧🇷 Português | [🇺🇸 English](README.en.md)

[![Dart](https://img.shields.io/badge/Dart-3.0%2B-0175C2)](https://dart.dev)
[![Pure Dart](https://img.shields.io/badge/Flutter-não%20requerido-informational)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Sem chave no envelope](https://img.shields.io/badge/CryptEnvelope-nunca%20serializa%20a%20chave-success)](#formato-recomendado-cryptenvelope--allcrypto)

Criptografia e hashes em Dart puro, extraídos do `all_validations_br` para uso independente e sem Flutter.

## Motivação

Este pacote existe para oferecer criptografia autenticada (AEAD) e hashing em Dart puro, sem depender de Flutter, sem plugins nativos e sem repetir a implementação em cada projeto do ecossistema `all_validations_br`. A extração também foi a oportunidade de corrigir um problema preexistente do formato de payload original: `EncryptedPayload.toJson()`/`toBase64()` serializavam a chave simétrica junto com o ciphertext, o que nunca ofereceu confidencialidade contra quem obtinha o payload. A partir desta versão, o pacote passa a ter um formato recomendado — `CryptEnvelope`, produzido pela fachada `AllCrypto` — que **nunca serializa a chave** e é **explicitamente versionado**. O formato antigo continua funcionando (compatibilidade), mas está marcado como legado. Veja [SECURITY.md](SECURITY.md) para o relato completo.

## Recursos

- ChaCha20-Poly1305 e AES-GCM para criptografia autenticada.
- AES-CBC com PKCS#7 e AES-CTR para interoperabilidade legada.
- SHA-256 e HMAC-SHA256.
- `CryptEnvelope`: envelope **seguro e versionado** (chave nunca serializada) — formato recomendado, via `AllCrypto`.
- `EncryptedPayload`: formato **legado** (chave embutida no payload), mantido por compatibilidade e marcado como depreciado nos pontos de serialização.
- Migração explícita de payloads legados para o novo formato (`AllCrypto.migrateLegacy`).
- Compatibilidade com a API histórica `CryptUtil` e com payloads existentes.

## Instalação

```yaml
dependencies:
  all_crypto: ^1.0.0
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## Primeiro exemplo — formato recomendado

```dart
final key = AllCrypto.generateKey();               // guarde em local seguro (keychain, etc.)
final envelope = AllCrypto.encryptText('segredo', key: key);
final b64 = envelope.toBase64();                    // NÃO contém a chave — seguro para persistir/logar

// ... depois, com a chave recuperada do cofre:
final restored = CryptEnvelope.fromBase64(b64);
final plainText = AllCrypto.decryptText(restored, key: key);
```

O exemplo executável está em `example/all_crypto_example.dart` e o snippet é coberto por teste em `test/documentation/readme_example_test.dart`.

## Formato recomendado: `CryptEnvelope` + `AllCrypto`

`CryptEnvelope` serializa **apenas** algoritmo, ciphertext, nonce/IV, tag e AAD — nunca a chave. A chave deve ser gerenciada externamente (`flutter_secure_storage`, keychain, KMS) e fornecida explicitamente em toda decifragem via `AllCrypto`. O envelope tem um campo `version` explícito (atualmente `2`); versões desconhecidas são rejeitadas com `ArgumentError` claro, assim como algoritmos desconhecidos.

```dart
final envelope = AllCrypto.encryptBytes(
  dados,
  key: key,
  algorithm: CryptAlgorithm.aesGcm, // padrão: chacha20Poly1305
  aad: utf8.encode('user_id:42'),   // opcional, só em modos AEAD
);
final original = AllCrypto.decryptBytes(envelope, key: key);
```

Veja [doc/pt-BR/formato-seguro.md](doc/pt-BR/formato-seguro.md) para a referência completa.

## Formato legado: `CryptUtil` + `EncryptedPayload`

Preservado por compatibilidade. `EncryptedPayload.toJson()`/`toBase64()` e os atalhos `CryptUtil.encryptToBase64()`/`decryptFromBase64()` estão marcados `@Deprecated` — continuam funcionando, mas **não devem ser usados em código novo** porque embutem a chave no payload serializado. Use-os apenas para ler dados já emitidos nesse formato, e migre com `AllCrypto.migrateLegacy`:

```dart
final legacy = EncryptedPayload.fromBase64(oldToken); // lê payload histórico
final migrated = AllCrypto.migrateLegacy(legacy);      // separa envelope e chave
// migrated.envelope -> persista/transmita (sem chave)
// migrated.key      -> mova para um cofre externo
```

Veja [doc/pt-BR/crypt_util.md](doc/pt-BR/crypt_util.md) para a referência completa do formato legado.

## Algoritmos

| Recurso | Uso recomendado | Observação |
|---|---|---|
| ChaCha20-Poly1305 | padrão para novos dados | AEAD; autentica ciphertext e AAD |
| AES-GCM | interoperabilidade AEAD | nonce de 12 bytes |
| AES-CBC | compatibilidade legada | não autentica; associe MAC em protocolo externo |
| AES-CTR | compatibilidade/stream | não autentica; nunca reutilize contador com a mesma chave |
| SHA-256 | digest | não é criptografia nem armazenamento de senha |
| HMAC-SHA256 | autenticação | exige chave secreta adequada |

## Erros

Entradas estruturalmente inválidas, versão de envelope desconhecida ou algoritmo desconhecido lançam `ArgumentError`. Falhas de autenticação, payload incompatível ou formato criptográfico inválido lançam `CryptException`. Base64/JSON malformado lança `FormatException`. Não use a mensagem de erro como parte de um protocolo de segurança.

## Compatibilidade e migração

Código anterior:

```dart
import 'package:all_validations_br/crypt.dart';
```

Novo código:

```dart
import 'package:all_crypto/all_crypto.dart';
```

O nome `CryptUtil` e seus métodos permanecem — o agregador continua reexportando esta API. Para novos dados, prefira `AllCrypto`/`CryptEnvelope`; veja a seção de migração acima.

## Desempenho

A implementação é Dart puro e prioriza portabilidade e comportamento verificável. Faça benchmarks no dispositivo e volume reais antes de escolher este pacote para cargas intensivas; nenhuma garantia de aceleração por hardware é feita.

## Segurança

Leia [SECURITY.md](SECURITY.md). Prefira `AllCrypto`/`CryptEnvelope` e algoritmos AEAD, gere nonces/IVs conforme a API, proteja chaves fora do código-fonte e nunca registre chaves, plaintexts sensíveis ou payloads completos. Este projeto não declara ter auditoria criptográfica externa.

## Limitações

- Não fornece cofre de chaves, rotação, KDF de senha, TLS ou assinatura de identidade.
- AES-CBC e AES-CTR não oferecem autenticação por si só.
- Segurança do sistema depende do gerenciamento de chaves e do protocolo consumidor.

## Roadmap

O roadmap prioriza vetores interoperáveis adicionais, documentação de formatos e migrações explícitas sem quebrar payloads existentes. A reavaliação de prontidão para publicação deste pacote após esta revisão de segurança é responsabilidade da IA/mantenedor que assumir o handoff seguinte — veja `HANDOFF_1_CRYPTO_FORMS.md`.

## Contribuição, licença e ecossistema

Veja [CONTRIBUTING.md](CONTRIBUTING.md). Licença MIT em [LICENSE](LICENSE). Este pacote integra o ecossistema `all_validations_br`, mas não depende do agregador, de Flutter, de logger, de validações ou de `Result`.

