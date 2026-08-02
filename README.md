# all_crypto

🇧🇷 Português | [🇺🇸 English](https://github.com/CriandoGames/all_crypto/blob/main/README.en.md)

[![pub package](https://img.shields.io/pub/v/all_crypto.svg)](https://pub.dev/packages/all_crypto)
[![CI](https://github.com/CriandoGames/all_crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/CriandoGames/all_crypto/actions/workflows/ci.yml)
[![pub points](https://img.shields.io/pub/points/all_crypto?label=pub%20points)](https://pub.dev/packages/all_crypto/score)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE)

Criptografia autenticada, AES, SHA-256 e HMAC-SHA256 em Dart puro, com um
envelope versionado que nunca serializa a chave e mantém o gerenciamento de
segredos sob controle da aplicação.

![all_crypto hero](https://raw.githubusercontent.com/CriandoGames/all_crypto/main/documentation/images/hero.png)

## Recursos

- ChaCha20-Poly1305 (padrão) e AES-GCM, ambos AEAD.
- AES-CBC/PKCS#7 e AES-CTR para interoperabilidade legada.
- SHA-256, HMAC-SHA256 e comparação de MAC em tempo constante.
- `AllCrypto` + `CryptEnvelope` para payloads sem chave e com schema v2.
- Leitura e migração explícita de payloads históricos de `EncryptedPayload`.
- Dart puro, sem Flutter, plugins nativos ou dependências de produção.

## Instalação

```yaml
dependencies:
  all_crypto: ^1.0.0
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## Como usar

```dart
final key = AllCrypto.generateKey(); // guarde em keychain, KMS ou cofre
final envelope = AllCrypto.encryptText('segredo', key: key);
final encoded = envelope.toBase64(); // nunca contém a chave

final restored = CryptEnvelope.fromBase64(encoded);
final value = AllCrypto.decryptText(restored, key: key);
```

O mesmo snippet existe em [example/all_crypto_example.dart](https://github.com/CriandoGames/all_crypto/blob/main/example/all_crypto_example.dart)
e é coberto por `test/documentation/`.

## Envelope seguro v2

`CryptEnvelope.toJson()` produz os campos abaixo, nesta ordem, e não possui
campo `key`:

```json
{
  "version": 2,
  "algorithm": "chacha20-poly1305",
  "ciphertext": "<base64>",
  "nonce": "<base64>",
  "tag": "<base64>",
  "aad": "<base64>"
}
```

A chave é obrigatória em `AllCrypto.decryptText`/`decryptBytes`. Versão ausente
ou desconhecida, algoritmo desconhecido e campos estruturais inválidos são
rejeitados; alterações de ciphertext, tag, nonce ou AAD falham na autenticação
dos modos AEAD.

## Payload legado

`EncryptedPayload.toJson()`/`toBase64()` e
`CryptUtil.encryptToBase64()`/`decryptFromBase64()` incluem a chave no próprio
payload. Isso é um problema preexistente do formato histórico: qualquer pessoa
com o Base64 consegue recuperar a chave e decifrar o conteúdo. Base64 é apenas
codificação, não proteção.

Essas APIs permanecem disponíveis para compatibilidade, estão depreciadas e
têm remoção planejada para `all_crypto` 2.0.0. Não as use para dados novos.

```dart
final legacy = EncryptedPayload.fromBase64(oldToken);
final migrated = AllCrypto.migrateLegacy(legacy);

final newToken = migrated.envelope.toBase64(); // sem chave
final key = migrated.key; // mova para um cofre externo
```

Se o payload legado já saiu de armazenamento confiável, trate a chave como
comprometida e recifre com uma chave nova.

## Segurança e limites

- Prefira ChaCha20-Poly1305 ou AES-GCM. CBC e CTR não autenticam dados.
- Nunca reutilize o mesmo par chave/nonce ou chave/IV.
- Não registre chaves, plaintext, AAD sensível nem payloads completos.
- O pacote não fornece cofre, rotação de chaves, KDF de senha, TLS ou identidade.
- O projeto não declara auditoria criptográfica externa.

Leia [SECURITY.md](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.md) antes de usar em produção.

## Documentação

- [Formato seguro e API](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/formato-seguro.md)
- [Uso e migração](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/uso.md)
- [Compatibilidade de `CryptUtil`](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/crypt_util.md)
- [Política de segurança](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.md)
- [Como contribuir](https://github.com/CriandoGames/all_crypto/blob/main/CONTRIBUTING.md)

Licença [MIT](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE).
