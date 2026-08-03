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

## Por que usar

Criptografar bytes é apenas parte do problema: a aplicação também precisa
transportar algoritmo, nonce, tag e metadados sem colocar a chave junto do
ciphertext. `all_crypto` entrega esse contrato em uma API Dart pura e em um
envelope versionado pronto para persistência ou transporte.

- Cifragem autenticada por padrão: confidencialidade e detecção de adulteração.
- Chave sempre fornecida externamente e nunca serializada no envelope v2.
- Um formato estável para banco local, backend, fila ou arquivo.
- A mesma API para texto e bytes, sem plugins nativos ou vínculo com Flutter.
- Primitivas para integridade, autenticação de mensagem e interoperabilidade.
- Migração explícita para aplicações que ainda possuem payloads históricos.

## Recursos

- ChaCha20-Poly1305 (padrão) e AES-GCM, ambos AEAD.
- AES-CBC/PKCS#7 e AES-CTR para interoperabilidade legada.
- SHA-256, HMAC-SHA256 e comparação de MAC em tempo constante.
- `AllCrypto` + `CryptEnvelope` para payloads sem chave e com schema v2.
- Leitura e migração explícita de payloads históricos de `EncryptedPayload`.
- Dart puro, sem Flutter, plugins nativos ou dependências de produção.

## Escolha rápida

| Necessidade | API recomendada |
|---|---|
| Cifrar dados novos | `AllCrypto` com ChaCha20-Poly1305, padrão do pacote |
| Interoperar com sistemas AES autenticados | `AllCrypto` com `CryptAlgorithm.aesGcm` |
| Persistir ou transportar ciphertext | `CryptEnvelope.toJson()` ou `toBase64()` |
| Cifrar arquivos ou conteúdo binário | `encryptBytes` e `decryptBytes` |
| Calcular digest de integridade | `sha256` |
| Autenticar uma mensagem | `hmacSha256` e `hmacEqual` |
| Ler dados históricos | `EncryptedPayload.fromJson`/`fromBase64` |
| Separar a chave de um payload histórico | `AllCrypto.migrateLegacy` e posterior rotação da chave |

Para código novo, use `AllCrypto` e `CryptEnvelope`. `CryptUtil` permanece
somente para compatibilidade com integrações existentes.

## Instalação

```yaml
dependencies:
  all_crypto: ^1.0.2
```

```dart
import 'package:all_crypto/all_crypto.dart';
```

## Exemplos de uso real

### Dados em repouso com chave externa

```dart
import 'dart:convert';

import 'package:all_crypto/all_crypto.dart';

final key = AllCrypto.generateKey(); // guarde em keychain, KMS ou cofre
final aad = utf8.encode('tenant:acme|record:42|schema:1');
final envelope = AllCrypto.encryptText(
  'segredo',
  key: key,
  aad: aad,
);
final encoded = envelope.toBase64(); // nunca contém a chave

final restored = CryptEnvelope.fromBase64(encoded);
final value = AllCrypto.decryptText(restored, key: key);
```

O AAD não é cifrado, mas é autenticado junto do conteúdo. Ele pode vincular o
ciphertext ao tenant, registro ou versão de schema; qualquer alteração faz a
verificação AEAD falhar. Não coloque informações sensíveis no AAD.

### Interoperabilidade com AES-GCM

```dart
final aesKey = AllCrypto.generateKey();
final order = {'id': 'order_42', 'totalInCents': 15990};
final envelope = AllCrypto.encryptText(
  jsonEncode(order),
  key: aesKey,
  algorithm: CryptAlgorithm.aesGcm,
  aad: utf8.encode('orders:v1'),
);

final token = envelope.toBase64();
```

O sistema que consumir o payload precisa compartilhar exatamente o protocolo:
algoritmo, tamanho de chave, nonce, tag, AAD e codificação. O envelope organiza
esses campos, mas não distribui a chave.

### Arquivos e conteúdo binário

```dart
final encrypted = AllCrypto.encryptBytes(fileBytes, key: key);
await storage.write(encrypted.toBase64());

final restored = CryptEnvelope.fromBase64(await storage.read());
final originalBytes = AllCrypto.decryptBytes(restored, key: key);
```

### Integridade e autenticação de mensagens

```dart
final bytes = utf8.encode(payload);
final digest = sha256(bytes); // integridade, não autenticação

final expectedMac = hmacSha256(macKey, bytes);
final authentic = hmacEqual(expectedMac, receivedMac);
```

SHA-256 detecta alteração acidental quando o digest esperado vem de uma fonte
confiável. HMAC-SHA256 comprova conhecimento da chave compartilhada; compare
tags com `hmacEqual`.

## Exemplo completo

O [exemplo executável](https://github.com/CriandoGames/all_crypto/blob/main/example/all_crypto_example.dart) reúne fluxos que podem
ser adaptados diretamente para uma aplicação:

- registro JSON protegido com chave externa e AAD;
- interoperabilidade com AES-GCM;
- conteúdo binário, como anexos e arquivos;
- digest SHA-256 para comparação com uma fonte confiável;
- assinatura e verificação de webhook com HMAC-SHA256;
- rejeição de ciphertext adulterado pela autenticação AEAD.

Execute com:

```bash
dart run example/all_crypto_example.dart
```

O exemplo imprime somente o resultado das verificações, nunca chaves,
plaintext ou tokens, e seus cenários são cobertos por `test/documentation/`.

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

## Quando usar

Use `all_crypto` quando você controla o gerenciamento da chave e precisa cifrar
texto ou bytes em Dart puro, armazenar um envelope versionado, autenticar
mensagens ou interoperar com os algoritmos oferecidos. Ele é adequado para
componentes de infraestrutura e bibliotecas que precisam de um contrato
criptográfico explícito.

Não use o pacote como substituto para TLS, cofre de segredos, autenticação de
usuários ou derivação de senha. Requisitos regulatórios e protocolos próprios
exigem revisão especializada. A suíte é extensa, mas o projeto não declara
auditoria criptográfica externa.

## Documentação

- [Formato seguro e API](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/formato-seguro.md)
- [Uso e migração](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/uso.md)
- [Compatibilidade de `CryptUtil`](https://github.com/CriandoGames/all_crypto/blob/main/doc/pt-BR/crypt_util.md)
- [Política de segurança](https://github.com/CriandoGames/all_crypto/blob/main/SECURITY.md)
- [Como contribuir](https://github.com/CriandoGames/all_crypto/blob/main/CONTRIBUTING.md)

Licença [MIT](https://github.com/CriandoGames/all_crypto/blob/main/LICENSE).
