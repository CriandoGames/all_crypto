# Changelog

## Não lançado

- **Correção de segurança (formato preexistente, não regressão da extração)**: `EncryptedPayload.toJson()`/`toBase64()` serializavam a chave simétrica junto com o ciphertext, então quem possuísse o payload conseguia decifrá-lo. Adicionado `CryptEnvelope` — formato seguro e versionado (campo `version`, atualmente `2`) que nunca serializa a chave — e a fachada `AllCrypto` (`encryptText`, `decryptText`, `encryptBytes`, `decryptBytes`, `migrateLegacy`, `generateKey`, `generateKey128`, `generateNonce`, `generateIv`).
- `CryptEnvelope.fromJson`/`fromBase64` rejeitam versão ausente/desconhecida e algoritmo desconhecido com `ArgumentError` claro.
- `EncryptedPayload.toJson()`, `EncryptedPayload.toBase64()`, `CryptUtil.encryptToBase64()` e `CryptUtil.decryptFromBase64()` marcados `@Deprecated`, com mensagem explicando o problema, o substituto e o pacote/import corretos. Mantidos funcionais para compatibilidade e leitura de payloads históricos — nenhuma remoção nesta versão.
- `AllCrypto.migrateLegacy` converte um `EncryptedPayload` legado em `CryptEnvelope` + chave extraída separadamente.
- Novos testes: reprodução da falha preexistente (`test/legacy_vulnerability_test.dart`), vetor oficial RFC 8439 §2.8.2 para ChaCha20-Poly1305 (`test/vectors/rfc8439_test.dart`), testes diferenciais cross-verificados com OpenSSL/Node.js (`test/differential/openssl_cross_check_test.dart`), suíte completa de `CryptEnvelope`/`AllCrypto` — round-trip por algoritmo, adulteração, chave/nonce inválidos, payload malformado/truncado, migração, fixture Base64 histórica congelada (`test/crypt_envelope_test.dart`).
- Documentação PT-BR/EN atualizada e equalizada: `README.md`/`README.en.md` (motivação, badges, formato recomendado x legado), `SECURITY.md`/`SECURITY.en.md` (falha preexistente, versionamento, limites de CBC/CTR, o que não logar), novo `doc/pt-BR/formato-seguro.md` + `doc/en/secure-format.md`, `doc/pt-BR/crypt_util.md` corrigido para não recomendar mais o padrão de chave embutida + novo `doc/en/crypt_util.md` (antes só um resumo mínimo existia em inglês), `doc/pt-BR/uso.md`/`doc/en/usage.md` atualizados.
- Exemplo principal (`example/all_crypto_example.dart`) e teste de documentação atualizados para usar exclusivamente `AllCrypto`/`CryptEnvelope`.

## 1.0.0

- Extração da implementação criptográfica do `all_validations_br` 4.5.2.
- Preservação de `CryptUtil`, payloads, algoritmos e formatos existentes.
- Inclusão de testes de vetores, round-trip, adulteração, chaves e tamanhos inválidos.
- Documentação bilíngue e orientação de segurança.

