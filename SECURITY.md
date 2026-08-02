# Segurança

## Formato recomendado: `CryptEnvelope` + `AllCrypto`

Use `AllCrypto.encryptText`/`encryptBytes` para cifrar e `AllCrypto.decryptText`/`decryptBytes` para decifrar. O resultado é um `CryptEnvelope`, que serializa **apenas** algoritmo, ciphertext, nonce/IV, tag e AAD — a chave **nunca** é incluída em `toJson()`/`toBase64()`. Toda decifragem exige a chave como parâmetro explícito, fornecida por você a partir de um cofre externo (`flutter_secure_storage`, keychain do SO, KMS, variável de ambiente segura). O envelope tem um campo `version` explícito (atualmente `2`); `CryptEnvelope.fromJson`/`fromBase64` rejeitam versão ausente, não numérica ou diferente da suportada, e rejeitam algoritmo desconhecido — sempre com `ArgumentError` claro, nunca decodificação silenciosa.

## Falha preexistente no formato legado — chave embutida no payload

`EncryptedPayload.toJson()`/`toBase64()` (e os atalhos `CryptUtil.encryptToBase64()`/`decryptFromBase64()`) serializam a chave simétrica **dentro** do próprio payload cifrado. Isso é um comportamento **preexistente** à extração deste pacote (herdado do agregador `all_validations_br`), reproduzido e comprovado em `test/legacy_vulnerability_test.dart`: qualquer pessoa que obtenha o Base64/JSON legado consegue extrair a chave e decifrar o conteúdo, sem precisar conhecê-la de antemão. Esse formato **nunca ofereceu confidencialidade contra quem possui o payload** — na prática, ele só protege dados quando o próprio armazenamento já é a fronteira de segurança (ex.: um app mobile guardando o Base64 no seu sandbox de disco, onde o sistema operacional impede outros apps de lerem o arquivo).

Essas APIs permanecem disponíveis e continuam decodificando payloads históricos corretamente (não foram removidas nem tiveram o formato alterado silenciosamente), mas estão marcadas `@Deprecated` com uma mensagem explicando o problema e apontando o substituto. **Não use o formato legado em código novo.** Use `AllCrypto.migrateLegacy` para converter um `EncryptedPayload` existente em um `CryptEnvelope` (sem chave) mais a chave extraída separadamente — e considere rotacionar a chave se o Base64 legado já tiver circulado fora de um armazenamento confiável.

Remoção planejada para `all_crypto` 2.0.0 (política de compatibilidade semver).

## Versionamento do envelope

`CryptEnvelope.version` é o schema do formato serializado, independente da versão do pacote Dart (`pubspec.yaml`) — os dois números evoluem separadamente. Versão atual: `2`. O formato legado (`EncryptedPayload`, sem campo de versão) é tratado como "v1" apenas para fins de migração/documentação; ele nunca teve um campo `version` real, e essa lacuna também é reproduzida em teste.

## Escopo de proteção

ChaCha20-Poly1305 e AES-GCM podem fornecer confidencialidade e integridade quando usados com chaves secretas fortes, gerenciadas fora do payload, e nonces exclusivos. HMAC-SHA256 autentica mensagens. SHA-256 produz digest. AES-CBC e AES-CTR fornecem somente confidencialidade e precisam de autenticação independente (veja abaixo).

## AES-CBC e AES-CTR — limites do modo não autenticado

Nem AES-CBC nem AES-CTR produzem tag de autenticação — o campo `tag` desses payloads/envelopes é sempre vazio. Isso significa que:

- ciphertext adulterado em CBC pode decifrar para dados corrompidos silenciosamente aceitos (padding PKCS#7 quebrado nem sempre lança erro em todos os padrões de adulteração) e nunca é detectado por criptografia — só pela aplicação, se ela validar o conteúdo;
- ciphertext adulterado em CTR decifra para um plaintext alterado nos bytes correspondentes, sem qualquer sinalização de erro — CTR é simplesmente XOR com o keystream, então bit flips no ciphertext viram bit flips previsíveis no plaintext;
- reutilizar o mesmo par (chave, IV/contador) em CTR anula completamente a confidencialidade dos dois textos cifrados (XOR dos dois ciphertexts revela o XOR dos dois plaintexts).

Para qualquer cenário onde adulteração é uma ameaça relevante — o caso comum — prefira ChaCha20-Poly1305 ou AES-GCM (AEAD). Se precisar interoperar com CBC/CTR por causa de um sistema externo, combine com um protocolo encrypt-then-MAC bem especificado (ex.: HMAC-SHA256 sobre o ciphertext, verificado em tempo constante antes de decifrar) — não invente uma combinação própria sem revisão especializada.

## Fora do escopo

O pacote não gerencia armazenamento, distribuição, rotação ou revogação de chaves; não substitui TLS; não autentica usuários; não é um gerenciador de segredos; e não oferece função dedicada para derivar chaves de senhas. Hash SHA-256 simples e o hash legado de `HelperUtil` não são adequados para armazenar senhas.

## Chaves, nonce e IV

- Gere chaves com `AllCrypto.generateKey()`/`generateKey128()` (fonte aleatória segura) e armazene-as fora do código, do repositório e — no formato recomendado — fora do próprio payload cifrado.
- Nunca reutilize nonce/contador com a mesma chave em ChaCha20-Poly1305, AES-GCM ou AES-CTR. Deixe a API gerar o nonce automaticamente (`nonce` omitido) sempre que possível.
- IV imprevisível é necessário para AES-CBC; um IV não é uma chave e não precisa ser secreto, apenas único e imprevisível por mensagem.
- Valide os comprimentos exigidos pela API (a própria API rejeita tamanhos inválidos com `ArgumentError`) e planeje rotação de chave antes de persistir dados por longos períodos.

## Logs e erros

Não registre chaves, nonces associados a contexto sensível, plaintext, senha, token, cartão completo, CPF/CNPJ completo, ou o payload criptográfico integral (`CryptEnvelope`/`EncryptedPayload` completos, inclusive em formato de string/Base64) em logs de aplicação, crash reporters ou telemetria. Mensagens de exceção (`CryptException.message`, mensagens de `ArgumentError`) servem a diagnóstico interno, não a decisões de autorização nem a exibição direta ao usuário final.

## Limitações e auditoria

A suíte de testes inclui vetores publicados (RFC 8439 para ChaCha20-Poly1305, NIST SP 800-38A/38D e FIPS 197 para AES, RFC 4231 para HMAC-SHA256, NIST para SHA-256), testes negativos (adulteração, chave errada, tamanhos inválidos, payload truncado/malformado, versão e algoritmo desconhecidos) e testes diferenciais cross-verificados com o backend OpenSSL exposto pelo `crypto` do Node.js — mas isso **não equivale a uma auditoria externa formal**. O projeto não afirma ser auditado nem adequado automaticamente a qualquer requisito regulatório (LGPD, PCI-DSS, etc.); avalie a adequação para seu caso de uso com especialistas próprios.

## Reporte responsável

Não abra detalhes exploráveis em issue pública. Use o canal privado de segurança do repositório GitHub ou contate o mantenedor pelo perfil do publisher. Inclua versão, algoritmo, impacto, reprodução mínima sem dados reais e sugestão de mitigação. Aguarde coordenação antes de divulgação pública.
