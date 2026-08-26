# 2FA Simulator

> ⚠️ Projeto educacional criado para fins de aprendizado em cyber security. Use apenas em sistemas próprios ou com autorização explícita.

## O que é

Implementação do algoritmo TOTP (RFC 6238) do zero — o mesmo usado pelo Google Authenticator, Authy etc. — sem depender de nenhuma biblioteca pronta de 2FA. Gera segredos, códigos de 6 dígitos e valida códigos com tolerância a variação de relógio (clock drift).

## Tecnologias

- Java 17+, Maven
- `javax.crypto.Mac` (HMAC-SHA1, nativo do JDK)
- Implementação própria de Base32 (RFC 4648), usada para codificar o segredo
- JUnit 5 — testes, validados contra os vetores oficiais da RFC 6238

## Como rodar

```bash
mvn clean package
java -jar target/totp-simulator-1.0.0.jar
```

O comando acima gera um novo segredo, a URI `otpauth://` (compatível com apps reais de autenticação) e o código atual. Para validar um código depois:

```bash
java -jar target/totp-simulator-1.0.0.jar validate <segredo> <codigo>
```

## Testes

```bash
mvn test
```

## O que aprendi

- Como HMAC-SHA1 + um contador de tempo (janela de 30s) viram um código de 6 dígitos (RFC 4226 / RFC 6238).
- Codificação Base32, usada nos segredos do Google Authenticator, implementada do zero.
- Por que aceitar o código da janela de tempo anterior/seguinte é necessário na prática (tolerância a clock drift) sem abrir uma janela de validade longa demais.
