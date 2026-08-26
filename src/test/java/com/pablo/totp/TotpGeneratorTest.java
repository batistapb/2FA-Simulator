package com.pablo.totp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TotpGeneratorTest {

    // Segredo de teste oficial da RFC 6238, Apêndice B (ASCII "12345678901234567890"), em Base32.
    private static final String RFC_SECRET_BASE32 =
            Base32.encode("12345678901234567890".getBytes(StandardCharsets.US_ASCII));

    private final TotpGenerator generator = new TotpGenerator();

    @Test
    void matchesRfc6238TestVectors() throws Exception {
        // A RFC 6238 publica códigos de 8 dígitos (SHA-1). Como esta implementação usa 6 dígitos,
        // e 10^8 é múltiplo de 10^6, o valor esperado é (codigo_rfc mod 10^6) = últimos 6 dígitos.
        assertEquals("287082", generator.generate(RFC_SECRET_BASE32, 59L));
        assertEquals("081804", generator.generate(RFC_SECRET_BASE32, 1111111109L));
        assertEquals("050471", generator.generate(RFC_SECRET_BASE32, 1111111111L));
        assertEquals("005924", generator.generate(RFC_SECRET_BASE32, 1234567890L));
        assertEquals("279037", generator.generate(RFC_SECRET_BASE32, 2000000000L));
    }

    @Test
    void validateAcceptsCodeFromPreviousTimeStep() throws Exception {
        String secret = TotpGenerator.generateSecret();
        long now = 1_700_000_000L;

        String codeFromPreviousStep = generator.generate(secret, now - 30);

        assertTrue(generator.validate(secret, codeFromPreviousStep, now));
    }

    @Test
    void validateRejectsCodeOutsideDriftWindow() throws Exception {
        String secret = TotpGenerator.generateSecret();
        long now = 1_700_000_000L;

        String oldCode = generator.generate(secret, now - 120); // 4 janelas atrás

        assertFalse(generator.validate(secret, oldCode, now));
    }

    @Test
    void buildOtpAuthUriIncludesSecretAndIssuer() {
        String uri = TotpGenerator.buildOtpAuthUri("MinhaApp", "user@exemplo.com", "JBSWY3DPEHPK3PXP");

        assertTrue(uri.startsWith("otpauth://totp/"));
        assertTrue(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assertTrue(uri.contains("issuer=MinhaApp"));
    }
}
