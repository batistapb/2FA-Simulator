package com.pablo.totp;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Base32Test {

    @Test
    void encodesRfc4648TestVectors() {
        assertEquals("MY", Base32.encode("f".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXQ", Base32.encode("fo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6", Base32.encode("foo".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YQ", Base32.encode("foob".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YTB", Base32.encode("fooba".getBytes(StandardCharsets.US_ASCII)));
        assertEquals("MZXW6YTBOI", Base32.encode("foobar".getBytes(StandardCharsets.US_ASCII)));
    }

    @Test
    void decodeReversesEncode() {
        byte[] original = "hello totp secret".getBytes(StandardCharsets.US_ASCII);

        byte[] roundTripped = Base32.decode(Base32.encode(original));

        assertArrayEquals(original, roundTripped);
    }

    @Test
    void decodeRejectsInvalidCharacters() {
        assertThrows(IllegalArgumentException.class, () -> Base32.decode("this-is-not-base32!"));
    }
}
