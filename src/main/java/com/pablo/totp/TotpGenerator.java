package com.pablo.totp;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.security.SecureRandom;

public class TotpGenerator {

    private static final int TIME_STEP_SECONDS = 30;
    private static final int CODE_DIGITS = 6;
    private static final String HMAC_ALGORITHM = "HmacSHA1";

    public static String generateSecret() {
        byte[] bytes = new byte[20]; // 160 bits, padrão do TOTP
        new SecureRandom().nextBytes(bytes);
        return Base32.encode(bytes);
    }

    public static String buildOtpAuthUri(String issuer, String accountName, String base32Secret) {
        return String.format("otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=%d&period=%d",
                issuer, accountName, base32Secret, issuer, CODE_DIGITS, TIME_STEP_SECONDS);
    }

    public String generate(String base32Secret, long unixTimeSeconds) throws Exception {
        byte[] key = Base32.decode(base32Secret);
        long counter = unixTimeSeconds / TIME_STEP_SECONDS;
        byte[] counterBytes = ByteBuffer.allocate(8).putLong(counter).array();

        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(new SecretKeySpec(key, HMAC_ALGORITHM));
        byte[] hash = mac.doFinal(counterBytes);

        // Truncamento dinâmico (RFC 4226, seção 5.3)
        int offset = hash[hash.length - 1] & 0x0F;
        int binaryCode = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

        int code = binaryCode % (int) Math.pow(10, CODE_DIGITS);
        return String.format("%0" + CODE_DIGITS + "d", code);
    }

    public boolean validate(String base32Secret, String submittedCode, long unixTimeSeconds) throws Exception {
        for (int drift = -1; drift <= 1; drift++) {
            long adjustedTime = unixTimeSeconds + (drift * (long) TIME_STEP_SECONDS);
            if (generate(base32Secret, adjustedTime).equals(submittedCode)) {
                return true;
            }
        }
        return false;
    }
}
