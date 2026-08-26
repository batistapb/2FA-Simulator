package com.pablo.totp;

import java.time.Instant;

public class Main {

    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            generateAndPrintAccount();
        } else if (args.length == 3 && args[0].equals("validate")) {
            validateCode(args[1], args[2]);
        } else {
            printUsage();
        }
    }

    private static void generateAndPrintAccount() throws Exception {
        String secret = TotpGenerator.generateSecret();
        String uri = TotpGenerator.buildOtpAuthUri("OSINT-Portfolio", "demo@exemplo.com", secret);
        TotpGenerator generator = new TotpGenerator();
        String code = generator.generate(secret, Instant.now().getEpochSecond());

        System.out.println("Segredo (Base32): " + secret);
        System.out.println("URI otpauth:      " + uri);
        System.out.println("Código atual:     " + code);
        System.out.println();
        System.out.println("Para validar depois: java -jar totp-simulator.jar validate " + secret + " <codigo>");
    }

    private static void validateCode(String secret, String code) throws Exception {
        TotpGenerator generator = new TotpGenerator();
        boolean valid = generator.validate(secret, code, Instant.now().getEpochSecond());
        System.out.println(valid ? "Código válido." : "Código inválido ou expirado.");
    }

    private static void printUsage() {
        System.out.println("Uso:");
        System.out.println("  java -jar totp-simulator.jar                          gera um novo segredo e mostra o código atual");
        System.out.println("  java -jar totp-simulator.jar validate <secret> <code> valida um código para um segredo");
    }
}
