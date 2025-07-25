package org.acme.utils;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

public class SRP6 {

    private final BigInteger N;
    private final BigInteger g;
    private final BigInteger k;

    private final SecureRandom random = new SecureRandom();

    public SRP6() {
        // 256-bit prime из TrinityCore WoW
        N = new BigInteger("B79B3E2A878DBEDF5AD53B139A99D8CEC8DA65FED1BD845FB70F6051754B8D36", 16);
        g = BigInteger.valueOf(7);
        k = calculateK();
    }

    private BigInteger calculateK() {
        byte[] N_bytes = N.toByteArray();
        byte[] g_bytes = g.toByteArray();

        byte[] toHash = new byte[N_bytes.length + g_bytes.length];
        System.arraycopy(N_bytes, 0, toHash, 0, N_bytes.length);
        System.arraycopy(g_bytes, 0, toHash, N_bytes.length, g_bytes.length);

        return new BigInteger(1, sha1(toHash));
    }

    /**
     * Генерирует случайный 32-байтовый salt и verifier по логину и паролю (TrinityCore стиль)
     * @param username логин
     * @param password пароль
     * @return объект с salt и verifier
     */
    public GeneratedVerifier generateSaltAndVerifierTrinity(String username, String password) {
        byte[] saltBytes = new byte[32];
        random.nextBytes(saltBytes);

        String up = toUppercaseAscii(username) + ":" + password;

        byte[] innerHash = sha1(up.getBytes(StandardCharsets.UTF_8));

        byte[] toHash = new byte[saltBytes.length + innerHash.length];
        System.arraycopy(saltBytes, 0, toHash, 0, saltBytes.length);
        System.arraycopy(innerHash, 0, toHash, saltBytes.length, innerHash.length);

        byte[] xHash = sha1(toHash);
        BigInteger x = new BigInteger(1, xHash);

        BigInteger v = g.modPow(x, N);

        return new GeneratedVerifier(saltBytes, v.toByteArray());
    }

    /**
     * Проверяет корректность пароля по базе (логин, пароль, salt и verifier из БД)
     * @param username логин
     * @param password пароль пользователя
     * @param salt соль из базы (32 байта)
     * @param verifier verifier из базы (байты)
     * @return true если пароль правильный, false иначе
     */
    public boolean verifyPassword(String username, String password, byte[] salt, byte[] verifier) {
        String up = toUppercaseAscii(username) + ":" + password;

        byte[] innerHash = sha1(up.getBytes(StandardCharsets.UTF_8));

        byte[] toHash = new byte[salt.length + innerHash.length];
        System.arraycopy(salt, 0, toHash, 0, salt.length);
        System.arraycopy(innerHash, 0, toHash, salt.length, innerHash.length);

        byte[] xHash = sha1(toHash);
        BigInteger x = new BigInteger(1, xHash);

        BigInteger vLocal = g.modPow(x, N);

        BigInteger vDb = new BigInteger(1, verifier);

        return vLocal.equals(vDb);
    }

    // --- Вспомогательные методы ---

    private String toUppercaseAscii(String str) {
        StringBuilder sb = new StringBuilder(str.length());
        for (char c : str.toCharArray()) {
            if (c >= 'a' && c <= 'z') sb.append((char)(c - 'a' + 'A'));
            else sb.append(c);
        }
        return sb.toString();
    }

    private byte[] sha1(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            return md.digest(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static class GeneratedVerifier {
        public final byte[] salt;
        public final byte[] verifier;

        public GeneratedVerifier(byte[] salt, byte[] verifier) {
            this.salt = salt;
            this.verifier = verifier;
        }
    }
}