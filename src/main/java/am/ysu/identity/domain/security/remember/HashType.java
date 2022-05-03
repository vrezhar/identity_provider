package am.ysu.identity.domain.security.remember;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.function.Function;

public enum HashType {
    MD5((raw) -> digestWith("MD5", raw)),
    SHA256((raw) -> digestWith("SHA-256", raw)),
    SHA384((raw) -> digestWith("SHA-384", raw)),
    SHA512((raw) -> digestWith("SHA-512", raw));

    private final Function<String, byte[]> hashingFunction;

    HashType(Function<String, byte[]> hashingFunction) {
        this.hashingFunction = hashingFunction;
    }

    public boolean validate(String cookieValue, byte[] hash) {
        return Arrays.equals(hashingFunction.apply(cookieValue), hash);
    }

    public byte[] hash(String value) {
        return hashingFunction.apply(value);
    }

    private static byte[] digestWith(String alg, String value) {
        try {
            final MessageDigest md = MessageDigest.getInstance(alg);
            md.update(value.getBytes(StandardCharsets.UTF_8));
            return md.digest();
        } catch(NoSuchAlgorithmException nse) {
            throw new RuntimeException("Digest algorithm " + alg + " not available");
        }
    }
}