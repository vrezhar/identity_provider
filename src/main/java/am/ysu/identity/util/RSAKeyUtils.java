package am.ysu.identity.util;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class RSAKeyUtils
{
    private static KeyFactory keyfactory;
    private static final String PUBLIC_KEY_START = "-----BEGIN PUBLIC KEY-----";
    private static final String PRIVATE_KEY_START = "-----BEGIN PRIVATE KEY-----";
    private static final String PRIVATE_KEY_END = "-----END PRIVATE KEY-----";
    private static final String PUBLIC_KEY_END = "-----END PUBLIC KEY-----";

    static {
        try {
            keyfactory = KeyFactory.getInstance("RSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
    }

    /**
     * Constructs an RSA public key from a simple string
     * @param publicKey the string representing the public key, can include the "-----BEGIN PUBLIC KEY-----" and "-----END PUBLIC KEY-----" lines
     * @return The constructed public key
     * @throws InvalidKeySpecException if the string doesn't actually contain a valid public key
     */
    public static RSAPublicKey getPublicKey(final String publicKey) throws InvalidKeySpecException
    {
        if(keyfactory == null){
            return null;
        }
        return (RSAPublicKey) keyfactory.generatePublic(
                new X509EncodedKeySpec(
                        Base64
                                .getDecoder()
                                .decode(
                                        publicKey
                                                .replace(PUBLIC_KEY_START, "")
                                                .replaceAll(System.lineSeparator(), "")
                                                .replace(PUBLIC_KEY_END, "").getBytes(StandardCharsets.UTF_8)
                                )
                )
        );
    }

    /**
     * Constructs an RSA private key from a simple string
     * @param privateKey the string representing the private key, can include the "-----BEGIN PRIVATE KEY-----" and "-----END PRIVATE KEY-----" lines
     * @return The private key constructed from the string
     * @throws InvalidKeySpecException if the string doesn't actually contain a valid private key
     */
    public static RSAPrivateKey getPrivateKey(final String privateKey) throws InvalidKeySpecException
    {
        if(keyfactory == null){
            return null;
        }
        return (RSAPrivateKey) keyfactory.generatePrivate(
                new PKCS8EncodedKeySpec(
                        Base64
                                .getDecoder()
                                .decode(
                                        privateKey
                                                .replace(PRIVATE_KEY_START, "")
                                                .replaceAll(System.lineSeparator(), "")
                                                .replace(PRIVATE_KEY_END, "")
                                )
                )
        );
    }

    /**
     * Calculates the fingerprint of the given public key in sha-256 format
     * @param publicKey The public key
     * @return The generated fingerprint
     * @throws NoSuchAlgorithmException If SHA-256 algorithm is not supported, usually indicates a problem with the jdk
     */
    public static String calculateFingerPrintBase64(RSAPublicKey publicKey) throws NoSuchAlgorithmException
    {
        MessageDigest messageDigest = getSha256Digest();
        messageDigest.update(publicKey.getEncoded());
        return Base64.getEncoder().encodeToString(messageDigest.digest());
    }

    public static String calculateFingerPrintHex(RSAPublicKey publicKey)
    {
        MessageDigest messageDigest = getSha256Digest();
        messageDigest.update(publicKey.getEncoded());
        byte[] fingerprint = messageDigest.digest();
        StringBuilder fingerprintHex = new StringBuilder();
        for(byte b : fingerprint){
            String hex = Integer.toHexString(b & 0xff);
            if(hex.length() == 1){
                fingerprintHex.append(0);
            }
            fingerprintHex.append(hex);
        }
        return fingerprintHex.toString();
    }

    private static MessageDigest getSha256Digest() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException ne) {
            throw new RuntimeException(ne);
        }
    }
}
