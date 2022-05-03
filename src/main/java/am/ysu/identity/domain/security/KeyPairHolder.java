package am.ysu.identity.domain.security;

import am.ysu.security.security.util.key.KeyUtils;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

public interface KeyPairHolder {
    String getPublicKey();

    String getPrivateKey();

    KeyType getKeyType();

    default PublicKey decodePublicKey() {
        final KeyType keyType = getKeyType();
        switch (keyType) {
            case RSA:
                try {
                    return KeyUtils.getRsaPublicKey(getPublicKey());
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt public key in database", e);
                }
            case EC:
                try {
                    return KeyUtils.getEcPublicKey(getPublicKey());
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt public key in database", e);
                }
            default:
                throw new IllegalArgumentException("Unsupported key type [" + keyType + "]");
        }
    }

    default PrivateKey decodePrivateKey() {
        final KeyType keyType = getKeyType();
        switch (keyType) {
            case RSA:
                try {
                    return KeyUtils.getRsaPrivateKey(getPublicKey());
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt public key in database", e);
                }
            case EC:
                try {
                    return KeyUtils.getEcPrivateKey(getPublicKey());
                } catch (InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt public key in database", e);
                }
            default:
                throw new IllegalArgumentException("Unsupported key type [" + keyType + "]");
        }
    }

    default KeyPair asKeypair() {
        final KeyType keyType = getKeyType();
        switch (keyType) {
            case RSA:
                try {
                    return new KeyPair(KeyUtils.getRsaPublicKey(getPublicKey()), KeyUtils.getRsaPrivateKey(getPrivateKey()));
                } catch(InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt key pair in the database", e);
                }
            case EC:
                try {
                    return new KeyPair(KeyUtils.getEcPublicKey(getPublicKey()), KeyUtils.getEcPrivateKey(getPrivateKey()));
                } catch(InvalidKeySpecException e) {
                    throw new RuntimeException("Corrupt key pair in the database", e);
                }
            default:
                throw new IllegalArgumentException("Unsupported key type [" + keyType + "]");
        }
    }
}
