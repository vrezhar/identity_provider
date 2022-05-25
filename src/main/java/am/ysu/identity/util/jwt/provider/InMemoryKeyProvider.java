package am.ysu.identity.util.jwt.provider;

import am.ysu.identity.domain.user.User;
import am.ysu.identity.util.jwt.KeyProvider;
import am.ysu.security.security.util.key.KeyUtils;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

import java.security.*;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;

import static am.ysu.identity.util.jwt.BaseKeyProvider.*;

@Order(Ordered.LOWEST_PRECEDENCE)
public class InMemoryKeyProvider implements KeyProvider, InitializingBean {

    private final ConcurrentHashMap<String, KeyPair> keyPairs = new ConcurrentHashMap<>(5);

    @Override
    public PublicKey getPublicKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        final KeyPair keyPair = keyPairs.get(keyId);
        if(keyPair != null) {
            return keyPair.getPublic();
        }
        return null;
    }

    @Override
    public PrivateKey getPrivateKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        final KeyPair keyPair = keyPairs.get(keyId);
        if(keyPair != null) {
            return keyPair.getPrivate();
        }
        return null;
    }

    @Override
    public KeyPair getAsKeyPair(String keyId) {
        if(keyId == null) {
            return null;
        }
        return keyPairs.get(keyId);
    }

    @Override
    public KeyPair getKeyPair(User user) {
        final var pair = keyPairs.computeIfAbsent(user.getUniqueId().toString(), key -> generateKeyPair(user));
        final var keyId = KeyUtils.calculateFingerPrintHex(pair.getPublic());
        keyPairs.putIfAbsent(keyId, pair);
        return pair;
    }

    @Override
    public KeyPair generateKeyPair(User user) {
        final KeyPairGenerator keyGen;
        final SecureRandom secureRandom;
        try {
            keyGen = KeyPairGenerator.getInstance(RSA_KEYPAIR_GENERATION_ALGORITHM);
            secureRandom = SecureRandom.getInstance(SECURE_RANDOM_GENERATION_ALGORITHM, DEFAULT_CRYPTOGRAPHIC_PROVIDER);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(2048, secureRandom);
        return keyGen.generateKeyPair();
    }

    @Override
    public List<String> availableKeys() {
        return new ArrayList<>(keyPairs.keySet());
    }

    @Override
    public List<String> availableServerKeys() {
        return availableKeys();
    }

    @Override
    public List<String> availableUserKeys() {
        return availableKeys();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        for (int i = 0; i < 5; i++) {
            final KeyPairGenerator keyGen;
            final SecureRandom secureRandom;
            final KeyPair keyPair;
            try {
                secureRandom = SecureRandom.getInstance(SECURE_RANDOM_GENERATION_ALGORITHM, DEFAULT_CRYPTOGRAPHIC_PROVIDER);
                if(i%2 == 0) {
                    keyGen = KeyPairGenerator.getInstance(EC_KEYPAIR_GENERATION_ALGORITHM);
                    keyGen.initialize(256, secureRandom);
                } else {
                    keyGen = KeyPairGenerator.getInstance(RSA_KEYPAIR_GENERATION_ALGORITHM);
                    keyGen.initialize(2048, secureRandom);
                }
                keyPair = keyGen.generateKeyPair();
                keyPairs.put(KeyUtils.calculateFingerPrintHex(keyPair.getPublic()), keyPair);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }
}
