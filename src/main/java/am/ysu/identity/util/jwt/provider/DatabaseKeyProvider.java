package am.ysu.identity.util.jwt.provider;

import am.ysu.identity.domain.security.KeyPairHolder;
import am.ysu.identity.dao.ServerKeyDao;
import am.ysu.identity.dao.user.UserKeysDao;
import am.ysu.identity.domain.security.server.ServerSigningKey;
import am.ysu.identity.util.jwt.BaseKeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.security.*;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

@Order(Ordered.HIGHEST_PRECEDENCE)
@Component("keyProvider")
@ConditionalOnProperty(value = "security.key.provider.class", havingValue = "DatabaseKeyProvider")
public class DatabaseKeyProvider extends BaseKeyProvider implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(DatabaseKeyProvider.class);
    //Can be configured
    private int defaultKeyCount = 4;
    private final ServerKeyDao serverKeyDao;
    private final ConcurrentHashMap<String, PublicKey> publicKeyCache = new ConcurrentHashMap<>();

    public DatabaseKeyProvider(ServerKeyDao serverKeyDao, UserKeysDao userKeysDao) {
        super(userKeysDao);
        this.serverKeyDao = serverKeyDao;
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        return publicKeyCache.computeIfAbsent(
                keyId, key -> serverKeyDao.findByKeyId(key)
                        .map(KeyPairHolder::decodePublicKey)
                        .or(() -> Optional.ofNullable(super.getPublicKey(keyId)))
                        .orElseThrow()
        );
    }

    @Override
    public PrivateKey getPrivateKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        final var key = serverKeyDao.findByKeyId(keyId).orElse(null);
        if(key == null) {
            final var userKey = super.getPrivateKey(keyId);
            if(userKey != null) {
                return userKey;
            }
            throw new NoSuchElementException();
        }
        publicKeyCache.put(keyId, key.decodePublicKey());
        return key.decodePrivateKey();
    }

    @Override
    public KeyPair getKeyPair(String keyId) {
        if(keyId == null) {
            return null;
        }
        var pair = super.getKeyPair(keyId);
        if(pair != null) {
            return pair;
        }
        final var serverKeys = serverKeyDao.findByKeyId(keyId).orElseThrow();
        pair = serverKeys.asKeypair();
        publicKeyCache.put(serverKeys.getKeyId(), pair.getPublic());
        return pair;
//        try {
//            final var pair = super.getKeyPair(keyId);
//            if(pair != null) {
//                return pair;
//            }
//            return serverKeyDao.findByKeyId(keyId).orElseThrow().asKeypair();
//        } catch (Exception e) {
//            logger.error("Unexpected exception {} from key id {}({})", e.getClass().getSimpleName(), keyId, e.getMessage());
//            throw new RuntimeException(e);
//        }
    }

    @Override
    public List<String> availableKeys() {
        final List<String> userKeys = super.availableKeys();
        final List<String> serverKeys = availableServerKeys();
        final List<String> allKeys = new ArrayList<>(userKeys.size() + serverKeys.size());
        allKeys.addAll(userKeys);
        allKeys.addAll(serverKeys);
        return allKeys;
    }

    @Override
    public List<String> availableServerKeys() {
        return StreamSupport.stream(serverKeyDao.findAll().spliterator(), false)
                .map(key -> {
                    final String keyId = key.getKeyId();
                    publicKeyCache.put(keyId, key.decodePublicKey());
                    return keyId;
                })
                .collect(Collectors.toList());
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        final var keys = serverKeyDao.findAll();
        if(!keys.iterator().hasNext()) {
            logger.info("Starting to initialize server keys");
            for (int i = 0; i < defaultKeyCount; i++) {
                final KeyPairGenerator keyGen;
                final SecureRandom secureRandom;
                try {
                    secureRandom = SecureRandom.getInstance(SECURE_RANDOM_GENERATION_ALGORITHM, DEFAULT_CRYPTOGRAPHIC_PROVIDER);
                    if(i%2 == 0) {
                        keyGen = KeyPairGenerator.getInstance(RSA_KEYPAIR_GENERATION_ALGORITHM);
                        keyGen.initialize(2048, secureRandom);
                        final KeyPair keyPair = keyGen.generateKeyPair();
                        serverKeyDao.save(new ServerSigningKey((RSAPrivateKey)keyPair.getPrivate(), (RSAPublicKey)keyPair.getPublic()));
                    } else {
                        keyGen = KeyPairGenerator.getInstance(EC_KEYPAIR_GENERATION_ALGORITHM);
                        keyGen.initialize(256, secureRandom);
                        final KeyPair keyPair = keyGen.generateKeyPair();
                        serverKeyDao.save(new ServerSigningKey((ECPrivateKey)keyPair.getPrivate(), (ECPublicKey)keyPair.getPublic()));
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        }
    }
}
