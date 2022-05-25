package am.ysu.identity.util.jwt;

import am.ysu.identity.domain.user.UserKeys;
import am.ysu.identity.dao.user.UserKeysDao;
import am.ysu.identity.domain.security.KeyType;
import am.ysu.identity.domain.user.User;
import am.ysu.security.security.util.key.KeyUtils;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;


public abstract class BaseKeyProvider implements KeyProvider {
    public final static String RSA_KEYPAIR_GENERATION_ALGORITHM = "RSA";
    public final static String EC_KEYPAIR_GENERATION_ALGORITHM = "EC";
    public final static String SECURE_RANDOM_GENERATION_ALGORITHM = "SHA1PRNG";
    public final static String DEFAULT_CRYPTOGRAPHIC_PROVIDER = "SUN";

    protected final UserKeysDao userKeysDao;
    protected final ConcurrentHashMap<String, PublicKey> userKeyCache = new ConcurrentHashMap<>();
    protected final AtomicBoolean useEc = new AtomicBoolean(false);

    protected BaseKeyProvider(UserKeysDao userKeysDao) {
        this.userKeysDao = userKeysDao;
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        return userKeyCache.computeIfAbsent(keyId, key -> {
            final UserKeys keys = userKeysDao.findByKeyId(key).orElse(null);
            if (keys == null) {
                return null;
            }
            return keys.decodePublicKey();
        });
    }

    @Override
    public PrivateKey getPrivateKey(String keyId) {
        final UserKeys keys = userKeysDao.findByKeyId(keyId).orElse(null);
        if(keys == null) {
            return null;
        }
        userKeyCache.put(keyId, keys.decodePublicKey());
        return keys.decodePrivateKey();
    }

    @Override
    public KeyPair getAsKeyPair(String keyId) {
        var keys = userKeysDao.findByKeyId(keyId).orElse(null);
        if(keys == null) {
            return null;
        }
        userKeyCache.put(keyId, keys.decodePublicKey());
        return keys.asKeypair();
    }

    @Override
    public KeyPair getKeyPair(User user) {
        final UserKeys userKeys = userKeysDao
                .findByUserEquals(user)
                .orElse(null);
        if(userKeys != null) {
            return userKeys.asKeypair();
        }
        return generateKeyPair(user);
    }

    @Override
    @Transactional
    public KeyPair generateKeyPair(User user) {
        final KeyPairGenerator keyGen;
        final SecureRandom secureRandom;
        final boolean shouldUseEc = useEc.get();
        useEc.set(!shouldUseEc);
        try {
            keyGen = KeyPairGenerator.getInstance(shouldUseEc ? EC_KEYPAIR_GENERATION_ALGORITHM : RSA_KEYPAIR_GENERATION_ALGORITHM);
            secureRandom = SecureRandom.getInstance(SECURE_RANDOM_GENERATION_ALGORITHM, DEFAULT_CRYPTOGRAPHIC_PROVIDER);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
        keyGen.initialize(shouldUseEc ? 256 : 2048, secureRandom);
        final KeyPair keyPair = keyGen.generateKeyPair();
        final UserKeys keys = new UserKeys();
        keys.setKeyType(shouldUseEc ? KeyType.EC : KeyType.RSA);
        keys.setUser(user);
        keys.setPrivateKey(Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
        keys.setPublicKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        keys.setKeyId(KeyUtils.calculateFingerPrintHex(keyPair.getPublic()));
        userKeysDao.save(keys);
        return keyPair;
    }

    @Override
    public List<String> availableKeys() {
        return StreamSupport.stream(userKeysDao.findAll().spliterator(), false)
                .map(key -> {
                    final String keyId = key.getKeyId();
                    userKeyCache.put(keyId, key.decodePublicKey());
                    return keyId;
                })
                .collect(Collectors.toList());
    }

    @Override
    public List<String> availableUserKeys() {
        return availableKeys();
    }
}
