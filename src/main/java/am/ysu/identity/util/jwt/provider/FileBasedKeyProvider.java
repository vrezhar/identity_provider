package am.ysu.identity.util.jwt.provider;

import am.ysu.identity.dao.user.UserKeysDao;
import am.ysu.identity.util.jwt.BaseKeyProvider;
import am.ysu.security.security.util.key.KeyUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@Order(Ordered.HIGHEST_PRECEDENCE + 1)
@Component("keyProvider")
@ConditionalOnProperty(value = "security.key.provider.class", havingValue = "FileBasedKeyProvider")
public class FileBasedKeyProvider extends BaseKeyProvider {
    private static final Logger logger = LoggerFactory.getLogger(FileBasedKeyProvider.class);

    private final KeyPair serverKeys;

    public FileBasedKeyProvider(KeyPair serverKeys, UserKeysDao userKeysDao) {
        super(userKeysDao);
        this.serverKeys = serverKeys;
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        final var key = super.getPublicKey(keyId);
        if(key != null) {
            return key;
        }
        final PublicKey publicKey = serverKeys.getPublic();
        if(KeyUtils.calculateFingerPrintHex(publicKey).equals(keyId)) {
            logger.warn("Unknown key id {}, will be returning the server key", keyId);
        }
        return publicKey;
    }

    @Override
    public PrivateKey getPrivateKey(String keyId) {
        if(keyId == null) {
            return null;
        }
        final var key = super.getPrivateKey(keyId);
        if(key != null) {
            return key;
        }
        if(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()).equals(keyId)) {
            logger.warn("Unknown key id {}, will be returning the server key", keyId);
        }
        return serverKeys.getPrivate();
    }

    @Override
    public KeyPair getKeyPair(String keyId) {
        if(keyId == null) {
            return null;
        }
        final var keys = super.getKeyPair(keyId);
        if(keys != null) {
            return keys;
        }
        if(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()).equals(keyId)) {
            logger.warn("Unknown key id {}, will be returning the server key", keyId);
        }
        return serverKeys;
    }

    @Override
    public List<String> availableKeys() {
        final List<String> userKeys = super.availableKeys();
        final List<String> allKeys = new ArrayList<>(userKeys.size() + 1);
        allKeys.add(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()));
        allKeys.addAll(userKeys);
        return allKeys;
    }

    @Override
    public List<String> availableServerKeys() {
        return Collections.singletonList(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()));
    }

//    @PostConstruct
//    void initKeysToFingerPrint() {
//
//    }
}
