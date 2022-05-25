package am.ysu.identity.util.jwt.provider;

import am.ysu.identity.domain.user.User;
import am.ysu.identity.util.jwt.KeyProvider;
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
public class FileBasedKeyProvider implements KeyProvider {
    private static final Logger logger = LoggerFactory.getLogger(FileBasedKeyProvider.class);

    private final KeyPair serverKeys;

    public FileBasedKeyProvider(KeyPair serverKeys) {
        this.serverKeys = serverKeys;
    }

    @Override
    public PublicKey getPublicKey(String keyId) {
        if(keyId == null) {
            return null;
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
        if(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()).equals(keyId)) {
            logger.warn("Unknown key id {}, will be returning the server key", keyId);
        }
        return serverKeys.getPrivate();
    }

    @Override
    public KeyPair getAsKeyPair(String keyId) {
        if(keyId == null) {
            return null;
        }
        if(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()).equals(keyId)) {
            logger.warn("Unknown key id {}, will be returning the server key", keyId);
        }
        return serverKeys;
    }

    @Override
    public KeyPair getKeyPair(User user) {
        return serverKeys;
    }

    @Override
    public KeyPair generateKeyPair(User user) {
        return null;
    }

    @Override
    public List<String> availableKeys() {
        final List<String> allKeys = new ArrayList<>(1);
        allKeys.add(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()));
        return allKeys;
    }

    @Override
    public List<String> availableServerKeys() {
        return Collections.singletonList(KeyUtils.calculateFingerPrintHex(serverKeys.getPublic()));
    }

    @Override
    public List<String> availableUserKeys() {
        return availableServerKeys();
    }

//    @PostConstruct
//    void initKeysToFingerPrint() {
//
//    }
}
