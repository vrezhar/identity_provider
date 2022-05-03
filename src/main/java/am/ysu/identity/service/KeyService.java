package am.ysu.identity.service;

import am.ysu.identity.util.errors.common.ForbiddenActionException;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.util.jwt.KeyProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.*;
import java.util.List;

/**
 * A service for manipulating user and server keys
 */
@Service("keyService")
@Transactional
public class KeyService implements InitializingBean { //implements KeyProvider {
    private static final Logger logger = LoggerFactory.getLogger(KeyService.class);

    private final KeyProvider keyProvider;

    public KeyService(KeyProvider keyProvider) {
        this.keyProvider = keyProvider;
    }

    /**
     * Generates a public/private key pair for the user
     * @param user The user for whom the keys are generated
     * @return The generated keys as a simple {@link KeyPair} object
     */
    public KeyPair generateKeyPairFor(User user)
    {
        if(user == null){
            return null;
        }
        return keyProvider.getKeyPair(user);
    }

    /**
     * Fetches the user keys or generates them on the fly using {@link KeyService#generateKeyPairFor}
     * @param user The user whose keys should be returned
     * @return The keys of the user
     */
    public KeyPair getKeys(User user) {
        final var keys = keyProvider.getKeyPair(user);
        if(keys == null){
            return generateKeyPairFor(user);
        }
        return keys;
    }

    public KeyPair getKeys(String keyId) {
        return keyProvider.getKeyPair(keyId);
    }

    public PublicKey getPublicKey(String keyId) {
        if(keyId == null){
            logger.warn("Received token with invalid public key id: null");
            throw new ForbiddenActionException("invalid.key");
        }
        return keyProvider.getPublicKey(keyId);
    }

    public List<String> availableKeys() {
        return keyProvider.availableKeys();
    }

    public List<String> availableServerKeys() {
        return keyProvider.availableServerKeys();
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        logger.info("Using key provider " + keyProvider.getClass().getSimpleName());
    }
}
