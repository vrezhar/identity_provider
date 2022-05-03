package am.ysu.identity.util.jwt;

import am.ysu.identity.domain.user.User;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

public interface KeyProvider {
    PublicKey getPublicKey(String keyId);

    PrivateKey getPrivateKey(String keyId);

    KeyPair getKeyPair(String keyId);

    KeyPair getKeyPair(User user);

    KeyPair generateKeyPair(User user);

    List<String> availableKeys();

    List<String> availableServerKeys();

    List<String> availableUserKeys();
}
