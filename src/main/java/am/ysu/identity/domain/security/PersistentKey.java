package am.ysu.identity.domain.security;

public interface PersistentKey {
    boolean containsPublicKey();

    boolean containsPrivateKey();
}
