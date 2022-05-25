package am.ysu.identity.domain.security.keys;

import am.ysu.identity.domain.client.Client;
import am.ysu.identity.domain.security.PersistentKey;
import am.ysu.identity.domain.security.keys.ec.EcKey;
import am.ysu.identity.domain.security.keys.ec.EdEcKey;
import am.ysu.identity.domain.security.keys.rsa.RsaKey;
import am.ysu.identity.domain.user.User;
import am.ysu.security.security.util.key.KeyUtils;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.io.Serializable;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.Objects;

@Entity
@Getter
@Setter
@NamedQueries({
        @NamedQuery(name = ServerKeyMetadata.FIND_BY_ID_QUERY, query = "select k from ServerKeyMetadata k where k.keyId = :keyId"),
        @NamedQuery(name = ServerKeyMetadata.FIND_USER_KEY_QUERY, query = "select k from ServerKeyMetadata k where k.user = :user"),
        @NamedQuery(name = ServerKeyMetadata.FIND_CLIENT_KEY_QUERY, query = "select k from ServerKeyMetadata k where k.client = :client"),
        @NamedQuery(name = ServerKeyMetadata.FIND_ALL_USER_KEYS_QUERY, query = "select k from ServerKeyMetadata k where k.client is null and k.user is not null "),
        @NamedQuery(name = ServerKeyMetadata.FIND_ALL_CLIENT_KEYS_QUERY, query = "select k from ServerKeyMetadata k where k.user is null and k.client is not null"),
        @NamedQuery(name = ServerKeyMetadata.FIND_ALL_COMMON_KEYS_QUERY, query = "select k from ServerKeyMetadata  k where k.user is null and k.client is null")
})
public class ServerKeyMetadata implements Serializable {
    public static final long serialVersionUID = 0L;
    public static final String FIND_BY_ID_QUERY = "ServerKeyMetadata.findKey";
    public static final String FIND_USER_KEY_QUERY = "ServerKeyMetadata.findUserKeys";
    public static final String FIND_CLIENT_KEY_QUERY = "ServerKeyMetadata.findClientKeys";
    public static final String FIND_ALL_USER_KEYS_QUERY = "ServerKeyMetadata.findAllUserKeys";
    public static final String FIND_ALL_CLIENT_KEYS_QUERY = "ServerKeyMetadata.findAllClientKeys";
    public static final String FIND_ALL_COMMON_KEYS_QUERY = "ServerKeyMetadata.findAllCommonKeys";

    private String keyId;
    private KeyAlgorithm algorithm;
    private Boolean encrypted;
    private User user;
    private Client client;
    private LocalDateTime dateCreated;
    private LocalDateTime expirationDate;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ServerKeyMetadata that = (ServerKeyMetadata) o;
        return Objects.equals(keyId, that.keyId) && Objects.equals(user, that.user) && Objects.equals(client, that.client);
    }

    @Override
    public int hashCode() {
        return Objects.hash(keyId, user, client);
    }

    @Id
    @Column(name = "key_id")
    public String getKeyId() {
        return keyId;
    }

    @Enumerated(EnumType.STRING)
    public KeyAlgorithm getAlgorithm() {
        return algorithm;
    }

    public Boolean getEncrypted() {
        return Objects.requireNonNullElse(encrypted, false);
    }

    @ManyToOne
    @JoinTable(
            name = "user_key_metadata",
            joinColumns = @JoinColumn(name = "key_id", referencedColumnName = "key_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id")
    )
    public User getUser() {
        return user;
    }

    @ManyToOne
    @JoinTable(
            name = "client_key_metadata",
            joinColumns = @JoinColumn(name = "key_id", referencedColumnName = "key_id"),
            inverseJoinColumns = @JoinColumn(name = "user_id", referencedColumnName = "id")
    )
    public Client getClient() {
        return client;
    }

    @CreationTimestamp
    public LocalDateTime getDateCreated() {
        return dateCreated;
    }

    @Transient
    public boolean isExpired() {
        if(expirationDate == null) {
            return false;
        }
        return LocalDateTime.now().isAfter(expirationDate);
    }

    @Transient
    public TypedQuery<?> getKeyFetchingQuery(EntityManager entityManager) {
        TypedQuery<?> query;
        switch (algorithm) {
            case RSA -> query = entityManager.createNamedQuery(RsaKey.KEY_FIND_QUERY, RsaKey.class);
            case EC -> query = entityManager.createNamedQuery(EcKey.KEY_FIND_QUERY, EcKey.class);
            case ED_EC -> query = entityManager.createNamedQuery(EdEcKey.KEY_FIND_QUERY, EcKey.class);
            default -> throw new IllegalArgumentException("Unknown key algorithm [" + algorithm.name() + "]");
        }
        query.setParameter("serverKeyMetadata", this);
        return query;
    }

    public static enum KeyAlgorithm {
        RSA,
        EC,
        ED_EC;

        public KeyPair generateKeyPair() {
            KeyPairGenerator keyGen;
            try {
                final var rand = SecureRandom.getInstanceStrong();
                switch (this) {
                    case RSA:
                        keyGen = KeyPairGenerator.getInstance("RSA");
                        keyGen.initialize(2048, rand);
                        return keyGen.generateKeyPair();
                    case EC:
                        keyGen = KeyPairGenerator.getInstance("EC");
                        keyGen.initialize(256, rand);
                        return keyGen.generateKeyPair();
                    case ED_EC:
                        return KeyUtils.generateEdECKeyPair(rand);
                    default:
                        throw new IllegalArgumentException("Unknown algorithm + [" + this + "]");
                }
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Unexpected NoSuchAlgorithmException", e);
            }
        }
    }
}
