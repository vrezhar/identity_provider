package am.ysu.identity.domain.user;

import am.ysu.identity.domain.security.KeyPairHolder;
import am.ysu.security.security.util.key.KeyUtils;
import am.ysu.identity.domain.security.KeyType;
import am.ysu.identity.domain.user.User;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Entity
@Getter
@Setter
public class UserKeys implements KeyPairHolder, Serializable {
    public static long serialVersionUid = 1L;

    private Long id;
    private Long version;
    private String publicKey;
    private String privateKey;
    private String keyId;
    private KeyType keyType;
    private User user;

    public UserKeys() { }

    public UserKeys(User user, RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.keyType = KeyType.RSA;
        this.user = user;
        this.privateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        this.publicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        this.keyId = KeyUtils.calculateFingerPrintHex(publicKey);
    }

    public UserKeys(User user, ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.keyType = KeyType.EC;
        this.user = user;
        this.privateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        this.publicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        this.keyId = KeyUtils.calculateFingerPrintHex(publicKey);
    }


    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public Long getId() {
        return id;
    }

    @Version
    public Long getVersion() {
        return version;
    }

    @OneToOne
    @JoinColumn(
            name = "user_id",
            nullable = false,
            unique = true
    )
    public User getUser() {
        return user;
    }

    @Column(columnDefinition = "LONGTEXT")
    @Override
    public String getPrivateKey() {
        return privateKey;
    }

    @Column(columnDefinition = "LONGTEXT")
    @Override
    public String getPublicKey() {
        return publicKey;
    }

    @Override
    @Enumerated(EnumType.STRING)
    public KeyType getKeyType() {
        return keyType;
    }
}
