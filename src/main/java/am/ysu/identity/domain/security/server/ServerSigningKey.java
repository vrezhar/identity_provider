package am.ysu.identity.domain.security.server;

import am.ysu.identity.domain.security.KeyPairHolder;
import am.ysu.identity.domain.security.KeyType;
import am.ysu.security.security.util.key.KeyUtils;
import lombok.Getter;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Getter
@Setter
@Entity
public class ServerSigningKey implements KeyPairHolder, Serializable {
    public static long serialVersionUid = 0L;

    private Long id;
    private String keyId;
    private String privateKey;
    private String publicKey;
    private KeyType keyType;

    public ServerSigningKey() { }

    public ServerSigningKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
        this.keyType = KeyType.RSA;
        this.keyId = KeyUtils.calculateFingerPrintHex(publicKey);
        this.privateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        this.publicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    public ServerSigningKey(ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.keyType = KeyType.EC;
        this.keyId = KeyUtils.calculateFingerPrintHex(publicKey);
        this.privateKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());
        this.publicKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
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
