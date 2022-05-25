package am.ysu.identity.domain.security.keys.ec;

import am.ysu.identity.domain.security.PersistentKey;
import am.ysu.identity.domain.security.keys.ServerKeyMetadata;
import am.ysu.security.security.util.key.NistEcCurve;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.util.Objects;

@Entity
@Getter
@Setter
@NoArgsConstructor
@NamedQueries(
        @NamedQuery(name = EcKey.KEY_FIND_QUERY, query = "select ek from EcKey ek where ek.serverKeyMetadata = :serverKeyMetadata")
)
public class EcKey implements PersistentKey, Serializable {
    public static final long serialVersionUID = 0L;
    public static final String KEY_FIND_QUERY = "EcKey.findByKeyId";

    private ServerKeyMetadata serverKeyMetadata;
    private byte[] s;
    private byte[] wx;
    private byte[] wy;
    private String curveId = NistEcCurve.P256.getAliases().get(0);

    public EcKey(ECPrivateKey privateKey, ECPublicKey publicKey) {
        this.s = privateKey.getS().toByteArray();
        final var w = publicKey.getW();
        this.wx = w.getAffineX().toByteArray();
        this.wy = w.getAffineY().toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EcKey that = (EcKey) o;
        return Objects.equals(serverKeyMetadata, that.serverKeyMetadata);
    }

    @Override
    public int hashCode() {
        return Objects.hash(serverKeyMetadata);
    }

    @Id
    @OneToOne
    @JoinColumn(name = "key_id")
    public ServerKeyMetadata getServerKeyMetadata() {
        return serverKeyMetadata;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getS() {
        return s;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getWx() {
        return wx;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getWy() {
        return wy;
    }

    @Override
    public boolean containsPublicKey() {
        return curveId != null && wx != null && wy != null && wx.length > 0 && wy.length > 0;
    }

    @Override
    public boolean containsPrivateKey() {
        return curveId != null && s != null && s.length > 0;
    }
}
