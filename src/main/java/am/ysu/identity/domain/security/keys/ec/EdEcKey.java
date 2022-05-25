package am.ysu.identity.domain.security.keys.ec;

import am.ysu.identity.domain.security.PersistentKey;
import am.ysu.identity.domain.security.keys.ServerKeyMetadata;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.security.interfaces.EdECPrivateKey;
import java.security.interfaces.EdECPublicKey;
import java.util.Objects;

@Entity
@Setter
@NoArgsConstructor
@NamedQueries(
        @NamedQuery(name = EdEcKey.KEY_FIND_QUERY, query = "select edk from EcKey edk where edk.serverKeyMetadata = :serverKeyMetadata")
)
public class EdEcKey implements PersistentKey, Serializable {
    public static final long serialVersionUID = 0L;
    public static final String KEY_FIND_QUERY = "EdEcKey.findByKeyId";

    private ServerKeyMetadata serverKeyMetadata;
    private byte[] h;
    private Boolean xOdd;
    private byte[] y;

    public EdEcKey(EdECPrivateKey privateKey, EdECPublicKey publicKey) {
        this.h = privateKey.getBytes().orElseThrow();
        final var edECPoint = publicKey.getPoint();
        this.xOdd = edECPoint.isXOdd();
        this.y = edECPoint.getY().toByteArray();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EdEcKey edEcKey = (EdEcKey) o;
        return Objects.equals(serverKeyMetadata, edEcKey.serverKeyMetadata);
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
    public byte[] getH() {
        return h;
    }

    @Column(columnDefinition = "BLOB")
    public Boolean getXOdd() {
        return Objects.requireNonNullElse(xOdd, false);
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getY() {
        return y;
    }

    @Override
    public boolean containsPublicKey() {
        return y != null && y.length > 0;
    }

    @Override
    public boolean containsPrivateKey() {
        return h != null && h.length > 0;
    }
}
