package am.ysu.identity.domain.security.keys.rsa;

import am.ysu.identity.domain.security.PersistentKey;
import am.ysu.identity.domain.security.keys.ServerKeyMetadata;
import lombok.NoArgsConstructor;
import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Objects;

@Entity
@Setter
@NoArgsConstructor
@NamedQueries(
        @NamedQuery(name = RsaKey.KEY_FIND_QUERY, query = "select rk from RsaKey rk where rk.serverKeyMetadata = :serverKeyMetadata")
)
public class RsaKey implements PersistentKey, Serializable {
    public static final long serialVersionUID = 0L;
    public static final String KEY_FIND_QUERY = "RsaKey.findByKeyId";

    private ServerKeyMetadata serverKeyMetadata;
    private byte[] e;
    private byte[] n;
    private byte[] d;

   public RsaKey(RSAPrivateKey privateKey, RSAPublicKey publicKey) {
       this.e = publicKey.getPublicExponent().toByteArray();
       this.d = privateKey.getPrivateExponent().toByteArray();
       this.n = privateKey.getModulus().toByteArray();
   }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        RsaKey that = (RsaKey) o;
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
    public byte[] getE() {
        return e;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getN() {
        return n;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getD() {
        return d;
    }

    @Override
    public boolean containsPublicKey() {
        return e != null && n != null && e.length > 0 && n.length > 0;
    }

    @Override
    public boolean containsPrivateKey() {
        return d != null && n != null && d.length > 0 && n.length > 0;
    }
}
