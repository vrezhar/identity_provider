package am.ysu.identity.domain.tokens;

import am.ysu.identity.domain.Client;
import am.ysu.identity.token.AccessTokenType;
import am.ysu.identity.token.AbstractAccessToken;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.Date;
import java.util.UUID;

@Entity
@Getter
@Setter
public class ServiceAccessToken extends AbstractAccessToken {
    private UUID id;
    private Long version = 0L;
    private Client client;

    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
    public UUID getId() {
        return id;
    }

    @Version
    public Long getVersion() {
        return version;
    }

    @Column(name = "issued_at")
    @Override
    public Date getIssuedAt() {
        return issuedAt;
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    @Column(name = "expires_in")
    @Override
    public Date getExpiresIn() {
        return expiresIn;
    }

    @Override
    public void setExpiresIn(Date expiresIn) {
        this.expiresIn = expiresIn;
    }

    @OneToOne(optional = false)
    @JoinColumn(
            name = "client_id",
            nullable = false
    )
    public Client getClient() {
        return client;
    }

    @Override
    public AccessTokenType type(){
        return AccessTokenType.CLIENT;
    }

    @Override
    public Client owner(){
        return client;
    }
}
