package am.ysu.identity.domain.tokens;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.Date;
import java.util.UUID;

@Entity
@Getter
@Setter
public class RefreshToken {
    private UUID id;
    private Long version = 0L;

    private Date issuedAt;

    private Date expiresIn;

    private AccessToken accessToken;

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
    public Date getIssuedAt() {
        return issuedAt;
    }

    @Column(name = "expires_in")
    public Date getExpiresIn() {
        return expiresIn;
    }

    @OneToOne
    @JoinColumn(
            name = "access_token_id",
            nullable = false,
            unique = true
    )
    public AccessToken getAccessToken() {
        return accessToken;
    }
}
