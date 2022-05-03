package am.ysu.identity.domain.tokens;

import am.ysu.identity.domain.user.User;
import am.ysu.identity.token.AccessTokenType;
import am.ysu.identity.token.AbstractAccessToken;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.util.Date;
import java.util.UUID;

@Entity
@Table(name = "access_token")
@Getter
@Setter
public class AccessToken extends AbstractAccessToken {
    private UUID id;
    private Long version;
    private User user;
    private Boolean isRememberMe;
    private RefreshToken refreshToken;

    @Id
    @GeneratedValue(generator = "uuid2")
    @GenericGenerator(name = "uuid2", strategy = "uuid2")
    @Column(name = "id", updatable = false, nullable = false, columnDefinition = "BINARY(16)")
    @Override
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

    public void setIssuedAt(java.util.Date issuedAt) {
        this.issuedAt = issuedAt;
    }

    @Column(name = "expires_in")
    @Override
    public Date getExpiresIn() {
        return expiresIn;
    }

    @Override
    public void setExpiresIn(Date expiresAt) {
        this.expiresIn = expiresAt;
    }

    @ManyToOne(optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false
    )
    public User getUser() {
        return user;
    }

    @OneToOne(mappedBy = "accessToken")
    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    @Override
    public AccessTokenType type() {
        return AccessTokenType.USER;
    }

    @Override
    public User owner(){
        return user;
    }
}
