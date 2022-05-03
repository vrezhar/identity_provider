package am.ysu.identity.domain;

import am.ysu.identity.domain.tokens.ServiceAccessToken;
import am.ysu.identity.token.AccessTokenOwner;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;

@Entity
@Table(name = "clients")
@Getter
@Setter
public class Client implements AccessTokenOwner
{
    private String id;
    private Long version = 0L;
    private String secret;
    private ServiceAccessToken accessToken;

    @Id
    @GenericGenerator(name = "assigned", strategy = "org.hibernate.id.Assigned")
    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    @Version
    public Long getVersion() {
        return version;
    }

    public void setVersion(Long version) {
        this.version = version;
    }

    public String getSecret() {
        return secret;
    }

    public void setSecret(String secret) {
        this.secret = secret;
    }

    @OneToOne(mappedBy = "client")
    public ServiceAccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(ServiceAccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    @Transient
    public String getUniqueId() {
        return id;
    }
}
