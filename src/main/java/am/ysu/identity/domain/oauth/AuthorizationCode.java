package am.ysu.identity.domain.oauth;

import am.ysu.identity.domain.client.Client;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.user.User;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.springframework.data.domain.Persistable;

import javax.persistence.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.LocalDateTime;
import java.util.Base64;

@Entity
@Getter
@Setter
public class AuthorizationCode implements Persistable<Long> {
    private Long id;
    private String code;
    private String codeChallenge;
    private ChallengeMethod challengeMethod;
    private String redirectUri;
    private Boolean setNotBefore;
    private Client client;
    private User user;
    private AccessToken accessToken;
    private LocalDateTime dateCreated;
    private LocalDateTime expiresAt;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    @Enumerated(EnumType.STRING)
    public ChallengeMethod getChallengeMethod() {
        return challengeMethod;
    }

    @CreationTimestamp
    public LocalDateTime getDateCreated() {
        return dateCreated;
    }

    @ManyToOne
    public User getUser() {
        return user;
    }

    @ManyToOne
    public Client getClient() {
        return client;
    }

    @OneToOne(cascade = {CascadeType.PERSIST, CascadeType.REMOVE})
    public AccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(AccessToken accessToken) {
        this.accessToken = accessToken;
    }

    @Override
    @Transient
    public boolean isNew() {
        return id == null;
    }

    public boolean verifyCodeChallenge(String codeVerifier) {
        switch (challengeMethod)
        {
            case PLAIN:
                return codeVerifier.equals(codeChallenge);
            case S256:
                try {
                    MessageDigest md = MessageDigest.getInstance("SHA-256");
                    return Base64.getUrlEncoder().encodeToString(md.digest(codeVerifier.getBytes(StandardCharsets.UTF_8))).equals(codeChallenge);
                } catch (NoSuchAlgorithmException nsa) {
                    throw new RuntimeException(nsa);
                }
            default:
                return false;
        }
    }

    public static enum ChallengeMethod {
        PLAIN,
        S256
    }
}
