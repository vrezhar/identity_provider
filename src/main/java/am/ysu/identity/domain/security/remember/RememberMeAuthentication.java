package am.ysu.identity.domain.security.remember;

import am.ysu.identity.domain.user.User;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;
import java.time.Duration;
import java.time.LocalDateTime;
import java.util.Date;

@Entity
@Getter
@Setter
public class RememberMeAuthentication {
    public static final String SEMANTICS_IDENTIFIER_COOKIE = "RMESID";
    public static final String TOKEN_COOKIE = "RMETOKEN";

    private Long id;
    private String semanticsIdentifier;
    private HashType hashType;
    private byte[] authenticationHash;
    private User user;
    private Date dateCreated;
    private LocalDateTime expirationDate;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public Long getId() {
        return id;
    }

    @Column(columnDefinition = "BLOB")
    public byte[] getAuthenticationHash() {
        return authenticationHash;
    }

    @Enumerated(EnumType.STRING)
    public HashType getHashType() {
        return hashType;
    }

    @ManyToOne
    public User getUser() {
        return user;
    }

    @CreationTimestamp
    public Date getDateCreated() {
        return dateCreated;
    }

    public boolean validate(String token) {
        return hashType.validate(token, authenticationHash);
    }

    public void populateCookiesAndSetHash(HttpServletResponse response, String token, String domain) {
        final LocalDateTime now = LocalDateTime.now();
        final long age = Duration.between(now, expirationDate).getSeconds();
        final Cookie semanticsId = new Cookie(SEMANTICS_IDENTIFIER_COOKIE, String.valueOf(semanticsIdentifier));
        semanticsId.setDomain(domain);
        semanticsId.setPath("/");
        semanticsId.setSecure(true);
        semanticsId.setHttpOnly(false);
        semanticsId.setMaxAge((int)age);
        this.authenticationHash = hashType.hash(token);
        final Cookie tokenCookie = new Cookie(TOKEN_COOKIE, token);
        tokenCookie.setDomain(domain);
        tokenCookie.setPath("/");
        tokenCookie.setSecure(true);
        tokenCookie.setHttpOnly(true);
        tokenCookie.setMaxAge((int)age);
        response.addCookie(semanticsId);
        response.addCookie(tokenCookie);
    }
}
