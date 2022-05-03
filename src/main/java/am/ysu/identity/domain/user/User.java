package am.ysu.identity.domain.user;

import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.token.AccessTokenOwner;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import javax.persistence.*;
import java.util.*;

@Entity
@Getter
@Setter
public class User implements AccessTokenOwner
{
    private Long id;
    private Long version = 0L;
    private UUID uniqueId;
    private String username;
    private String password;
    private Boolean enabled;
    private String firstName;
    private String lastName;
    private String defaultAccountId;
    private UserKeys keys;
    private String accountId;
    private String passwordRecoveryKey;
    private Set<AccessToken> tokens = new HashSet<>();
    private Set<OldCredentials> oldCredentials = new HashSet<>();

    private Date dateCreated;
    private Date lastUpdated;

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    @Version
    public Long getVersion() {
        return version;
    }

    @Column(columnDefinition = "BINARY(16)")
    @Override
    public UUID getUniqueId() {
        return uniqueId;
    }

    @Column(unique = true)
    public String getUsername() {
        return username;
    }

    @Transient
    public String getAccountId() {
        return accountId;
    }

    @OneToOne(mappedBy = "user", cascade = CascadeType.REMOVE)
    public UserKeys getKeys() {
        return keys;
    }

    @OneToMany(mappedBy = "user")
    public Set<AccessToken> getTokens() {
        return tokens;
    }

    @OneToMany(mappedBy = "user", cascade = CascadeType.REMOVE)
    public Set<OldCredentials> getOldCredentials() {
        return oldCredentials;
    }

    @CreationTimestamp
    public Date getDateCreated() {
        return dateCreated;
    }

    @UpdateTimestamp
    public Date getLastUpdated() {
        return lastUpdated;
    }
}
