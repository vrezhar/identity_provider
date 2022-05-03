package am.ysu.identity.domain.user;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;

import javax.persistence.*;
import java.util.Date;

@Entity
@Getter
@Setter
public class OldCredentials
{
    private Long id;
    private String username;
    private String password;
    private User user;
    private Date dateCreated;

    public OldCredentials(){ }

    public OldCredentials(User user)
    {
        this.username = user.getUsername();
        this.password = user.getPassword();
        this.user = user;
    }

    public OldCredentials(User user, String oldUsername, String oldPassword)
    {
        this.username = oldUsername;
        this.password = oldPassword;
        this.user = user;
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    public Long getId() {
        return id;
    }

    @ManyToOne
    @JoinColumn
    public User getUser() {
        return user;
    }

    @CreationTimestamp
    public Date getDateCreated() {
        return dateCreated;
    }
}
