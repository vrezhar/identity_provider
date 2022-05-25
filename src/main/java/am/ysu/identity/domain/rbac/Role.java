package am.ysu.identity.domain.rbac;

import am.ysu.identity.domain.user.User;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.util.List;

@Entity
@Setter
public class Role {
    private Long id;
    private String name;
    private List<User> users;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public Long getId() {
        return id;
    }

    @NaturalId
    public String getName() {
        return name;
    }

    @ManyToMany(fetch = FetchType.LAZY)
    public List<User> getUsers() {
        return users;
    }
}
