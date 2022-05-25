package am.ysu.identity.domain.rbac;

import am.ysu.identity.domain.client.Client;
import lombok.Getter;
import lombok.Setter;
import org.hibernate.annotations.NaturalId;

import javax.persistence.*;
import java.util.List;

@Entity
@Setter
public class Scope {
    private Long id;
    private String name;
    private List<Client> clients;

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    public Long getId() {
        return id;
    }

    @NaturalId
    public String getName() {
        return name;
    }

    @ManyToMany
    public List<Client> getClients() {
        return clients;
    }
}
