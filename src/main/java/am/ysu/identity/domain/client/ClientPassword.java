package am.ysu.identity.domain.client;

import lombok.Setter;

import javax.persistence.Entity;
import javax.persistence.Id;
import javax.persistence.OneToOne;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Setter
public class ClientPassword implements Serializable {
    public static final long serialVersionUID = 0L;

    private Client client;
    private String password;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientPassword that = (ClientPassword) o;
        return Objects.equals(client, that.client);
    }

    @Override
    public int hashCode() {
        return Objects.hash(client);
    }

    @Id
    @OneToOne(optional = false)
    public Client getClient() {
        return client;
    }

    public String getPassword() {
        return password;
    }
}
