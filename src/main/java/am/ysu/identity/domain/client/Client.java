package am.ysu.identity.domain.client;

import am.ysu.identity.token.AccessTokenOwner;
import lombok.Getter;
import lombok.Setter;
import lombok.experimental.NonFinal;
import org.hibernate.annotations.GenericGenerator;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Table(name = "clients")
@Getter
@Setter
public class Client implements AccessTokenOwner, Serializable {
    public static final long serialVersionUID = 0L;

    private String id;
    private String name;
    private String ipAddress;
    private String secret;
    private Boolean isSecretEncrypted;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Client that = (Client) o;
        return Objects.equals(id, that.id);
    }

    @Override
    public int hashCode() {
        return Objects.hash(id);
    }

    @Id
    @GenericGenerator(name = "assigned", strategy = "org.hibernate.id.Assigned")
    public String getId() {
        return id;
    }

    @Override
    @Transient
    public String getUniqueId() {
        return id;
    }
}
