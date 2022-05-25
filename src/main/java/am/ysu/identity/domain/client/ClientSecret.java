package am.ysu.identity.domain.client;

import lombok.Setter;

import javax.persistence.*;
import java.io.Serializable;
import java.util.Objects;

@Entity
@Setter
public class ClientSecret implements Serializable {
    public static final long serialVersionUID = 0L;

    private Client client;
    private String secret;
    private Usage usage = Usage.ALL;

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ClientSecret that = (ClientSecret) o;
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

    public String getSecret() {
        return secret;
    }

    @Enumerated(EnumType.STRING)
    public Usage getUsage() {
        return usage;
    }

    public static enum Usage {
        HMAC_AUTH,
        JWT,
        ALL
    }
}
