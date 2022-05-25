package am.ysu.identity.security.auth.client;

import am.ysu.identity.domain.client.Client;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;

public class ClientAuthentication implements Authentication {
    public final Client client;

    public ClientAuthentication(Client client) {
        this.client = client;
    }

    @Override
    //RBAC not defined for clients
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return new ArrayList<>();
    }

    @Override
    public Object getCredentials() {
        return client.getSecret();
    }

    @Override
    public Object getDetails() {
        return client.getUniqueId();
    }

    @Override
    public Object getPrincipal() {
        return client;
    }

    @Override
    public boolean isAuthenticated() {
        return true;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        if(isAuthenticated){
            return;
        }
        throw new UnsupportedOperationException("Clients are assumed to be authenticated");
    }

    @Override
    public String getName() {
        return client.getId();
    }
}
