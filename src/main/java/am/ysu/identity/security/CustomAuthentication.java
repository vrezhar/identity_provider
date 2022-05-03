package am.ysu.identity.security;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

/**
 * Custom authentication base object used by our filters
 */
public abstract class CustomAuthentication implements Authentication {

    private boolean authenticated = false;
    private final ArrayList<GrantedAuthority> authorities = new ArrayList<>();
    private final Object principal;

    public CustomAuthentication(Object principal)
    {
        this.principal = principal;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    public void setAuthorities(String... authorities)
    {
        Arrays.stream(authorities).forEach(authority -> this.authorities.add(() -> authority));
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public boolean isAuthenticated() {
        return authenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.authenticated = isAuthenticated;
    }
}
