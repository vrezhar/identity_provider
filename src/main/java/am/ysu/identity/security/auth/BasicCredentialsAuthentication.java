package am.ysu.identity.security.auth;

import am.ysu.identity.security.CustomAuthentication;

/**
 * Authentication object representing basic credentials authentication, holds id/secret pairs
 */
public class BasicCredentialsAuthentication extends CustomAuthentication
{
    private final String secret;
    private Object details;

    public void setDetails(String details) {
        this.details = details;
    }

    public BasicCredentialsAuthentication(Object principal, String secret)
    {
        super(principal);
        this.secret = secret;
    }

    @Override
    public Object getCredentials() {
        return secret;
    }

    @Override
    public Object getDetails() {
        return details;
    }

    public void setDetails(Object details) {
        this.details = details;
    }

    @Override
    public String getName() {
        return getPrincipal().toString();
    }
}
