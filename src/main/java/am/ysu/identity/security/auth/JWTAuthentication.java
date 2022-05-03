package am.ysu.identity.security.auth;

import am.ysu.security.jwt.JWT;
import am.ysu.identity.security.CustomAuthentication;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;

/**
 * Authentication for JWT based access, builds the object from a service access/id token
 */
public class JWTAuthentication extends CustomAuthentication {
    public final JWT jwt;
    private boolean isAuthenticated = false;

    public JWTAuthentication(JWT jwt)
    {
        super(jwt.getSubject());
        this.jwt = jwt;
    }

    /**
     * @return the JWT signature
     */
    @Override
    public Object getCredentials() {
        return jwt.getSignature();
    }

    /**
     * @return the id of the JWT that the authentication is based on(any other information can be fetched from the JWT itself)
     */
    @Override
    public Object getDetails() {
        return jwt.getTokenId();
    }

    @Override
    public boolean isAuthenticated() {
        return isAuthenticated;
    }

    @Override
    public void setAuthenticated(boolean isAuthenticated) throws IllegalArgumentException {
        this.isAuthenticated = isAuthenticated;
    }

    /**
     * @return The email of the user or client's name
     */
    @Override
    public String getName() {
        final Object email = jwt.getClaim(CustomJWTClaims.USER_EMAIL);
        if(email == null) {
            return jwt.getSubject();
        }
        return email.toString();
    }
}
