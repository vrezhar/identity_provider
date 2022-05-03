package am.ysu.identity.security.auth.user;

import am.ysu.identity.security.auth.JWTAuthentication;
import am.ysu.identity.domain.user.User;
import am.ysu.security.jwt.JWT;

public class UserAuthentication extends JWTAuthentication
{
    public final User user;

    public UserAuthentication(JWT jwt, User user) {
        super(jwt);
        this.user = user;
    }

    @Override
    public Object getPrincipal() {
        return user;
    }

    @Override
    public String getName() {
        return user.getUsername();
    }
}
