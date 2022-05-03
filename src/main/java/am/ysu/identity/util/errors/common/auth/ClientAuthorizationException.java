package am.ysu.identity.util.errors.common.auth;

import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.UnauthorizedException;

public class ClientAuthorizationException extends UnauthorizedException
{
    public final boolean basic;

    public ClientAuthorizationException() {
        this("client.authorization.required", Realms.CLIENT_REALM);
    }

    public ClientAuthorizationException(String message) {
        this(message, true);
    }

    public ClientAuthorizationException(String message, boolean basic) {
        super(message, Realms.CLIENT_REALM);
        this.basic = basic;
    }

    public ClientAuthorizationException(String message, String realm) {
        super(message, realm);
        this.basic = true;
    }

    public ClientAuthorizationException(String message, String realm, Throwable cause) {
        super(message, cause, realm);
        this.basic = true;
    }
}
