package am.ysu.identity.util.errors.common.auth;

import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.UnauthorizedException;

public class UserAuthorizationException extends UnauthorizedException
{
    public UserAuthorizationException(String message) {
        super(message, Realms.USER_OPERATIONS_REALM);
    }

    public UserAuthorizationException(String message, String realm) {
        super(message, realm);
    }

    public UserAuthorizationException(String message, Throwable cause, String realm) {
        super(message, cause, realm);
    }
}
