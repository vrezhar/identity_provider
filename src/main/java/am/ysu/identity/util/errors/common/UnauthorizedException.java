package am.ysu.identity.util.errors.common;

import org.springframework.security.core.AuthenticationException;

public class UnauthorizedException extends AuthenticationException
{
    public final String realm;
    public final String errorDescription;

    public UnauthorizedException(String message, String realm) {
        this(message, realm, "Invalid token");
    }

    public UnauthorizedException(String message, Throwable cause, String realm) {
        this(message, cause, realm, "Invalid token");
    }

    public UnauthorizedException(String message, String realm, String errorDescription) {
        super(message);
        this.realm = realm;
        this.errorDescription = errorDescription;
    }

    public UnauthorizedException(String message, Throwable cause, String realm, String errorDescription) {
        super(message, cause);
        this.realm = realm;
        this.errorDescription = errorDescription;
    }
}
