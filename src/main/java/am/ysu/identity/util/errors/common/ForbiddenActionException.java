package am.ysu.identity.util.errors.common;

import org.springframework.security.core.AuthenticationException;

public class ForbiddenActionException extends AuthenticationException
{
    public ForbiddenActionException(String message) {
        super(message);
    }

    public ForbiddenActionException(String message, Throwable cause) {
        super(message, cause);
    }
}
