package am.ysu.identity.util.errors;

public class TokenValidationException extends RuntimeException
{
    private String validationError;

    public String getValidationError() {
        return validationError;
    }

    public TokenValidationException() {
    }

    public TokenValidationException(String message) {
        super(message);
        this.validationError = message;
    }

    public TokenValidationException(String message, String validationError) {
        super(message);
        this.validationError = validationError;
    }

    public TokenValidationException(String message, Throwable cause)
    {
        super(message, cause);
        this.validationError = message;
    }

    public TokenValidationException(Throwable cause)
    {
        super(cause);
        this.validationError = cause.getMessage();
    }

    public TokenValidationException(String message, Throwable cause, boolean enableSuppression, boolean writableStackTrace)
    {
        super(message, cause, enableSuppression, writableStackTrace);
        this.validationError = message;
    }
}
