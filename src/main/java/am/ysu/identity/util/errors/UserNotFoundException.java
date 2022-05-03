package am.ysu.identity.util.errors;

public class UserNotFoundException extends RuntimeException
{
    private final String userId;

    public UserNotFoundException(String message, String userId)
    {
        super(message);
        this.userId = userId;
    }

    public UserNotFoundException(String userId)
    {
        super("No user found by key " + userId);
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }
}
