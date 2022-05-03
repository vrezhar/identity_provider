package am.ysu.identity.util.errors;

public class ClientNotFoundException extends RuntimeException
{
    private final String clientId;

    public ClientNotFoundException(String message, String clientId)
    {
        super(message);
        this.clientId = clientId;
    }

    public String getClientId() {
        return clientId;
    }
}
