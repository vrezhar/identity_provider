package am.ysu.identity.dto.request;

import com.fasterxml.jackson.annotation.JsonAlias;

/**
 * Used for representing client credentials(basic authentication or POST request body)
 */
public class ClientCredentialsDto
{
    @JsonAlias({"id", "client_id", "name"})
    private String clientId;

    @JsonAlias({"secret", "client_secret"})
    private String clientSecret;

    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public String getClientSecret() {
        return clientSecret;
    }

    public void setClientSecret(String clientSecret) {
        this.clientSecret = clientSecret;
    }
}
