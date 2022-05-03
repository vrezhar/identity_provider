package am.ysu.identity.token.jwt.oauth.access;

import am.ysu.identity.token.jwt.AbstractJWTToken;
import am.ysu.security.jwt.structure.JWTClaims;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ServiceAccessToken extends AbstractJWTToken {
    private String clientId;
    private String accessTokenId;

    @JsonProperty(JWTClaims.SUBJECT)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    @JsonProperty(JWTClaims.TOKEN_ID)
    public String getAccessTokenId() {
        return accessTokenId;
    }

    public void setAccessTokenId(String accessTokenId) {
        this.accessTokenId = accessTokenId;
    }
}
