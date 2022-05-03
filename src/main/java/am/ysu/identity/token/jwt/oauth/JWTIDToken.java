package am.ysu.identity.token.jwt.oauth;

import am.ysu.identity.token.jwt.AbstractJWTToken;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.security.jwt.structure.JWTClaims;
import com.fasterxml.jackson.annotation.JsonGetter;
import com.fasterxml.jackson.annotation.JsonProperty;

public class JWTIDToken extends AbstractJWTToken {
    private String tokenId;
    private String userId;
    private String username;
    private boolean isRememberMe;

    @JsonProperty(JWTClaims.SUBJECT)
    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonProperty(JWTClaims.TOKEN_ID)
    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    @JsonGetter(CustomJWTClaims.IS_REMEMBER_ME)
    public boolean isRememberMe() {
        return isRememberMe;
    }

    public void setRememberMe(boolean rememberMe) {
        isRememberMe = rememberMe;
    }
}
