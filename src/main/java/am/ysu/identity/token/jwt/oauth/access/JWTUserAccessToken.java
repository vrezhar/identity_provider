package am.ysu.identity.token.jwt.oauth.access;

import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.token.jwt.oauth.JWTIDToken;
import am.ysu.security.jwt.structure.JWTClaims;
import am.ysu.security.security.util.key.KeyUtils;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.*;
import java.util.List;
import java.util.Objects;

public class JWTUserAccessToken extends JWTIDToken {
    private KeyPair serverKeyPair;
    private String refreshTokenId;
    private List<String> roles;

    @JsonProperty(CustomJWTClaims.REFRESH_TOKEN_ID)
    public String getRefreshTokenId() {
        return refreshTokenId;
    }

    public void setRefreshTokenId(String refreshTokenId) {
        this.refreshTokenId = refreshTokenId;
    }

    @JsonIgnore
    public void setServerKeypair(KeyPair keyPair) {
        this.serverKeyPair = keyPair;
    }


    public List<String> getRoles() {
        return roles;
    }

    public void setRoles(List<String> roles) {
        this.roles = roles;
    }

    @JsonProperty(JWTClaims.PUBLIC_KEY_ID)
    public String getServersKeyFingerprint() throws NoSuchAlgorithmException {
        return KeyUtils.calculateFingerPrintHex(serverKeyPair.getPublic());
    }

    @JsonIgnore
    public PrivateKey getServerPrivateKey() {
        return serverKeyPair.getPrivate();
    }

    @JsonIgnore
    public PublicKey getServerPublicKey() {
        return serverKeyPair.getPublic();
    }

    public JWTUserAccessToken withRoles(List<String> roles) {
        setRoles(Objects.requireNonNull(roles));
        return this;
    }
}
