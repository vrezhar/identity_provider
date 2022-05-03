package am.ysu.identity.token.jwt;

import am.ysu.security.jwt.alg.AlgorithmDefinition;
import am.ysu.security.jwt.alg.asymmetric.EcAlgorithm;
import am.ysu.security.jwt.alg.asymmetric.RsaAlgorithm;
import am.ysu.security.jwt.structure.JWTClaims;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public abstract class AbstractJWTToken {
    private KeyPair keyPair;
    private AlgorithmDefinition signatureAlgorithm;
    protected String audience;
    private String issuer;
    private Instant issuedAt;
    private Instant expirationDate;

    @JsonIgnore
    public PrivateKey getPrivateKey() {
        return keyPair.getPrivate();
    }

    @JsonIgnore
    public PublicKey getPublicKey() {
        return keyPair.getPublic();
    }

    public void setKeyPair(KeyPair keyPair) {
        this.keyPair = keyPair;
        final PublicKey publicKey = keyPair.getPublic();
        if(publicKey instanceof RSAPublicKey) {
            signatureAlgorithm = RsaAlgorithm.RS256;
        } else if(publicKey instanceof ECPublicKey) {
            signatureAlgorithm = EcAlgorithm.ES256;
        }
    }

    @JsonProperty(JWTClaims.AUDIENCE)
    public String getAudience() {
        return audience;
    }

    public void setAudience(List<String> audience) {
        this.audience = audience.toString().replaceAll("\\[", "").replaceAll("]", "");
    }

    public void setAudience(String... audience){
        setAudience(Arrays.asList(audience));
    }

    public void addToAudience(String... audience){
        this.audience += ", " + Arrays.toString(audience).replaceAll("\\[", "").replaceAll("]", "");
    }

    @JsonProperty(JWTClaims.ISSUER)
    public String getIssuer() {
        return issuer;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    @JsonProperty(JWTClaims.ISSUING_DATE)
    public long getIssuedAt() {
        return issuedAt.getEpochSecond();
    }

    public void setIssuedAt(long issuedAt) {
        this.issuedAt = Instant.ofEpochSecond(issuedAt);
    }

    public void setIssuedAt(Date issuedAt) {
        this.issuedAt = issuedAt.toInstant();
    }

    @JsonProperty(JWTClaims.EXPIRATION_DATE)
    public long getExpirationDate() {
        return expirationDate.getEpochSecond();
    }

    public void setExpirationDate(long expirationDate) {
        this.expirationDate = Instant.ofEpochSecond(expirationDate);
    }

    public void setExpirationDate(Date expirationDate) {
        this.expirationDate = expirationDate.toInstant();
    }

    @JsonIgnore
    public AlgorithmDefinition getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    @JsonIgnore
    public void setSignatureAlgorithm(AlgorithmDefinition signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    @Override
    public String toString() {
        return String.format(
          "{\"issuer\": %s, \"issued\": %s,  \"expires\": %s}",
                issuer,
                issuedAt.toEpochMilli(),
                expirationDate.toEpochMilli()
        );
    }
}
