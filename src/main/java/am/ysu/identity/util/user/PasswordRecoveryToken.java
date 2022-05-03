package am.ysu.identity.util.user;

import am.ysu.identity.util.DateTools;

import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * A token representing the password recovery key, has an expiration date
 */
public class PasswordRecoveryToken
{
    private String tokenId;
    private long expirationDate;

    private PasswordRecoveryToken() {}

    public boolean hasExpired(){
        return (new Date().toInstant()).compareTo(Instant.ofEpochSecond(expirationDate)) >= 0;
    }

    public String getTokenId() {
        return tokenId;
    }

    public void setTokenId(String tokenId) {
        this.tokenId = tokenId;
    }

    public long getExpirationDate() {
        return expirationDate;
    }

    public void setExpirationDate(long expirationDate) {
        this.expirationDate = expirationDate;
    }

    /**
     * Generates a token that expires in a day
     * @return the generated token
     */
    public static PasswordRecoveryToken generate()
    {
        PasswordRecoveryToken token = new PasswordRecoveryToken();
        token.tokenId = UUID.randomUUID().toString();
        token.expirationDate = DateTools.toZonedTime(new Date()).plusDays(1).toEpochSecond();
        return token;
    }

    /**
     * Serializes the token as JSON
     * @return the serialized token
     */
    public String serialize() {
        return this.toString();
    }

    @Override
    public String toString(){
        return String.format("{\"tokenId\": \"%s\", \"expirationDate\": %s}", tokenId, expirationDate);
    }
}
