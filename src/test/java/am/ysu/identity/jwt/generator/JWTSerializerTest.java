package am.ysu.identity.jwt.generator;

import am.ysu.identity.util.jwt.generation.JWTSerializer;
import am.ysu.identity.jwt.TestingKeyHolder;
import am.ysu.identity.token.jwt.AbstractJWTToken;
import am.ysu.identity.token.jwt.oauth.JWTIDToken;
import am.ysu.security.jwt.JWT;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

public class JWTSerializerTest
{
    @Test
    @DisplayName("Check JWT parts generation")
    void generateJWT_checkThatItIsValid()
    {
        AbstractJWTToken jwt = new AbstractJWTToken(){};
        try{
            jwt.setKeyPair(TestingKeyHolder.getTestingKeyPair());
            jwt.setExpirationDate(1916239058);
            jwt.setIssuedAt(new Date());
            jwt.setIssuer("id.estateguru.co");
            final String encodedJWT = JWTSerializer.encodeAndSerializeAsString(jwt);
            assertEquals(encodedJWT.split("\\.").length, 3);
        }
        catch (Exception any){
            fail(any.getMessage());
        }
    }

    @Test
    @DisplayName("Test access token serialization and deserialization via simple validations and claim checks")
    void generateUserIDTokenAndSerializeIt_thenCheckThatClaimsAreOk()
    {
        JWTIDToken jwt = new JWTIDToken();
        try {
            jwt.setKeyPair(TestingKeyHolder.getTestingKeyPair());
            jwt.setExpirationDate(1916239058);
            jwt.setIssuedAt(new Date());
            jwt.setIssuer("id.estateguru.co");
            jwt.setUserId("+37491018211");
            jwt.setAudience(Arrays.asList("example.com", "example1.com"));
            final String encodedJWT = JWTSerializer.encodeAndSerializeAsString(jwt);
            JWT parsedBackJWT = new JWT(encodedJWT);
            assertEquals("+37491018211", parsedBackJWT.getClaim("sub"), "Mismatching user id, should be +37491018211");
            assertEquals("id.estateguru.co", parsedBackJWT.getClaim("iss"), "Mismatching issuer, should be id.estateguru.co");
        }
        catch (Exception any){
            fail(any.getMessage());
        }
    }
}
