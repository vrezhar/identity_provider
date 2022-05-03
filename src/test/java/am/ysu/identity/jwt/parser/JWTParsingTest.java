package am.ysu.identity.jwt.parser;

import am.ysu.identity.jwt.TestingKeyHolder;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.util.jwt.SignatureHelper;
import am.ysu.security.jwt.JWT;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import java.security.Signature;

import static org.junit.jupiter.api.Assertions.*;

public class JWTParsingTest
{
    private final String testJWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.dH7tYFOT1gFgejLrCoJfiTLVOlDkwNrqaIz9pFKWPlW1C_vjhkgyu45QNoNwMN3jJ60ufUUXFXjSQzDdC_bwpfk-VQv4v12il35rYCJ-nZZaqcPkJIW7CKbAUKbXbPeWUcwOYGItxkbebOfGto5tNcRQXsa7vRX96XO9ixBfR-Ze0Mqq_gzRDBh3CuwNtSMEYyyDBLAt7R9fAycZ3vH5tJ56cP-JzKOGuP__klkpTTE92cRkxKAFc5mO7zk5QnpkGMJVWnn3psiPGE_tYPiep00JL4nwOnuLA5iKNNhaXal9Wnt5F3CSFXxD0jJrCSgiEckxXflcytAMcBwVNgF5Z35Vjn3udAywtuZfogtKXc1xSjYJoeG14RE9v5WvBRYv0MLTTjHnBk8yi9cRAxlna1brxWIL9JCwrZsqwxFTveA3H7EBLh--92lZ0x7YkSReWhDGm0W-gVCUx9jjxKPg2zZTSjRa-1pRNNl_baD0jrOw42-g1CIJMKcQxtLNNEudU55_MI-m9W4Ijz_-JshepmUHKWqR7_QoZU1fZg7AREYNlP6GeXNfJiyoScwsveiXSYVFB5JP8xP3YQCEI7oNwyu9QyR7pjb09PCPRTl7RgBbP6zyxR2Mxq0T2We-JOBejzHm0IoEGx5HYU7htMoMSQTs_MVc_GKhwG-Rsfdffa4";

    @Test
    @DisplayName("Test parsing of the JWT header")
    void givenValidJWT_parseAlgorithmCorrectly()
    {
        try {
            final JWT parsedJWT = new JWT(testJWT);
            Assertions.assertEquals(parsedJWT.getSignatureAlgorithm(), CustomJWTClaims.DEFAULT_SIGNATURE_ALGORITHM_VALUE);
        } catch (Exception e) {
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test the signature of the sample JWT using standard java Signature class")
    void givenValidJWTAndUsingJavasDefaultSignatureClass_assertThatSignatureIsValidVerifyingWithPublicKeyGeneratedBeforehand()
    {
        try{
            final JWT parsedJWT = new JWT(testJWT);
            final Signature signature = Signature.getInstance(SignatureHelper.SHA_256_RSA_SIGNING_ALGORITHM);
            signature.initVerify(TestingKeyHolder.getTestingKeyPair().getPublic());
            signature.update(parsedJWT.getHeaderAndPayloadBytes());
            assertTrue(signature.verify(parsedJWT.getSignature()));
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test claim values of the sample JWT")
    void givenValidJWT_assertThatPredefinedClaimsArePresentAndHaveCorrectValues()
    {
        try{
            final JWT parsedJWT = new JWT(testJWT);
            assertEquals(parsedJWT.getClaim("iat"), 1516239022);
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }
}
