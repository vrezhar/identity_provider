package am.ysu.identity.key;

import am.ysu.identity.domain.security.keys.ServerKeyMetadata;
import am.ysu.identity.jwt.TestingKeyHolder;
import am.ysu.identity.util.RSAKeyUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.xml.bind.DatatypeConverter;
import java.security.MessageDigest;
import java.security.interfaces.RSAPublicKey;

import static org.junit.jupiter.api.Assertions.*;

public class FingerPrintTest
{
    /**
     * Calculated using the following command:
     * openssl pkey -in public.key -pubin -pubout -outform der | openssl dgst -sha256 -binary | openssl enc -base64
     */
    private final String fingerprint = "SxAuHckC+LyAMvLS/Hy2VbFK6QhrYONPTgTodJhHk4w=";
    private final String fingerprintHex = "4b102e1dc902f8bc8032f2d2fc7cb655b14ae9086b60e34f4e04e8749847938c";

    @Test
    @DisplayName("Test fingerprint generation for the testing public key")
    void givenATestingPublicKey_generateCorrectFingerprint()
    {
        try{
            RSAPublicKey publicKey = (RSAPublicKey) TestingKeyHolder.getTestingKeyPair().getPublic();
            Assertions.assertEquals(fingerprintHex, RSAKeyUtils.calculateFingerPrintHex(publicKey));
            assertEquals(fingerprint, RSAKeyUtils.calculateFingerPrintBase64(publicKey));
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test fingerprints with javax.xml")
    void givenATestingPublicKey_generateFingerPrintUsingJavaxXml()
    {
        try{
            RSAPublicKey publicKey = (RSAPublicKey) TestingKeyHolder.getTestingKeyPair().getPublic();
            MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
            messageDigest.update(publicKey.getEncoded());
            byte[] fingerprint = messageDigest.digest();
            assertEquals(fingerprintHex, DatatypeConverter.printHexBinary(fingerprint).toLowerCase());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    public void test() {
        try {
            final var ec = ServerKeyMetadata.KeyAlgorithm.EC.generateKeyPair();
            assertNotNull(ec);
            final var rsa = ServerKeyMetadata.KeyAlgorithm.RSA.generateKeyPair();
            assertNotNull(rsa);
            final var ed = ServerKeyMetadata.KeyAlgorithm.ED_EC.generateKeyPair();
            assertNotNull(ed);
        } catch(Exception e) {
            fail(e.getMessage());
        }
    }
}
