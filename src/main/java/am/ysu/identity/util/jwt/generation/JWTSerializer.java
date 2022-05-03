package am.ysu.identity.util.jwt.generation;

import am.ysu.identity.token.jwt.AbstractJWTToken;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.util.Base64Tools;
import am.ysu.identity.util.jwt.SignatureHelper;
import am.ysu.security.jwt.alg.AlgorithmDefinition;
import am.ysu.security.jwt.structure.JWTClaims;
import am.ysu.security.security.util.key.KeyUtils;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.nio.charset.StandardCharsets;

public class JWTSerializer {
    private JWTSerializer(){}

    public static String encodeAndSerializeAsString(AbstractJWTToken tokenObject)
    {
        final ObjectMapper mapper = new ObjectMapper();
        final AlgorithmDefinition algorithmDefinition = tokenObject.getSignatureAlgorithm();
        final String header = String.format(
                "{\"%s\": \"%s\", \"%s\": \"%s\", \"%s\": \"%s\"}",
                JWTClaims.SIGNATURE_ALGORITHM, algorithmDefinition.getJwtAlgorithmName(),
                JWTClaims.TOKEN_TYPE, CustomJWTClaims.TOKEN_TYPE_VALUE,
                JWTClaims.PUBLIC_KEY_ID, KeyUtils.calculateFingerPrintHex(tokenObject.getPublicKey())
        );
        final String payload;
        try {
            payload = mapper.writeValueAsString(tokenObject);
        } catch(JsonProcessingException e) {
            throw new RuntimeException(e);
        }
        final String unsignedData = Base64Tools.encodeToString(header) + "." + Base64Tools.encodeToString(payload);
        final String signatureEncoded = Base64Tools.encodeToString(SignatureHelper.sign(unsignedData.getBytes(StandardCharsets.UTF_8), tokenObject.getPrivateKey(), algorithmDefinition));
        return  unsignedData + "." + signatureEncoded;
    }
}
