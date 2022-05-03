package am.ysu.identity.util.jwt;

import am.ysu.security.jwt.alg.AlgorithmDefinition;

import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;

public class SignatureHelper
{
    public final static String SHA_256_RSA_SIGNING_ALGORITHM = "SHA256withRSA";
    public final static String SHA256_EC_SIGNING_ALGORITHM = "SHA256withECDSA";

    public static byte[] sign(byte[] dataToSign, PrivateKey privateKey) {
        try {
            final Signature signature;
            if(privateKey instanceof RSAPrivateKey) {
                signature = Signature.getInstance(SHA_256_RSA_SIGNING_ALGORITHM);
            } else if(privateKey instanceof ECPrivateKey) {
                signature = Signature.getInstance(SHA256_EC_SIGNING_ALGORITHM);
            } else {
                throw new IllegalArgumentException("Unsupported private key type [" + privateKey.getClass().getSimpleName() + "], only RSA and EC keys supported");
            }
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static byte[] sign(byte[] dataToSign, PrivateKey privateKey, AlgorithmDefinition alg) {
        try {
            final Signature signature = Signature.getInstance(alg.getJavaAlgorithmName());
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        } catch(Exception e) {
            throw new RuntimeException(e);
        }
    }

    private SignatureHelper(){}
}
