package am.ysu.identity.security;

import am.ysu.identity.util.RSAKeyUtils;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;

import javax.annotation.PostConstruct;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;

@Configuration
public class ServerKeyConfiguration {
    private RSAPrivateKey privateKey;
    private RSAPublicKey publicKey;

    private final Environment environment;

    ServerKeyConfiguration(final Environment environment)
    {
        this.environment = environment;
    }

    /**
     * @return The server's private/public keys as KeyPair bean
     */
    @Bean("serverKeys")
    public KeyPair serverKeys() {
        return new KeyPair(publicKey, privateKey);
    }

    /**
     * Constructs an RSA private/public key pair using files specified in the configuration
     * @throws RuntimeException if a configuration is missing or the files containing the keys cannot be read
     * @throws InvalidKeySpecException if the files specified in the configuration do not contain valid private/public keys
     */
    @PostConstruct
    void initKeys() throws RuntimeException, InvalidKeySpecException
    {
        final String keyLocation = environment.getProperty("security.keys.location", System.getProperty("user.home") + "/.keys");
        final String privateKeyName = environment.getProperty("security.keys.private", "private.key");
        final String publicKeyName = environment.getProperty("security.keys.public", "public.key");
        try(InputStream privateKeyReader = Files.newInputStream(Path.of(keyLocation + "/" + privateKeyName));
            InputStream publicKeyReader  = Files.newInputStream(Path.of(keyLocation + "/" + publicKeyName))){
            privateKey = RSAKeyUtils.getPrivateKey(new String(privateKeyReader.readAllBytes()));
            publicKey = RSAKeyUtils.getPublicKey(new String(publicKeyReader.readAllBytes()));
        }
        catch(IOException ioException){
            throw new RuntimeException("Unable to read the private/public keys of the server");
        }
    }
}
