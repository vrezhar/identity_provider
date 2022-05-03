package am.ysu.identity.controllers.keys;

import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.KeyService;
import am.ysu.identity.service.user.UserService;
import am.ysu.identity.util.errors.UserNotFoundException;
import am.ysu.security.jwk.JWK;
import am.ysu.security.jwk.ec.EcJWK;
import am.ysu.security.jwk.rsa.RsaJWK;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.*;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.stream.Collectors;

@RestController
public class KeyController {
    private static final Logger logger = LoggerFactory.getLogger(KeyController.class);

    private final KeyService keyService;
    private final UserService userService;

    KeyController(final KeyService keyService, final UserService userService) {
        this.keyService = keyService;
        this.userService = userService;
    }

    @RequestMapping(value = "/key", method = RequestMethod.GET)
    public @ResponseBody
    List<JWK> getPublicKey(
            @RequestParam(value = "username", required = false) @Nullable String username,
            @RequestParam(value = "key_id", required = false) @Nullable String keyId
    ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException {
        PublicKey publicKey;
        if(keyId != null) {
            publicKey = keyService.getPublicKey(keyId);
            if(publicKey == null) {
                throw new NoSuchElementException("not.found");
            }
        } else if(username != null) {
            final User user = userService.findByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
            publicKey = keyService.getKeys(user).getPublic();
        } else {
            logger.warn("Loading public key list, might take some time...");
            return keyService
                    .availableKeys()
                    .stream()
                    .map(keyService::getPublicKey)
                    .filter(key -> key instanceof RSAPublicKey || key instanceof ECPublicKey)
                    .map(key -> {
                        if(key instanceof RSAPublicKey rsaPublicKey) {
                            return RsaJWK.from(rsaPublicKey);
                        }
                        ECPublicKey ecPublicKey = (ECPublicKey) key;
                        return EcJWK.from(ecPublicKey);
                    })
                    .collect(Collectors.toList());
        }
        if(publicKey instanceof RSAKey) {
            return List.of(RsaJWK.from((RSAPublicKey)publicKey));
        }
        if(publicKey instanceof ECPublicKey) {
            return List.of(EcJWK.from((ECPublicKey)publicKey));
        }
        logger.info("Unknown public key class " + publicKey.getClass().getSimpleName());
        return new ArrayList<>();
    }
}
