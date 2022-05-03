package am.ysu.identity.service.jwt;

import am.ysu.identity.dao.tokens.ServiceAccessTokenDao;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.util.errors.UserNotFoundException;
import am.ysu.identity.dao.tokens.AccessTokenDao;
import am.ysu.identity.dao.user.UserDao;
import am.ysu.identity.domain.Client;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.ClientService;
import am.ysu.identity.service.KeyService;
import am.ysu.identity.token.AccessTokenOwner;
import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.ForbiddenActionException;
import am.ysu.identity.util.errors.common.UnauthorizedException;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import am.ysu.identity.util.errors.common.auth.UserAuthorizationException;
import am.ysu.security.jwt.JWT;
import am.ysu.security.jwt.validators.JWTValidator;
import am.ysu.security.jwt.validators.JWTValidatorBuilder;
import am.ysu.security.jwt.validators.common.IssuerValidator;
import am.ysu.security.jwt.validators.common.LifeSpanValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.PublicKey;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

@Service
public class TokenValidatorService {
    private static final Logger logger = LoggerFactory.getLogger(TokenValidatorService.class);

    private final UserDao userDao;
    private final AccessTokenDao accessTokenDao;
    private final ServiceAccessTokenDao serviceAccessTokenDao;
    private final ClientService clientService;
    private final KeyService keyService;
    private final String issuer;

    public TokenValidatorService(UserDao userDao, AccessTokenDao accessTokenDao, ServiceAccessTokenDao serviceAccessTokenDao, ClientService clientService, KeyService keyService, Environment environment) {
        this.userDao = userDao;
        this.accessTokenDao = accessTokenDao;
        this.serviceAccessTokenDao = serviceAccessTokenDao;
        this.clientService = clientService;
        this.keyService = keyService;
        this.issuer = environment.getProperty("security.oauth.tokens.issuer", String.class,"id.staging.estateguru.co");
    }

    @Transactional(noRollbackFor = ForbiddenActionException.class)
    public AccessTokenOwner validate(JWT jwt) {
        final String publicKeyId = jwt.getPublicKeyId();
        final PublicKey publicKey = keyService.getPublicKey(publicKeyId);
        if(publicKey == null) {
            throw new UnauthorizedException("public.key.invalid", Realms.DEFAULT_REALM);
        }
        final String uniqueId = jwt.getSubject();
        final String tokenId = jwt.getTokenId();
        final Object accountId = jwt.getClaim(CustomJWTClaims.ACCOUNT_ID);
        final Optional<Client> possibleClient = clientService.findById(uniqueId);
        final boolean isIdToken = (accountId == null && possibleClient.isEmpty());
        if(!isIdToken) {
            if(possibleClient.isPresent()) {
                final JWTValidator validator = JWTValidatorBuilder
                        .newValidator()
                        .withValidIssuers(issuer)
                        .withSignatureVerificationKey(publicKey)
                        .withCustomValidator(new LifeSpanValidator())
                        .create();
                if(!validator.validate(jwt)){
                    serviceAccessTokenDao.findById(getIdFromStringOrElse(tokenId,
                            () -> new ClientAuthorizationException("token.id.invalid"))).ifPresent(serviceAccessTokenDao::delete);
                    throw new ClientAuthorizationException(validator.getErrorMessage(), false);
                }
                logger.info("Successfully validated access token for client " + uniqueId);
                return possibleClient.get();
            }
            //is not an id token and no client is present, meaning it's an access token
            final User user = userDao.findByUniqueId(getIdFromStringOrElse(uniqueId, () -> new UserAuthorizationException("token.id.invalid")))
                    .orElseThrow(() -> new UserNotFoundException(uniqueId));
            final AccessToken accessToken = accessTokenDao.findById(getIdFromStringOrElse(tokenId,
                    () -> new UserAuthorizationException("token.id.invalid"))).orElseThrow(() -> new ForbiddenActionException("access.token.invalid"));
            logger.info("Successfully validated access token for user " + uniqueId);
            return accessToken.getUser();
        }
        //this is an id token
        JWTValidator validator = JWTValidatorBuilder
                .newValidator()
                .withCustomValidator(new IssuerValidator(issuer))
                .withCustomValidator(new LifeSpanValidator())
                .withSignatureVerificationKey(publicKey)
                .create();
        if(!validator.validate(jwt)){
            throw new UserAuthorizationException(validator.getErrorMessage());
        }
        return userDao.findByUniqueId(getIdFromStringOrElse(uniqueId, () -> new UserAuthorizationException("token.id.invalid")))
                .orElseThrow(() -> new UserNotFoundException(uniqueId));
    }

    private static UUID getIdFromStringOrElse(String id, Supplier<? extends UnauthorizedException> exceptionSupplier) {
        try {
            return UUID.fromString(id);
        } catch (Exception ignored) {
            throw exceptionSupplier.get();
        }
    }
}
