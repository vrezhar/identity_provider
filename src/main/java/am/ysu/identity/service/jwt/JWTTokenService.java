package am.ysu.identity.service.jwt;

import am.ysu.identity.dao.tokens.RefreshTokenDao;
import am.ysu.identity.dao.tokens.ServiceAccessTokenDao;
import am.ysu.identity.dao.tokens.AccessTokenDao;
import am.ysu.identity.domain.Client;
import am.ysu.identity.domain.tokens.RefreshToken;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.KeyService;
import am.ysu.identity.service.TokenService;
import am.ysu.identity.sync.Synchronization;
import am.ysu.identity.token.AbstractAccessToken;
import am.ysu.identity.token.jwt.AbstractJWTToken;
import am.ysu.identity.token.jwt.oauth.access.ServiceAccessToken;
import am.ysu.identity.token.jwt.oauth.access.JWTUserAccessToken;
import am.ysu.identity.util.DateTools;
import am.ysu.identity.token.jwt.oauth.JWTIDToken;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.KeyPair;
import java.security.SecureRandom;
import java.util.*;

@Service
@Transactional
public class JWTTokenService extends TokenService {
    private final KeyService keyService;
    private final int idTokenExpirationMinutes;
    private final String issuer;
    private final List<String> audiences;

    public JWTTokenService(
            final AccessTokenDao accessTokenDao,
            final ServiceAccessTokenDao serviceAccessTokenDao,
            final RefreshTokenDao refreshTokenDao,
            final Environment environment,
            final KeyService keyService
    ) {
        super(accessTokenDao, serviceAccessTokenDao, refreshTokenDao, environment);
        this.keyService = keyService;
        this.idTokenExpirationMinutes = environment.getProperty("security.oauth.tokens.expiration.user.id", Integer.class,2);
        this.issuer = environment.getProperty("security.oauth.tokens.issuer", String.class,"id.staging.estateguru.co");
        this.audiences = Arrays.asList(environment.getProperty("security.oauth.tokens.audience", String.class, "").replaceAll(" ", "").split(","));
    }

    public JWTIDToken generateIdToken(User user, String requestingClient, String defaultAccountId) {
        JWTIDToken jwtidToken = new JWTIDToken();
        setIdTokenProperties(jwtidToken, user, requestingClient, defaultAccountId);
        setGenericTokenProperties(jwtidToken, idTokenExpirationMinutes);
        return jwtidToken;
    }

    public JWTUserAccessToken generateUserAccessToken(User user, String clientId, boolean rememberMe) {
        JWTUserAccessToken jwt = new JWTUserAccessToken();
        final AccessToken accessToken = (AccessToken) createAccessToken(user, rememberMe);
        setUserAccessTokenProperties(jwt, accessToken, clientId,
                refreshTokenDao.findByAccessTokenEquals(accessToken).orElseThrow(() -> new RuntimeException("Shouldn't be thrown, refresh token not saved"))
        );
        return jwt;
    }

    public JWTUserAccessToken regenerateUserAccessToken(AccessToken userAccessToken, String clientId) {
        try {
            return Synchronization.lockingOn(userAccessToken.getId()).execute(() -> {
                JWTUserAccessToken jwt = new JWTUserAccessToken();
                User user = userAccessToken.getUser();
                deleteRefreshToken(userAccessToken.getRefreshToken());
                final AccessToken accessToken = (AccessToken) createAccessToken(user, userAccessToken.getIsRememberMe());
                setUserAccessTokenProperties(jwt, accessToken, clientId,
                        refreshTokenDao.findByAccessTokenEquals(accessToken).orElseThrow(() -> new RuntimeException("refresh token not saved, shouldn't be thrown"))
                );
                return jwt;
            });
        } catch (Exception e) {
            throw new RuntimeException("Unexpected fatal error " + e.getClass().getSimpleName(), e);
        }
    }

    public ServiceAccessToken generateServiceAccessToken(Client client) {
        ServiceAccessToken jwt = new ServiceAccessToken();
        jwt.setKeyPair(selectRandomServerKeyPair());
        jwt.setAudience(audiences);
        if(!audiences.contains(client.getUniqueId())){
            jwt.addToAudience(client.getUniqueId());
        }
        jwt.setClientId(client.getUniqueId());
        am.ysu.identity.domain.tokens.ServiceAccessToken accessToken = (am.ysu.identity.domain.tokens.ServiceAccessToken)createAccessToken(client);
        jwt.setAccessTokenId(accessToken.getId().toString());
        setGenericTokenProperties(jwt, accessToken);
        return jwt;
    }

    private void setUserAccessTokenProperties(JWTUserAccessToken jwt, AccessToken accessToken, String clientId, RefreshToken refreshToken) {
        setGenericTokenProperties(jwt, accessToken);
        User user = accessToken.getUser();
        jwt.setUserId(user.getUniqueId().toString());
        jwt.setUsername(user.getUsername());
        jwt.setAudience(issuer);
        if(clientId != null && !clientId.trim().equals("")){
            jwt.addToAudience(clientId);
        }
        jwt.setTokenId(accessToken.getId().toString());
        jwt.setAudience(audiences);
        if(!audiences.contains(clientId)){
            jwt.addToAudience(clientId);
        }
        jwt.setKeyPair(keyService.getKeys(user));
        jwt.setServerKeypair(selectRandomServerKeyPair());
        jwt.setRefreshTokenId(refreshToken.getId().toString());
        jwt.setRememberMe(Objects.requireNonNullElse(accessToken.getIsRememberMe(), false));
    }

    private void setIdTokenProperties(JWTIDToken jwtidToken, User user, String requestingClient, String defaultAccountId) {
        jwtidToken.setUserId(user.getUniqueId().toString());
        jwtidToken.setUsername(user.getUsername());
        jwtidToken.setTokenId(UUID.randomUUID().toString());
        jwtidToken.setAudience(issuer);
        if(requestingClient != null && !requestingClient.trim().equals("")){
            jwtidToken.addToAudience(requestingClient);
        }
        jwtidToken.setKeyPair(selectRandomServerKeyPair());
    }

    private void setGenericTokenProperties(AbstractJWTToken jwt, int expirationMinutes) {
        jwt.setIssuer(issuer);
        final Date now = new Date();
        jwt.setIssuedAt(now);
        jwt.setExpirationDate(DateTools.toDate(DateTools.toZonedTime(now).plusMinutes(expirationMinutes)));
    }

    private void setGenericTokenProperties(AbstractJWTToken jwt, AbstractAccessToken accessToken) {
        jwt.setIssuer(issuer);
        jwt.setIssuedAt(accessToken.getIssuedAt());
        jwt.setExpirationDate(accessToken.getExpiresIn());
    }

    private KeyPair selectRandomServerKeyPair() {
        final List<String> availableKeys = keyService.availableServerKeys();
        if(availableKeys == null || availableKeys.isEmpty()) {
            throw new RuntimeException("No keys available");
        }
        if(availableKeys.size() == 1) {
            return keyService.getKeys(availableKeys.get(0));
        }
        final var random = new SecureRandom();
        return keyService.getKeys(availableKeys.get(random.nextInt(availableKeys.size())));
    }
}
