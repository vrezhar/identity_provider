package am.ysu.identity.service;

import am.ysu.identity.dao.tokens.ServiceAccessTokenDao;
import am.ysu.identity.domain.Client;
import am.ysu.identity.domain.tokens.ServiceAccessToken;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.sync.Synchronization;
import am.ysu.identity.token.AbstractAccessToken;
import am.ysu.identity.token.AccessTokenOwner;
import am.ysu.identity.dao.tokens.RefreshTokenDao;
import am.ysu.identity.dao.tokens.AccessTokenDao;
import am.ysu.identity.domain.tokens.RefreshToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.ZonedDateTime;
import java.util.*;

/**
 * Main service for manipulating access and refresh tokens
 */
@Service
@Transactional
public class TokenService {
    private static final Logger logger = LoggerFactory.getLogger(TokenService.class);

    protected final AccessTokenDao accessTokenDao;
    protected final ServiceAccessTokenDao serviceAccessTokenDao;
    protected final RefreshTokenDao refreshTokenDao;
    /**
     * User access token validity minutes, configurable
     */
    private final int accessTokenExpirationMinutes;
    /**
     * Service access token validity minutes, configurable
     */
    private final int serviceTokenExpirationMinutes;

    public TokenService(final AccessTokenDao accessTokenDao,
                 final ServiceAccessTokenDao serviceAccessTokenDao,
                 final RefreshTokenDao refreshTokenDao,
                 final Environment environment
    ) {
        this.accessTokenDao = accessTokenDao;
        this.serviceAccessTokenDao = serviceAccessTokenDao;
        this.refreshTokenDao = refreshTokenDao;
        accessTokenExpirationMinutes = environment.getProperty("security.oauth.tokens.expiration.user.access", Integer.class, 5);
        serviceTokenExpirationMinutes = environment.getProperty("security.oauth.tokens.expiration.service.access", Integer.class, 10);
    }

    /**
     * Synced method for finding user access token by the token id
     * @param accessTokenId The token id
     * @return The access token, if found
     */
    public Optional<AccessToken> findUserAccessToken(String accessTokenId) {
        if(accessTokenId == null || accessTokenId.trim().equals("")){
            return Optional.empty();
        }
        try {
            Optional<AccessToken> optionalUserAccessToken = accessTokenDao.findById(UUID.fromString(accessTokenId));
            if(optionalUserAccessToken.isPresent()){
                AccessToken accessToken = optionalUserAccessToken.get();
                if(accessToken.getExpiresIn().compareTo(new Date()) <= 0){
                    deleteAccessToken(accessToken);
                    return Optional.empty();
                }
            }
            return optionalUserAccessToken;
        }
        catch (Exception ignored){
            return Optional.empty();
        }
    }

    /**
     * Synced method for finding service access token by the token id
     * @param accessTokenId The token id
     * @return The access token, if found
     */
    public Optional<ServiceAccessToken> findServiceAccessToken(String accessTokenId) {
        if(accessTokenId == null || accessTokenId.trim().equals("")){
            return Optional.empty();
        }
        try {
            Optional<ServiceAccessToken> optionalServiceAccessToken = serviceAccessTokenDao.findById(UUID.fromString(accessTokenId));
            if(optionalServiceAccessToken.isPresent()){
                ServiceAccessToken accessToken = optionalServiceAccessToken.get();
                if(accessToken.getExpiresIn().before(new Date())){
                    deleteAccessToken(accessToken);
                    return Optional.empty();
                }
            }
            return optionalServiceAccessToken;
        }
        catch (Exception e){
            logger.error("Unable to find service access token with id {} due to exception, message is " + e.getMessage(), accessTokenId);
            return Optional.empty();
        }
    }

    /**
     * Synced method for finding a refresh token by its id
     * @param refreshTokenId The token id
     * @return The token, if found
     */
    public Optional<RefreshToken> findRefreshToken(String refreshTokenId) {
        if(refreshTokenId == null || refreshTokenId.trim().equals("")){
            return Optional.empty();
        }
        try {
            return refreshTokenDao.findById(UUID.fromString(refreshTokenId));
        } catch (Exception ignored) {
            return Optional.empty();
        }
    }

    /**
     * Creates a refresh token for given access token
     * @param accessToken The access token
     */
    @Transactional
    public void createRefreshToken(AccessToken accessToken) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setIssuedAt(new Date());
        refreshToken.setExpiresIn(getRefreshTokenExpirationDateFromNow());
        refreshToken.setAccessToken(accessToken);
        refreshTokenDao.save(refreshToken);
    }

    /**
     * Create an access token for given owner, deletes the already existing one if it's present of course
     * @param owner The owner for whom the token is being issued
     * @param isRememberMe If the token is generated based on remember me
     * @return The saved token
     */
    @Transactional
    public AbstractAccessToken createAccessToken(AccessTokenOwner owner, boolean isRememberMe) {
        Objects.requireNonNull(owner);
        //findAccessToken(owner).ifPresent(this::deleteAccessToken);
        if(owner instanceof User){
            AccessToken accessToken = new AccessToken();
            accessToken.setIssuedAt(new Date());
            accessToken.setExpiresIn(getUserAccessTokenExpirationDateFromNow());
            accessToken.setUser((User)owner);
            accessToken.setIsRememberMe(isRememberMe);
            accessTokenDao.save(accessToken);
            createRefreshToken(accessToken);
            return accessToken;
        }
        Client client = (Client)owner;
        serviceAccessTokenDao.findByClientEquals(client).ifPresent(sat -> serviceAccessTokenDao.deleteByClient(client));
        ServiceAccessToken accessToken = new ServiceAccessToken();
        accessToken.setIssuedAt(new Date());
        accessToken.setExpiresIn(getServiceAccessTokenExpirationDateFromNow());
        client.setAccessToken(null);
        accessToken.setClient(client);
        return serviceAccessTokenDao.save(accessToken);
    }

    public AbstractAccessToken createAccessToken(AccessTokenOwner owner) {
        return createAccessToken(owner, false);
    }

    /**
     * Synced method for deleting an access token. Deletes the refresh token as well if it's present
     * @param accessToken the access token to delete
     */
    @Transactional
    public void deleteAccessToken(AbstractAccessToken accessToken) {
        switch (accessToken.type()) {
            case CLIENT -> {
                logger.info("Deleting service access token " + accessToken.getId().toString());
                serviceAccessTokenDao.delete((ServiceAccessToken) accessToken);
            }
            case USER -> {
                deleteRefreshToken(((AccessToken) accessToken).getRefreshToken());
                logger.info("Deleting user access token " + accessToken.getId().toString());
                accessTokenDao.delete((AccessToken) accessToken);
            }
        }
    }

    /**
     * Deletes all specified access tokens of a user
     * @param tokens the tokens to delete
     */
    @Transactional
    public void deleteAccessTokens(List<AccessToken> tokens) {
        for (AccessToken accessToken : tokens) {
            deleteRefreshToken((accessToken).getRefreshToken());
            accessTokenDao.delete(accessToken);
        }
    }

    /**
     * Wrapper method for deleting the access tokens of  a user
     * @param user The user in question
     */
    @Transactional
    public void deleteAccessTokensOf(User user) {
        findUserAccessTokens(user).forEach(this::deleteAccessToken);
    }

    /**
     * Synced method for deleting a refresh token
     * @param refreshToken The refresh token
     */
    @Transactional
    public void deleteRefreshToken(RefreshToken refreshToken) {
        Synchronization.lockingOn(refreshToken.getId()).execute(() -> {
            logger.info("Deleting refresh token " + refreshToken.getId().toString());
            refreshTokenDao.delete(refreshToken);
        });
    }

//    public EstateJWTToken serialize(AccessToken accessToken)
//    {
//
//    }
//
//    public JWTIDToken createIdToken(User user)
//    {
//        JWTIDToken idToken = new JWTIDToken();
//        idToken.setIssuedAt();
//    }

    /**
     * Synced method for finding user's access token
     * @param user The user in question
     * @return The user access tokens, if found
     */
    public List<AccessToken> findUserAccessTokens(User user) {
        if(user == null){
            return new ArrayList<>();
        }
        try{
            List<AccessToken> tokens = accessTokenDao.findAllByUserEquals(user);
            if(tokens != null && !tokens.isEmpty()){
                Iterator<AccessToken> iterator = tokens.iterator();
                while (iterator.hasNext()){
                    AccessToken accessToken = iterator.next();
                    if(accessToken.getExpiresIn().before(new Date())){
                        deleteAccessToken(accessToken);
                        iterator.remove();
                    }
                }
            }
            return tokens;
        }
        catch (Exception ignored){
            return new ArrayList<>();
        }
    }

    /**
     * Synced method for finding client's access token
     * @param client The client in question
     * @return The service access token, if present
     */
    public Optional<ServiceAccessToken> findServiceAccessToken(Client client) {
        if(client == null){
            return Optional.empty();
        }
        try{
            Optional<ServiceAccessToken> tokenOptional = serviceAccessTokenDao.findByClientEquals(client);
            if (tokenOptional.isPresent())
            {
                ServiceAccessToken accessToken = tokenOptional.get();
                if (accessToken.getExpiresIn().compareTo(new Date()) <= 0) {
                    deleteAccessToken(accessToken);
                    return Optional.empty();
                }
            }
            return tokenOptional;
        } catch (Exception ignored){
            return Optional.empty();
        }
    }

    private Date getUserAccessTokenExpirationDateFromNow()
    {
        return Date.from(ZonedDateTime.now().plusMinutes(accessTokenExpirationMinutes).toInstant());
    }

    private static Date getRefreshTokenExpirationDateFromNow() {
        return Date.from(ZonedDateTime.now().plusYears(200).toInstant());
    }

    private Date getServiceAccessTokenExpirationDateFromNow() {
        return Date.from(ZonedDateTime.now().plusMinutes(serviceTokenExpirationMinutes).toInstant());
    }
}
