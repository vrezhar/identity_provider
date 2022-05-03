package am.ysu.identity.service.user;

import am.ysu.identity.dao.user.RememberMeAuthenticationDao;
import am.ysu.identity.dto.request.user.RememberMeDto;
import am.ysu.identity.domain.security.remember.HashType;
import am.ysu.identity.domain.security.remember.RememberMeAuthentication;
import am.ysu.identity.domain.user.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.NoSuchElementException;
import java.util.Optional;

@Service
public class RememberMeService implements InitializingBean {
    private static final Logger logger = LoggerFactory.getLogger(RememberMeService.class);

    private final RememberMeAuthenticationDao rememberMeAuthenticationDao;

    @Value("${security.remember-me.hash-type}")
    private HashType tokenHashType;

    @Value("${security.remember-me.cookie.domain}")
    private String cookieDomain;

    @Value("${security.remember-me.cookie.max-age}")
    private int cookieMaxAge;

    public RememberMeService(RememberMeAuthenticationDao rememberMeAuthenticationDao) {
        this.rememberMeAuthenticationDao = rememberMeAuthenticationDao;
    }

    @Transactional(noRollbackFor = NoSuchElementException.class)
    public Optional<User> checkRememberMe(HttpServletRequest request, HttpServletResponse response, RememberMeDto rememberMeDto) {
        if(rememberMeDto != null) {
            return doRememberMe(response, rememberMeDto.getSemanticsIdentifier(), rememberMeDto.getToken());
        }
        Cookie semanticsId = null, token = null;
        final Cookie[] cookies = request.getCookies();
        if(cookies == null) {
            return Optional.empty();
        }
        for(Cookie cookie : cookies) {
            if(cookie.getName().equals(RememberMeAuthentication.SEMANTICS_IDENTIFIER_COOKIE)) {
                semanticsId = cookie;
                continue;
            }
            if(cookie.getName().equals(RememberMeAuthentication.TOKEN_COOKIE)) {
                token = cookie;
            }
        }
        if(semanticsId == null || token == null) {
            return Optional.empty();
        }
        final String sidValue = semanticsId.getValue();
        try {
            Long.parseLong(sidValue);
        } catch (Exception e) {
            logger.info("Invalid semantics identifier {} present in the cookie", sidValue);
            clearCookies(response);
            return Optional.empty();
        }
        return doRememberMe(response,  sidValue, token.getValue());
    }

    private Optional<User> doRememberMe(HttpServletResponse response, String semanticsIdentifier, String token) {
        Optional<RememberMeAuthentication> possibleAuth = rememberMeAuthenticationDao.findBySemanticsIdentifier(semanticsIdentifier);
        if(possibleAuth.isEmpty()) {
            logger.info("No authentication found by semantics identifier " + semanticsIdentifier);
            clearCookies(response);
            return Optional.empty();
        }
        final var auth = possibleAuth.get();
        final User user = auth.getUser();
        if(auth.getExpirationDate().isBefore(LocalDateTime.now())) {
            logger.info("Remember me token with semantics identifier {} for user {} has expired", semanticsIdentifier, user.getUsername());
            rememberMeAuthenticationDao.delete(auth);
            clearCookies(response);
            return Optional.empty();
        }
        if(!auth.validate(token)) {
            logger.warn("Security alert; hash mismatch with a valid semantics identifier {}, clearing all remembered authentications", semanticsIdentifier);
            rememberMeAuthenticationDao.deleteAll(rememberMeAuthenticationDao.findAllByUserEquals(user));
            return Optional.empty();
        }
        logger.info("Remember me authentication successfully validated for {}, removing old cookies", user.getUsername());
        rememberMeAuthenticationDao.delete(auth);
        rememberMe(user, response);
        return Optional.of(user);
    }

    @Transactional
    public void rememberMe(User user, HttpServletResponse response) {
        logger.info("RememberMe switched on for " + user.getUsername());
        final SecureRandom secureRandom;
        try {
            secureRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException nse) {
            logger.error("Strong secure random algorithm not available, exception message is " + nse.getMessage());
            throw new RuntimeException(nse);
        }
        logger.info("Generating a random semantics identifier...");
        final byte[] sBytes = new byte[4];
        secureRandom.nextBytes(sBytes);
        String semanticsId = new BigInteger(1, sBytes).toString();
        while (rememberMeAuthenticationDao.findBySemanticsIdentifier(semanticsId).isPresent()) {
            logger.info("Duplicate semantics identifier generated for {}, re-rolling", user.getUsername());
            secureRandom.nextBytes(sBytes);
            semanticsId = new BigInteger(1, sBytes).toString();
        }
        logger.info("Generating a remember me token...");
        final byte[] tBytes = new byte[8];
        secureRandom.nextBytes(tBytes);
        final String token = new BigInteger(1, tBytes).toString();
        final var auth = new RememberMeAuthentication();
        auth.setUser(user);
        auth.setSemanticsIdentifier(semanticsId);
        auth.setHashType(tokenHashType);
        auth.setExpirationDate(LocalDateTime.now().plusHours(cookieMaxAge));
        logger.info("Generated remember me authentication for user {}: semantics id: {}, token: {}, used hash type: {}, cookie expires at: {}",
                user.getUsername(), semanticsId, token, tokenHashType, auth.getExpirationDate());
        auth.populateCookiesAndSetHash(response, token, cookieDomain);
        logger.info("Cookies set for domain " + cookieDomain);
        rememberMeAuthenticationDao.save(auth);
    }

    private static void clearCookies(HttpServletResponse response) {
        final var deletedSid = new Cookie(RememberMeAuthentication.SEMANTICS_IDENTIFIER_COOKIE, "");
        deletedSid.setMaxAge(0);
        final var deletedToken = new Cookie(RememberMeAuthentication.TOKEN_COOKIE, "");
        deletedToken.setMaxAge(0);
        response.addCookie(deletedSid);
        response.addCookie(deletedToken);
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        logger.info("Remember me service configured for domain {}, using token hash type {}; max age of cookies: {} hours", cookieDomain, tokenHashType, cookieMaxAge);
    }
}
