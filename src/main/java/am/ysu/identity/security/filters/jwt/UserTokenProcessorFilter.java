package am.ysu.identity.security.filters.jwt;

import am.ysu.identity.security.auth.JWTAuthentication;
import am.ysu.identity.security.auth.user.UserAuthentication;
import am.ysu.identity.security.filters.AbstractJWTFilter;
import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.util.errors.common.ForbiddenActionException;
import am.ysu.identity.util.errors.common.auth.UserAuthorizationException;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.token.AccessTokenOwner;
import am.ysu.identity.util.Realms;
import am.ysu.security.jwt.JWT;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * A filter for processing ID and access tokens, should be applied to all endpoints that require ID tokens to grant access to a resource
 */
@Component
@Order(1)
public class UserTokenProcessorFilter extends AbstractJWTFilter
{

    public UserTokenProcessorFilter(final JWTTokenService jwtTokenService, final TokenValidatorService tokenValidatorService) {
        super(jwtTokenService, tokenValidatorService);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authorizationHeader == null){
            throw new UserAuthorizationException("user.auth.required");
        }
        JWT jwt;
        try{
            jwt = JWT.fromAuthorizationHeader(authorizationHeader);
        }
        catch (IllegalArgumentException te){
            throw new UserAuthorizationException("credentials.invalid", te, Realms.USER_OPERATIONS_REALM);
        }
        final AccessTokenOwner owner = tokenValidatorService.validate(jwt);
        if(!(owner instanceof User)) {
            throw new ForbiddenActionException("access.denied");
        }
        /*
         * Initialize the context with custom authentication containing the JWT's info
         */
        SecurityContextHolder.getContext().setAuthentication(createIdTokenAuthentication(jwt, (User)owner));
        filterChain.doFilter(request, response);
    }

    /**
     * Creates an authentication from ID token's data
     * @param jwt The JWT to build the authentication from
     * @param user The authenticated user
     * @return An authentication object containing JWT's data, the principal is the ID token's subject claim
     */
    private static Authentication createIdTokenAuthentication(JWT jwt, User user)
    {
        JWTAuthentication jwtAuthentication = new UserAuthentication(jwt, user);
        jwtAuthentication.setAuthenticated(true);
        return jwtAuthentication;
    }
}
