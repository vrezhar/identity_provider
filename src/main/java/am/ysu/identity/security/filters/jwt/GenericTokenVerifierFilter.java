package am.ysu.identity.security.filters.jwt;

import am.ysu.identity.security.auth.JWTAuthentication;
import am.ysu.identity.security.filters.AbstractJWTFilter;
import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.UnauthorizedException;
import am.ysu.security.jwt.JWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class GenericTokenVerifierFilter extends AbstractJWTFilter
{
    private static final Logger logger = LoggerFactory.getLogger(GenericTokenVerifierFilter.class);

    public GenericTokenVerifierFilter(JWTTokenService jwtTokenService, TokenValidatorService tokenValidatorService)
    {
        super(jwtTokenService, tokenValidatorService);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException
    {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION); //token should be passed in the Authorization header
        if(authorizationHeader == null){
            throw new UnauthorizedException("not.authorized", Realms.TOKEN_REALM);
        }
        JWT jwt;
        try{
            jwt = JWT.fromAuthorizationHeader(authorizationHeader);
        }
        catch (IllegalArgumentException te){
            throw new UnauthorizedException("invalid.credentials", Realms.TOKEN_REALM);
        }
        final var owner = tokenValidatorService.validate(jwt);
        logger.info("Validated JWT token for " + owner.getUniqueId());
        final var auth = new JWTAuthentication(jwt);
        auth.setAuthenticated(true);
        SecurityContextHolder.getContext().setAuthentication(auth);
        filterChain.doFilter(request, response);
    }
}
