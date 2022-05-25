package am.ysu.identity.security.filters.jwt;

import am.ysu.identity.security.filters.AbstractJWTFilter;
import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import am.ysu.security.jwt.JWT;
import am.ysu.identity.domain.client.Client;
import am.ysu.identity.security.auth.client.ClientAuthentication;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.ForbiddenActionException;
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
 * A filter for processing service access tokens should be applied over endpoints that require access tokens and client authentication is not enough
 */
@Component
public class ServiceAccessTokenProcessorFilter extends AbstractJWTFilter {

    public ServiceAccessTokenProcessorFilter(final JWTTokenService jwtTokenService, final TokenValidatorService tokenValidatorService)
    {
        super(jwtTokenService, tokenValidatorService);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException
    {
        String authorizationHeader = request.getHeader(HttpHeaders.AUTHORIZATION); //token should be passed in the Authorization header
        if(authorizationHeader == null){
            throw new ClientAuthorizationException("authorization.required");
        }
        JWT jwt;
        try{
            jwt = JWT.fromAuthorizationHeader(authorizationHeader);
        }
        catch (IllegalArgumentException te){
            throw new ClientAuthorizationException("invalid.credentials", Realms.CLIENT_REALM, te);
        }
        var client = tokenValidatorService.validate(jwt);
        if(!(client instanceof Client)){
            throw new ForbiddenActionException("access.denied");
        }
        /*
         * initialize the context with a custom authentication
         */
        SecurityContextHolder.getContext().setAuthentication(createServiceAccessTokenAuthentication(jwt, (Client)client));
        chain.doFilter(request, response);
    }

    /**
     * Creates an authentication based on the claims of the JWT, sets the principal to JWT's subject claim
     * @param jwt The JWT to build the authentication from
     * @param client The authenticated client
     * @return An authentication object based on the service access token
     */
    private Authentication createServiceAccessTokenAuthentication(JWT jwt, Client client)
    {
        ClientAuthentication authentication = new ClientAuthentication(client);
        authentication.setAuthenticated(true);
        return authentication;
    }
}
