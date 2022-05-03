package am.ysu.identity.security.filters;

import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.service.jwt.JWTTokenService;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

/**
 * Abstract class for JWT based filters. defines utility methods for working with JWT-s
 */
public abstract class AbstractJWTFilter extends OncePerRequestFilter {
    //protected final static Logger logger = LoggerFactory.getLogger(AbstractJWTFilter.class);
    private final JWTTokenService jwtTokenService;
    protected final TokenValidatorService tokenValidatorService;

    public AbstractJWTFilter(final JWTTokenService jwtTokenService, TokenValidatorService tokenValidatorService)
    {
        this.jwtTokenService = jwtTokenService;
        this.tokenValidatorService = tokenValidatorService;
    }

    protected RequestMatcher matchRequests() {
        return request -> true;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) throws ServletException {
        return !matchRequests().matches(request);
    }
}
