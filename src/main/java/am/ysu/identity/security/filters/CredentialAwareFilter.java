package am.ysu.identity.security.filters;

import am.ysu.identity.dto.request.user.UserCredentialsDto;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.ServletRequest;

/**
 * Generic filter for extracting client/user credentials, either from POST body or the Authorization header
 */
public abstract class CredentialAwareFilter extends OncePerRequestFilter {

    /**
     * Reads user credentials from request body
     * @param request The request to read from
     * @return User credentials object, if request body was parsable
     */
    protected UserCredentialsDto getUserCredentials(ServletRequest request)
    {
        try{
            return new ObjectMapper().readValue(
                    request.getInputStream().readAllBytes(),
                    UserCredentialsDto.class);
        }
        catch (Exception ignored){
            return null;
        }
    }


}
