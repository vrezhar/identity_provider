package am.ysu.identity.security.filters.basic;

import am.ysu.identity.dto.request.ClientCredentialsDto;
import am.ysu.identity.security.filters.CredentialAwareFilter;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import am.ysu.identity.domain.Client;
import am.ysu.identity.security.auth.client.ClientAuthentication;
import am.ysu.identity.service.ClientService;
import org.springframework.core.annotation.Order;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Filter that checks client credentials, should be put over URL-s that require basic authentication of a client
 */
@Component
@Order(1)
public class ClientCredentialsProcessorFilter extends CredentialAwareFilter {
    private final ClientService clientService;

    public ClientCredentialsProcessorFilter(final ClientService clientService) {
        this.clientService = clientService;
    }

    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
        final Client client = clientService.checkClient(request).orElseThrow(() -> new ClientAuthorizationException("invalid.credentials"));
        /*
         * Create a custom authentication object and initialize the context with it
         */
        SecurityContextHolder.getContext().setAuthentication(createClientAuthentication(client));
        chain.doFilter(request, response);
    }

    /**
     * Creates custom authentication that holds client information
     * @param client the client for whom to build the authentication
     * @return An authentication object holding client information
     */
    private static Authentication createClientAuthentication(Client client) {
        return new ClientAuthentication(client);
    }
}
