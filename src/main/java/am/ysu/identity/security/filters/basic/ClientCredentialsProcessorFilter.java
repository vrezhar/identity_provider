package am.ysu.identity.security.filters.basic;

import am.ysu.identity.security.filters.CredentialAwareFilter;
import am.ysu.identity.domain.client.Client;
import am.ysu.identity.security.auth.client.ClientAuthentication;
import am.ysu.identity.service.ClientService;
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
        final String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        if(authHeader.startsWith("Basic")) {
            final var credentials = clientService.getClientCredentials(request);
            final var optionalClient = clientService.findById(credentials.getClientId());
            if(optionalClient.isPresent()) {
                final var client = optionalClient.get();
                if(client.getIsSecretEncrypted()) {
                    //secret encrypted, this should be a standard basic auth
                    /*
                     * Create a custom authentication object and initialize the context with it
                     */
                    if(clientService.checkSecret(client, credentials.getClientSecret())) {
                        SecurityContextHolder.getContext().setAuthentication(createClientAuthentication(client));
                        chain.doFilter(request, response);
                        return;
                    }
                    chain.doFilter(request, response);
                    return;
                }
            }
        }
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
