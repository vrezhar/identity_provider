package am.ysu.identity.service;

import am.ysu.identity.dao.ClientDao;
import am.ysu.identity.domain.client.Client;
import am.ysu.identity.dto.request.ClientCredentialsDto;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

@Service
@RequiredArgsConstructor
public class ClientService {
    private final ClientDao clientDao;
    private final PasswordEncoder passwordEncoder;

    public Optional<Client> findById(String id){
        return clientDao.findById(id);
    }

    public Client save(Client client){
        return clientDao.save(client);
    }

    public boolean checkSecret(Client client, String secret) {
        return passwordEncoder.matches(secret, client.getSecret());
    }

    /**
     * Checks the client id/secret assuming the secret in the database is not hashed
     * @param id The client id
     * @param secret The client secret
     * @return The client if the id/secret provided were correct, empty otherwise
     */
    public Optional<Client> checkClient(String id, String secret){
        final Optional<Client> optionalClient = findById(id);
        if(optionalClient.isEmpty()) {
            return Optional.empty();
        }
        final var client = optionalClient.get();
        if(client.getIsSecretEncrypted()) {
            return passwordEncoder.matches(secret, client.getSecret()) ? optionalClient : Optional.empty();
        }
        return client.getSecret().equals(secret) ? optionalClient : Optional.empty();
    }

    public Optional<Client> checkClient(String id) {
        return findById(id);
    }

    public Optional<Client> checkClient(HttpServletRequest request) {
        final var credentials = getClientCredentials(request);
        return findById(credentials.getClientId());
    }

    /**
     * Reads basic authentication details from the Authentication header
     * @param request the request to extract auth data from
     * @throws ClientAuthorizationException if credentials are not valid
     * @return The collected client credentials, or null if none were present
     */
    public ClientCredentialsDto getClientCredentials(HttpServletRequest request) {
        try {
            BasicAuthenticationConverter converter = new BasicAuthenticationConverter();
            UsernamePasswordAuthenticationToken authenticationToken = converter.convert(request);
            if(authenticationToken != null){
                ClientCredentialsDto clientCredentialsDto = new ClientCredentialsDto();
                clientCredentialsDto.setClientId(authenticationToken.getName());
                clientCredentialsDto.setClientSecret((String)authenticationToken.getCredentials());
                return clientCredentialsDto;
            }
        }
        catch (Exception ignored){ }
        throw new ClientAuthorizationException();
    }
}
