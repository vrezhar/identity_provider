package am.ysu.identity.service;

import am.ysu.identity.dao.ClientDao;
import am.ysu.identity.domain.Client;
import am.ysu.identity.dto.request.ClientCredentialsDto;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.web.authentication.www.BasicAuthenticationConverter;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Facade for {@link ClientDao}
 */
@Component
public class ClientService
{
    private final ClientDao clientDao;
    //private final PasswordEncoder passwordEncoder;

    ClientService(final ClientDao clientDao) {//, final PasswordEncoder passwordEncoder){
        this.clientDao = clientDao;
        //this.passwordEncoder = passwordEncoder;
    }

    public Optional<Client> findById(String id){
        return clientDao.findById(id);
    }

    public Client save(Client client){
        return clientDao.save(client);
    }

    /**
     * Checks the client id/secret assuming the secret in the database is not hashed
     * @param id The client id
     * @param secret The client secret
     * @return The client if the id/secret provided were correct, empty otherwise
     */
    public Optional<Client> checkClient(String id, String secret){
        final Optional<Client> client = findById(id);
        return (client.isPresent() && client.get().getSecret().equals(secret)) ? client : Optional.empty();
    }

    public Optional<Client> checkClient(HttpServletRequest request) {
        final var credentials = getClientCredentials(request);
        return checkClient(credentials.getClientId(), credentials.getClientSecret());
    }

    /**
     * Reads basic authentication details from the Authentication header
     * @param request the request to extract auth data from
     * @throws ClientAuthorizationException if credentials are not valid
     * @return The collected client credentials, or null if none were present
     */
    protected ClientCredentialsDto getClientCredentials(HttpServletRequest request) {
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
