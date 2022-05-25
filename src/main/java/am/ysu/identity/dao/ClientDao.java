package am.ysu.identity.dao;

import am.ysu.identity.domain.client.Client;
import org.springframework.data.repository.CrudRepository;

public interface ClientDao extends CrudRepository<Client, String> {

}
