package am.ysu.identity.dao;

import am.ysu.identity.domain.Client;
import org.springframework.data.repository.CrudRepository;

public interface ClientDao extends CrudRepository<Client, String> {}
