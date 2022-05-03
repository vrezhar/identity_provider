package am.ysu.identity.dao;

import am.ysu.identity.domain.security.server.ServerSigningKey;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

public interface ServerKeyDao extends CrudRepository<ServerSigningKey, Long> {
    Optional<ServerSigningKey> findByKeyId(String keyId);
}
