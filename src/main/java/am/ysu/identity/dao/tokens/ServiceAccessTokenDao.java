package am.ysu.identity.dao.tokens;

import am.ysu.identity.domain.client.Client;
import am.ysu.identity.domain.tokens.ServiceAccessToken;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.CrudRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;
import java.util.UUID;

/**
 * Data access object for manipulating the {@link ServiceAccessToken} entity.
 * Refer to Spring JPA's documentation for more details on repositories.
 */
@Repository
@Transactional
public interface ServiceAccessTokenDao extends CrudRepository<ServiceAccessToken, UUID> {
    Optional<ServiceAccessToken> findByClientEquals(Client client);

    /**
     * Implementor's note: standard delete for some reason doesn't work with AWS MySQL(works on MariaDB 5.2, haven't tested on anything else), this is a workaround
     */
    @Modifying
    @Query(nativeQuery = true, value = "DELETE FROM service_access_token WHERE client_id=:#{#client.uniqueId}")
    int deleteByClient(@Param("client") Client client);
}
