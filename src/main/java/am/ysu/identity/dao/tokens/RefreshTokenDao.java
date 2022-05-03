package am.ysu.identity.dao.tokens;

import am.ysu.identity.domain.tokens.RefreshToken;
import am.ysu.identity.domain.tokens.AccessToken;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

/**
 * Data access object for manipulating the {@link RefreshToken} entity.
 * Refer to Spring JPA's documentation for more details on repositories.
 */
@Repository
public interface RefreshTokenDao extends CrudRepository<RefreshToken, UUID> {
    Optional<RefreshToken> findByAccessTokenEquals(AccessToken accessToken);
}
