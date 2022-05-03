package am.ysu.identity.dao.tokens;

import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.user.User;
import org.springframework.data.repository.CrudRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.UUID;

/**
 * Data access object for manipulating the {@link AccessToken} entity.
 * Refer to Spring JPA's documentation for more details on repositories.
 */
@Repository
public interface AccessTokenDao extends CrudRepository<AccessToken, UUID> {
    List<AccessToken> findAllByUserEquals(User user);
}
