package am.ysu.identity.dao.user;

import am.ysu.identity.domain.user.UserKeys;
import am.ysu.identity.domain.user.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;

/**
 * Data access object for manipulating the {@link UserKeys} entity.
 * Refer to Spring JPA's documentation for more details on repositories.
 */
public interface UserKeysDao extends CrudRepository<UserKeys, Long>
{
    Optional<UserKeys> findByUserEquals(User user);

    Optional<UserKeys> findByKeyId(String keyId);
}
