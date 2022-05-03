package am.ysu.identity.dao.user;

import am.ysu.identity.domain.user.User;
import org.springframework.data.repository.CrudRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Data access object for manipulating the {@link User} entity.
 * Refer to Spring JPA's documentation for more details on repositories.
 */
public interface UserDao extends CrudRepository<User, Long>
{
    Optional<User> findByUniqueId(UUID uuid);

    Optional<User> findByUsername(String username);

    Optional<User> findByPasswordRecoveryKey(String passwordRecoveryKey);
}
