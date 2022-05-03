package am.ysu.identity.dao.user;

import am.ysu.identity.domain.security.remember.RememberMeAuthentication;
import am.ysu.identity.domain.user.User;
import org.springframework.data.repository.CrudRepository;

import java.util.List;
import java.util.Optional;

public interface RememberMeAuthenticationDao extends CrudRepository<RememberMeAuthentication, Long> {
    Optional<RememberMeAuthentication> findBySemanticsIdentifier(String semanticsIdentifier);

    List<RememberMeAuthentication> findAllByUserEquals(User user);
}
