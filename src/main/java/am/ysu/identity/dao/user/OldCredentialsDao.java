package am.ysu.identity.dao.user;

import am.ysu.identity.domain.user.OldCredentials;
import org.springframework.data.repository.CrudRepository;

public interface OldCredentialsDao extends CrudRepository<OldCredentials, Long>
{
}
