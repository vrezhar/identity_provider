package am.ysu.identity.token;

import java.io.Serializable;

public interface AccessTokenOwner
{
    Serializable getUniqueId();
}
