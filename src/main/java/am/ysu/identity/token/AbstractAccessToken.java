package am.ysu.identity.token;

import java.io.Serializable;
import java.util.Date;

public abstract class AbstractAccessToken {
    protected Date issuedAt;
    protected Date expiresIn;

    public abstract Serializable getId();
    public abstract AccessTokenType type();
    public abstract AccessTokenOwner owner();

    public abstract void setExpiresIn(Date expiresIn);

    public abstract Date getExpiresIn();

    public abstract Date getIssuedAt();
}
