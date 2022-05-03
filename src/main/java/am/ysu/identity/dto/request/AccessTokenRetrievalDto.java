package am.ysu.identity.dto.request;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

public class AccessTokenRetrievalDto
{
    public final List<String> roles;
    public final List<String> permissions;
    public final String accountId;

    @JsonCreator
    public AccessTokenRetrievalDto(
            @JsonProperty("roles") List<String> roles,
            @JsonProperty("permissions") List<String> permissions,
            @JsonProperty("accountId") String accountId
    ) {
        this.roles = roles;
        this.permissions = permissions;
        this.accountId = accountId;
    }
}
