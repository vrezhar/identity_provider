package am.ysu.identity.dto.request.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotNull;

public class UserInitialsDto {
    @JsonProperty("username") @NotNull public final String username;
    @JsonProperty("firstName") public final String firstName;
    @JsonProperty("lastName") public final String lastName;
    @JsonProperty("defaultAccountId") public final String defaultAccountId;

    @JsonCreator
    public UserInitialsDto(
            @JsonProperty("username") String username,
            @JsonProperty("firstName") String firstName,
            @JsonProperty("lastName") String lastName,
            @JsonProperty("defaultAccountId") String defaultAccountId) {
        this.username = username;
        this.firstName = firstName;
        this.lastName = lastName;
        this.defaultAccountId = defaultAccountId;
    }
}
