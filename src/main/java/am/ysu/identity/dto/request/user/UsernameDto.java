package am.ysu.identity.dto.request.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import javax.validation.constraints.NotBlank;

public record UsernameDto(@NotBlank @JsonProperty("username") String username) {
    @JsonCreator
    public UsernameDto(@NotBlank @JsonProperty("username") String username) {
        this.username = username;
    }
}
