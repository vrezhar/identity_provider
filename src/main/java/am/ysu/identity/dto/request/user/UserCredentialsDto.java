package am.ysu.identity.dto.request.user;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Getter;
import lombok.Setter;

/**
 * Body of a POST request passing user credentials, password should not be encrypted
 */
@Getter
@Setter
public class UserCredentialsDto {
    private String username;
    private String password;
    private boolean rememberMe = false;

    @JsonAlias("login")
    public void setUsername(String username) {
        this.username = username;
    }

    @JsonAlias("remember_me")
    public void setRememberMe(boolean rememberMe) {
        this.rememberMe = rememberMe;
    }
}
