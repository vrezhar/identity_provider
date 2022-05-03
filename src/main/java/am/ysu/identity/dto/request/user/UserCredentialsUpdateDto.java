package am.ysu.identity.dto.request.user;

import com.fasterxml.jackson.annotation.JsonAlias;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import org.springframework.lang.NonNull;

/**
 * A class representing request body of a POST request updating user data
 */
public class UserCredentialsUpdateDto
{
    /**
     * Required
     */
    private String username;
    /**
     * Not required unless newPassword is not present
     */
    private String newUsername;
    /**
     * Required
     */
    private String oldPassword;
    /**
     * Not required unless newUsername is present
     */
    private String newPassword;

    @JsonAlias("old_username")
    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @JsonAlias({"new_username"})
    public String getNewUsername() {
        return newUsername;
    }

    public void setNewUsername(String newUsername) {
        this.newUsername = newUsername;
    }

    @JsonAlias({"old_password", "password"})
    public String getOldPassword() {
        return oldPassword;
    }

    public void setOldPassword(String oldPassword) {
        this.oldPassword = oldPassword;
    }

    @JsonAlias({"new_password"})
    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}
