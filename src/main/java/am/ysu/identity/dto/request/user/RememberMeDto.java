package am.ysu.identity.dto.request.user;

import com.fasterxml.jackson.annotation.JsonAlias;
import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotNull;

@Getter
@Setter
public class RememberMeDto {
    @NotNull
    private String semanticsIdentifier;
    @NotNull
    private String token;

    @JsonAlias("sid")
    public void setSemanticsIdentifier(String semanticsIdentifier) {
        this.semanticsIdentifier = semanticsIdentifier;
    }
}
