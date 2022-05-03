package am.ysu.identity.dto.request.token;

import lombok.Getter;
import lombok.Setter;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.NotEmpty;
import java.util.List;

@Getter
@Setter
public class TokenRefreshDto {
//    @NotBlank
//    private String clientId;
    @NotBlank
    private String refreshTokenId;
    @NotEmpty
    private List<String> roles;
}
