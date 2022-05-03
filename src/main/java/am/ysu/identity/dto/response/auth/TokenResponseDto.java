package am.ysu.identity.dto.response.auth;

import am.ysu.identity.dto.response.OkStatus;

public class TokenResponseDto extends OkStatus {
    public final String token;

    public TokenResponseDto(String token) {
        this.token = token;
    }
}
