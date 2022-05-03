package am.ysu.identity.dto.response.auth;

import am.ysu.identity.dto.response.OkStatus;

public class SignatureResponseDto extends OkStatus {
    public final String signature;

    public SignatureResponseDto(String signature) {
        this.signature = signature;
    }
}
