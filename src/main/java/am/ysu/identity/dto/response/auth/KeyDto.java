package am.ysu.identity.dto.response.auth;

import am.ysu.identity.dto.response.OkStatus;

public class KeyDto extends OkStatus {
    public final String key;

    public KeyDto(String key) {
        this.key = key;
    }
}
