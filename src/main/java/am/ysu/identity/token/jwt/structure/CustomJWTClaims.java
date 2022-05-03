package am.ysu.identity.token.jwt.structure;

public class CustomJWTClaims {
    public static final String DEFAULT_SIGNATURE_ALGORITHM_VALUE = "RS256";
    public static final String TOKEN_TYPE_VALUE = "jwt";
    public static final String USER_EMAIL = "email";
    public static final String FIRST_NAME = "fnm";
    public static final String LAST_NAME = "snm";
    public static final String ACCOUNT_ID = "acc";
    public static final String TOKEN_ID = "jti";
    public static final String REFRESH_TOKEN_ID = "rti";
    public static final String PUBLIC_KEY_FINGERPRINT = "kid";
    public static final String IS_REMEMBER_ME = "rme";
    public static final String ROLES = "roles";
    public static final String SCOPE = "scope";

    private CustomJWTClaims(){}
}
