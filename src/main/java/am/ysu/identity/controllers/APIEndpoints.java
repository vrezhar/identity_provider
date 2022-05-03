package am.ysu.identity.controllers;

public class APIEndpoints {
    private APIEndpoints(){}

    public static final String[] LOGIN_ENDPOINTS = new String[]{ "/login", "/authorize" };
    public static final String VOUCHING_ENDPOINT = "/vouch";
    public static final String SIGNATURE_ENDPOINT = "/sign";
    public static final String[] ID_TOKEN_ENDPOINTS = new String[]{ "/login", "/authorize" };
    public static final String[] TOKEN_ENDPOINTS = new String[]{ "/token", "/oauth/token" };
    public static final String SERVICE_ACCESS_TOKEN_ENDPOINT = "/service";
    public static final String USER_ACCESS_TOKEN_ENDPOINT =  "/user";
    public static final String TOKEN_VALIDATION_ENDPOINT =  "/check";
    public static final String TOKEN_REVOCATION_ENDPOINT = "/revoke" ;
    public static final String PUBLIC_KEY_RETRIEVAL_ENDPOINT = "/key";
    public static final String USER_REGISTRATION_ENDPOINT = "/user";
    public static final String FORGOT_PASSWORD_ENDPOINT = "/user/password/forgot";
    public static final String PASSWORD_RECOVERY_ENDPOINT =  "/user/password/recover";
    public static final String USER_CREDENTIALS_VERIFICATION_ENDPOINT = "/user/check";
    public static final String USER_UPDATE_ENDPOINT = "/user" ;
    public static final String USER_DELETION_ENDPOINT =  "/user";
}
