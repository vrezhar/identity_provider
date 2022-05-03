package am.ysu.identity.controllers.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

import javax.servlet.http.HttpServletResponse;

public class ResponseHelper {
    private static final Logger logger = LoggerFactory.getLogger(ResponseHelper.class);

    private ResponseHelper(){}

    public static ResponseEntity<String> okResponse(){
        return ResponseEntity
                .status(HttpServletResponse.SC_OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(String.format("{\"status\": %s}", HttpServletResponse.SC_OK));
    }

    public static ResponseEntity<String> createErrorResponse(Exception e)
    {
        return ResponseEntity
                .status(HttpServletResponse.SC_INTERNAL_SERVER_ERROR)
                .contentType(MediaType.APPLICATION_JSON)
                .body(
                        String.format(
                                "{\"status\": %s, \"error\": \"%s\"}",
                                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                                e.getMessage()
                        )
                );
    }

    public static String createErrorResponse(String error)
    {
        return  String.format(
                "{\"status\": %s, \"error\": \"%s\"}",
                HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                error
        );
    }

    public static String createErrorResponse(String error, int status)
    {
        return String.format(
                "{\"status\": %s, \"error\": \"%s\"}",
                status,
                error
        );
    }

    public static ResponseEntity<String> createTokenResponse(String jwt)
    {
        logger.info("Generated JWT: {}", jwt);
        return doCreateOKResponse("token", jwt);
    }

    public static ResponseEntity<String> createSignatureResponse(String signature)
    {
        return doCreateOKResponse("signature", signature);
    }

    public static ResponseEntity<String> createKeyResponse(String key)
    {
        return doCreateOKResponse("key", key);
    }

    private static ResponseEntity<String> doCreateOKResponse(String resultJsonField, String result)
    {
        return ResponseEntity
                .status(HttpServletResponse.SC_OK)
                .contentType(MediaType.APPLICATION_JSON)
                .body(
                        String.format(
                                "{\"status\": %s, \"%s\": \"%s\"}",
                                HttpServletResponse.SC_OK,
                                resultJsonField,
                                result
                        )
                );
    }
}
