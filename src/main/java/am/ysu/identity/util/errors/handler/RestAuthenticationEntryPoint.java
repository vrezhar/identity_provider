package am.ysu.identity.util.errors.handler;

import am.ysu.identity.controllers.util.ResponseHelper;
import am.ysu.identity.util.errors.common.auth.ClientAuthorizationException;
import am.ysu.identity.util.errors.common.ForbiddenActionException;
import am.ysu.identity.util.errors.common.UnauthorizedException;
import am.ysu.identity.util.errors.common.auth.UserAuthorizationException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class RestAuthenticationEntryPoint implements AuthenticationEntryPoint
{
    private static final int UNAUTHORIZED_STATUS = HttpStatus.UNAUTHORIZED.value();
    private static final int FORBIDDEN_STATUS = HttpStatus.FORBIDDEN.value();
    private static final String BASIC_REALM = "ClientOps";

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        SecurityContextHolder.clearContext();
        if(authException instanceof ForbiddenActionException) {
            forbidden(response, authException.getMessage());
            return;
        }
        if(authException instanceof  UnauthorizedException unauthorizedException) {
            if(authException instanceof ClientAuthorizationException clientAuthorizationException) {
                unauthorized(response, clientAuthorizationException);
                return;
            }
            if(authException instanceof UserAuthorizationException userAuthorizationException) {
                unauthorized(response, userAuthorizationException);
                return;
            }
            unauthorized(response, unauthorizedException.realm, authException.getMessage());
            return;
        }
        unauthorized(response, BASIC_REALM, authException.getMessage());
    }

    private void unauthorized(HttpServletResponse response, String realm, String message) throws IOException {
        response.setStatus(UNAUTHORIZED_STATUS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, String.format("Basic realm=\"%s\", charset=\"UTF-8\"", realm));
        response.getOutputStream().write(
                ResponseHelper
                        .createErrorResponse(message != null ? message : "authorization.required", UNAUTHORIZED_STATUS)
                        .getBytes(StandardCharsets.UTF_8)
        );

    }

    private void unauthorized(HttpServletResponse response, ClientAuthorizationException clientAuthorizationException) throws IOException {
        response.setStatus(UNAUTHORIZED_STATUS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        final String message = clientAuthorizationException.getMessage() != null ? clientAuthorizationException.getMessage() : "credentials.invalid";
        final String wwwAuthenticate = clientAuthorizationException.basic
                ? String.format("Basic realm=\"%s\", charset=\"UTF-8\"", clientAuthorizationException.realm)
                : String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\" charset=\"UTF-8\"",
                clientAuthorizationException.realm, message, clientAuthorizationException.errorDescription);
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticate);
        response.getOutputStream().write(
                ResponseHelper
                        .createErrorResponse(message != null ? message : "authorization.required", UNAUTHORIZED_STATUS)
                        .getBytes(StandardCharsets.UTF_8)
        );

    }

    private void unauthorized(HttpServletResponse response, UserAuthorizationException userAuthorizationException) throws IOException {
        response.setStatus(UNAUTHORIZED_STATUS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        final String message = userAuthorizationException.getMessage() != null ? userAuthorizationException.getMessage() : "token.invalid";
        response.setHeader(HttpHeaders.WWW_AUTHENTICATE, String.format("Bearer realm=\"%s\", error=\"%s\", error_description=\"%s\" charset=\"UTF-8\"",
                userAuthorizationException.realm, message, userAuthorizationException.errorDescription));
        response.getOutputStream().write(
                ResponseHelper
                        .createErrorResponse(message != null ? message : "authorization.required", UNAUTHORIZED_STATUS)
                        .getBytes(StandardCharsets.UTF_8)
        );
    }

    private void forbidden(HttpServletResponse response, String message) throws IOException {
        response.setStatus(FORBIDDEN_STATUS);
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.getOutputStream().write(
                ResponseHelper
                        .createErrorResponse(message != null ? message : "access.denied", FORBIDDEN_STATUS)
                        .getBytes(StandardCharsets.UTF_8)
        );
    }
}
