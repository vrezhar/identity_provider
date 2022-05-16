package am.ysu.identity.controllers.auth;

import am.ysu.identity.dto.request.user.RememberMeDto;
import am.ysu.identity.dto.request.user.UserCredentialsDto;
import am.ysu.identity.dto.request.user.UserInitialsDto;
import am.ysu.identity.dto.response.auth.TokenResponseDto;
import am.ysu.identity.domain.Client;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.user.RememberMeService;
import am.ysu.identity.service.user.UserService;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.token.jwt.oauth.JWTIDToken;
import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.common.auth.UserAuthorizationException;
import am.ysu.identity.util.jwt.generation.JWTSerializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.lang.Nullable;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.NoSuchElementException;

@RestController
//@RequestMapping(value = "/login")
@Validated
public class LoginController {
    private static final Logger logger = LoggerFactory.getLogger(LoginController.class);

    private final UserService userService;
    private final JWTTokenService jwtTokenService;
    private final RememberMeService rememberMeService;

    public LoginController(final UserService userService, final JWTTokenService jwtTokenService, RememberMeService rememberMeService) {
        this.userService = userService;
        this.jwtTokenService = jwtTokenService;
        this.rememberMeService = rememberMeService;
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserCredentialsDto userCredentialsDto, HttpServletResponse response) {
        final User user = userService.checkCredentials(userCredentialsDto.getUsername(), userCredentialsDto.getPassword())
                .orElseThrow(() -> new UserAuthorizationException("invalid.credentials", Realms.USER_OPERATIONS_REALM));
        final String jwt = JWTSerializer.encodeAndSerializeAsString(jwtTokenService.generateIdToken(user, "*"));
        if(userCredentialsDto.isRememberMe()) {
            rememberMeService.rememberMe(user, response);
        }
        return ResponseEntity.status(HttpStatus.OK).body(new TokenResponseDto(jwt));
    }

    @PostMapping("/login/vouch")
    @PreAuthorize("principal instanceof T(am.ysu.identity.domain.Client)")
    public TokenResponseDto vouch(
            @AuthenticationPrincipal Client client,
            @Valid @RequestBody UserInitialsDto userInitialsDto
    ) {
        final User user = userService.findByUsername(userInitialsDto.username).orElseThrow(() -> {
            logger.info("User {} not found", userInitialsDto.username);
            return new NoSuchElementException("not.found");
        } );
//        final Client client = (Client)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        userService.changeInitials(user, userInitialsDto);
        final var jwt = JWTSerializer.encodeAndSerializeAsString(jwtTokenService.generateIdToken(user, client.getId()));
        return new TokenResponseDto(jwt);
    }

    @PostMapping("/login/remember")
    public TokenResponseDto rememberMe(HttpServletRequest request, HttpServletResponse response, @RequestBody(required = false) @Valid RememberMeDto rememberMeDto) {
        final User user = rememberMeService.checkRememberMe(request, response, rememberMeDto).orElseThrow(() -> new NoSuchElementException("not.found"));
        final JWTIDToken token = jwtTokenService.generateIdToken(user, "*");
        token.setRememberMe(true);
        final String jwt = JWTSerializer.encodeAndSerializeAsString(token);
        return new TokenResponseDto(jwt);
    }

}
