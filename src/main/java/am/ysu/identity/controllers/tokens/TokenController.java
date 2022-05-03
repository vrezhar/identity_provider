package am.ysu.identity.controllers.tokens;

import am.ysu.identity.controllers.util.ResponseHelper;
import am.ysu.identity.domain.Client;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.dto.request.AccessTokenRetrievalDto;
import am.ysu.identity.dto.request.token.TokenRefreshDto;
import am.ysu.identity.dto.response.auth.TokenResponseDto;
import am.ysu.identity.security.auth.JWTAuthentication;
import am.ysu.identity.security.auth.user.UserAuthentication;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.util.errors.TokenValidationException;
import am.ysu.identity.util.jwt.generation.JWTSerializer;
import am.ysu.identity.dto.response.OkStatus;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.sync.Synchronization;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Objects;

@RestController
@RequestMapping(value = "/token", consumes = { MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE })
public class TokenController {
    private final JWTTokenService jwtTokenService;

    public TokenController(final JWTTokenService jwtTokenService)
    {
        this.jwtTokenService = jwtTokenService;
    }

    @RequestMapping(value = "/user", method = RequestMethod.POST)
    @PreAuthorize("principal instanceof T(am.ysu.identity.domain.user.User)")
    public @ResponseBody
    TokenResponseDto getAccessToken(
            @RequestBody AccessTokenRetrievalDto accessTokenRetrievalDto,
            @RequestParam("client_id") String clientId
    ) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        boolean rememberMe = false;
        if(authentication instanceof UserAuthentication userAuthentication) {
            rememberMe = Objects.requireNonNullElse((Boolean)userAuthentication.jwt.getClaim(CustomJWTClaims.IS_REMEMBER_ME), false);
        }
        final User user = (User) authentication.getPrincipal();
        user.setAccountId(accessTokenRetrievalDto.accountId);
        return new TokenResponseDto(
                JWTSerializer.encodeAndSerializeAsString(
                        jwtTokenService.generateUserAccessToken(user, clientId, rememberMe)
                                .withRoles(accessTokenRetrievalDto.roles)
                )
        );
    }

    @RequestMapping(value = "/check", method = RequestMethod.POST)
    public ResponseEntity<?> checkToken() {
        final var authentication = SecurityContextHolder.getContext().getAuthentication();
        if(authentication instanceof JWTAuthentication jwtAuthentication) {
            return ResponseEntity.ok(jwtAuthentication.jwt.getClaims());
        }
        return new ResponseEntity<>(HttpStatus.OK);
    }

    @RequestMapping(value = "/service", method = RequestMethod.POST)
    @PreAuthorize("principal instanceof T(am.ysu.identity.domain.Client)")
    public ResponseEntity<String> getServiceAccessToken() {
        final Client client = (Client)SecurityContextHolder.getContext().getAuthentication().getPrincipal();
        return ResponseHelper.createTokenResponse(JWTSerializer.encodeAndSerializeAsString(jwtTokenService.generateServiceAccessToken(client)));
    }

    @PostMapping(value = "/refresh")
    public @ResponseBody TokenResponseDto refreshAccessToken(@Valid @RequestBody TokenRefreshDto tokenRefreshDto) {
        final String refreshToken = tokenRefreshDto.getRefreshTokenId();
        final AccessToken accessToken = jwtTokenService.findRefreshToken(refreshToken).orElseThrow( () -> new TokenValidationException("Refresh token not found by id " + refreshToken)).getAccessToken();
        return new TokenResponseDto(
                JWTSerializer.encodeAndSerializeAsString(
                        jwtTokenService.regenerateUserAccessToken(accessToken, "*")
                                .withRoles(tokenRefreshDto.getRoles())
                )
        );
    }

    @PostMapping(value = "/revoke")
    public @ResponseBody OkStatus revokeToken(
            @RequestParam(value = "access_token", required = false) String accessTokenId,
            @RequestParam(value = "id_token", required = false) String idTokenId
    ) {
        if((accessTokenId == null || accessTokenId.equals("")) && (idTokenId == null || idTokenId.equals(""))){
            throw new TokenValidationException("No token id present");
        }
        if(accessTokenId != null && !accessTokenId.equals("")){
            jwtTokenService.deleteAccessToken(jwtTokenService.findUserAccessToken(accessTokenId)
                    .orElseThrow(() -> new TokenValidationException("No access token found by id " + accessTokenId))
            );
        }
        return new OkStatus();
    }
}
