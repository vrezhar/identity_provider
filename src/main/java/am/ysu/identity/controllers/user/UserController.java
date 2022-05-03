package am.ysu.identity.controllers.user;

import am.ysu.identity.controllers.util.ResponseHelper;
import am.ysu.identity.dto.request.user.*;
import am.ysu.identity.dto.response.OkStatus;
import am.ysu.identity.dto.response.auth.KeyDto;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.user.UserService;
import am.ysu.identity.service.jwt.JWTTokenService;
import am.ysu.identity.util.Realms;
import am.ysu.identity.util.errors.UserNotFoundException;
import am.ysu.identity.util.errors.common.BadRequestException;
import am.ysu.identity.util.errors.common.UnauthorizedException;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.Optional;

@Validated
@RestController
@RequestMapping(value = "/user", consumes = { MediaType.APPLICATION_JSON_VALUE, MediaType.TEXT_PLAIN_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE })
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    private final UserService userService;
    private final JWTTokenService jwtTokenService;

    UserController(final UserService userService, final JWTTokenService jwtTokenService) {
        this.userService = userService;
        this.jwtTokenService = jwtTokenService;
    }

    @PostMapping
    public @ResponseBody OkStatus addNewUser(@RequestBody UserCredentialsDto userCredentialsDto) {
        if(userService.findByUsername(userCredentialsDto.getUsername()).isPresent()){
            throw new BadRequestException("user.exists");
        }
        userService.createUser(userCredentialsDto.getUsername(), userCredentialsDto.getPassword());
        return new OkStatus();
    }

    @PutMapping
    public @ResponseBody OkStatus changePassword(@RequestBody UserCredentialsUpdateDto userCredentialsUpdateDto) { //,
//                                                 @RequestParam(value = "redirect_uri", required = false) String redirectUrl,
//                                                 @RequestParam(value = "nonce", required = false) String nonce,
//                                                 HttpServletResponse response){
        final String username = userCredentialsUpdateDto.getUsername();
        Optional<User> userOptional = userService.checkCredentials(username, userCredentialsUpdateDto.getOldPassword());
        if(userOptional.isEmpty()) {
            throw new UnauthorizedException("credentials.invalid", Realms.USER_OPERATIONS_REALM);
        }
        User user = userOptional.get();
        final String newUsername = userCredentialsUpdateDto.getNewUsername();
        final String newPassword = userCredentialsUpdateDto.getNewPassword();
        userService.changeCredentials(user, newUsername, newPassword);
        return new OkStatus();
    }

    @PutMapping(value = "/email")
    public @ResponseBody OkStatus changeEmail(@RequestBody EmailChangeDto emailChange) {
        final String username = emailChange.getUsername();
        Optional<User> userOptional = userService.findByUsername(username);
        if(userOptional.isEmpty()){
            logger.info("Invalid email change request; user {} not found", username);
            throw new UserNotFoundException(username);
        }
        User user = userOptional.get();
        userService.changeUsername(user, emailChange.getNewUsername());
        return new OkStatus();
    }

    @DeleteMapping
    @ResponseBody OkStatus deleteUser(@RequestParam("username") String username) {
        User user = userService.findByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
        jwtTokenService.deleteAccessTokensOf(user);
        userService.delete(user);
        return new OkStatus();
    }

    @PostMapping(value = "/check")
    public @ResponseBody OkStatus checkUserCredentials(@RequestBody UserCredentialsDto userCredentialsDto) {
        if(userService.checkCredentials(userCredentialsDto.getUsername(), userCredentialsDto.getPassword()).isEmpty()){
            throw new UnauthorizedException("credentials.invalid", Realms.USER_OPERATIONS_REALM);
        }
        return new OkStatus();
    }

    @PutMapping("/initials")
    public @ResponseBody OkStatus changeInitials(@RequestBody UserInitialsDto initialsDto) {
        final User user = userService.findByUsername(initialsDto.username).orElseThrow(() -> new UserNotFoundException(initialsDto.username));
        userService.changeInitials(user, initialsDto);
        return new OkStatus();
    }

    @PostMapping(value = "/password/forgot")
    public @ResponseBody KeyDto forgotPassword(@RequestBody @Valid UsernameDto usernameDto) {
        final String username = usernameDto.username();
        logger.info("Received password recovery request for username {}", username);
        User user = userService.findByUsername(username).orElseThrow(() -> new UserNotFoundException(username));
        userService.generatePasswordRecoveryKeyFor(user);
        return new KeyDto(userService.save(user).getPasswordRecoveryKey());
    }

    @RequestMapping(value = "/password/recovery/check")
    ResponseEntity<String> checkRecoveryKey(@RequestParam("password_recovery_key") String passwordRecoveryKey) throws JsonProcessingException {
        userService.findByPasswordRecoveryKeyIfNotExpired(passwordRecoveryKey).orElseThrow(() -> new UserNotFoundException(passwordRecoveryKey));
        return ResponseHelper.okResponse();
    }

    @RequestMapping(value = "/password/recover", method = RequestMethod.POST)
    ResponseEntity<String> recoverPassword(@RequestParam("password_recovery_key") String passwordRecoveryKey, @RequestBody UserCredentialsDto userChangeDto) throws JsonProcessingException {
        User user = userService.findByPasswordRecoveryKeyIfNotExpired(passwordRecoveryKey).orElseThrow(() -> new UserNotFoundException(passwordRecoveryKey));
        if(!user.getUsername().equals(userChangeDto.getUsername())){
            throw new UserNotFoundException(userChangeDto.getUsername());
        }
        user.setPasswordRecoveryKey(null);
        userService.changePassword(user, userChangeDto.getPassword());
        return ResponseHelper.okResponse();
    }

    private static boolean isValidUrl(String url){
        return url.startsWith("http://") || url.startsWith("https://") || url.startsWith("www.");
    }
}
