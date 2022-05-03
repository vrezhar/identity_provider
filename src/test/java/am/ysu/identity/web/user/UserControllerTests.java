package am.ysu.identity.web.user;

import am.ysu.identity.AuthenticationServerTestsConfiguration;
import am.ysu.identity.controllers.APIEndpoints;
import am.ysu.identity.dto.request.user.UserCredentialsDto;
import am.ysu.identity.dto.request.user.UserCredentialsUpdateDto;
import am.ysu.identity.web.MVCTestHelper;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.*;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ContextConfiguration(classes = AuthenticationServerTestsConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class UserControllerTests extends MVCTestHelper
{
    @Test
    void contextLoads()
    {
        assertNotNull(mockMvc);
        assertNotNull(userService);
    }

    @BeforeAll
    public void init()
    {
        super.initDatabase();
        userService.createUser(TEST_USER_USERNAME, TEST_USER_PASSWORD);
    }

    @Test
    @DisplayName("Test getting users credentials changed provided the old password is present")
    void givenCorrectCredentialsAndByFetchingServiceAccessTokenBeforehand_changeTheUsersPassword()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try {
            String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(
                                    MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))
                            ),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            UserCredentialsUpdateDto dto = new UserCredentialsUpdateDto();
            dto.setUsername(TEST_USER_USERNAME);
            dto.setOldPassword(TEST_USER_PASSWORD);
            dto.setNewPassword("aNewPassword");
            printAndExpect(
                    mockMvc.perform(
                            MockMvcRequestBuilders.put(APIEndpoints.USER_UPDATE_ENDPOINT)
                                    .content(new ObjectMapper().writeValueAsString(dto))
                                    .headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            );
            Assertions.assertTrue(userService.checkCredentials(TEST_USER_USERNAME, dto.getNewPassword()).isPresent());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test deleting a user from the AS database")
    void byFetchingServiceAccessTokenBeforeHand_deleteAnExistingUser()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try {
            String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(
                                    MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))
                            ),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            Assertions.assertTrue(userService.checkCredentials(TEST_USER_USERNAME, TEST_USER_PASSWORD).isPresent());
            printAndExpect(
                    mockMvc.perform(
                            delete(APIEndpoints.USER_UPDATE_ENDPOINT + "?username=" + TEST_USER_USERNAME).headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            );
            Assertions.assertTrue(userService.checkCredentials(TEST_USER_USERNAME, TEST_USER_PASSWORD).isEmpty());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test the forgot password flow")
    void byFetchingForgotPasswordToken_ChangeTheUsersPassword()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try {
            String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(
                                    MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))
                            ),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            String forgotPasswordKey = getKeyFromResult(
                    printAndExpect(
                            mockMvc.perform(
                                    post(APIEndpoints.FORGOT_PASSWORD_ENDPOINT + "?username=" + TEST_USER_USERNAME).headers(new HttpHeaders(headers))
                            ),
                            status().isOk()
                    ).andReturn()
            );
            UserCredentialsDto dto = new UserCredentialsDto();
            dto.setUsername(TEST_USER_USERNAME);
            dto.setPassword("aNewPassword");
            Assertions.assertTrue(userService.findByPasswordRecoveryKeyIfNotExpired(forgotPasswordKey).isPresent());
            Assertions.assertTrue(userService.checkCredentials(TEST_USER_USERNAME, TEST_USER_PASSWORD).isPresent());
            printAndExpect(
                    mockMvc.perform(
                            post(APIEndpoints.PASSWORD_RECOVERY_ENDPOINT + "?password_recovery_key=" + forgotPasswordKey)
                                    .headers(new HttpHeaders(headers))
                                    .content(new ObjectMapper().writeValueAsString(dto))
                    ),
                    status().isOk()
            );
            Assertions.assertTrue(userService.checkCredentials(TEST_USER_USERNAME, dto.getPassword()).isPresent());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

}
