package am.ysu.identity.web.login;

import am.ysu.identity.AuthenticationServerTestsConfiguration;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.web.MVCTestHelper;
import am.ysu.security.jwt.JWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import static am.ysu.identity.controllers.APIEndpoints.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ContextConfiguration(classes = AuthenticationServerTestsConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class LoginControllerTests extends MVCTestHelper
{
    @Autowired
    TokenValidatorService tokenValidatorService;

    @Test
    @DisplayName("Login with correct credentials")
    void givenCorrectCredentials_LoginAndValidateIdToken() {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            final String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(post(TOKEN_ENDPOINTS[0] + SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            final MvcResult result = printAndExpect(
                    mockMvc.perform(
                            post(LOGIN_ENDPOINTS[0] + "?client_id=" + TEST_CLIENT_ID)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(String.format("{\"login\": \"%s\", \"password\": \"%s\"}", TEST_USER_USERNAME, TEST_USER_PASSWORD))
                                    .headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            ).andReturn();
            final String idToken = getTokenFromResult(result);
            final JWT jwt = new JWT(idToken);
            final var owner = tokenValidatorService.validate(jwt);
            assertTrue(owner instanceof User);
            assertEquals(((User)owner).getUsername(), TEST_USER_USERNAME);
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Vouch for user")
    void givenCorrectInitials_VouchForUserLoginAndValidateIdToken() {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            final String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(post(TOKEN_ENDPOINTS[0] + SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            final MvcResult result = printAndExpect(
                    mockMvc.perform(
                            post(LOGIN_ENDPOINTS[0] + VOUCHING_ENDPOINT)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(String.format("{\"username\": \"%s\"}", TEST_USER_USERNAME))
                                    .headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            ).andReturn();
            final String idToken = getTokenFromResult(result);
            final JWT jwt = new JWT(idToken);
            final var owner = tokenValidatorService.validate(jwt);
            assertTrue(owner instanceof User);
            assertEquals(((User)owner).getUsername(), TEST_USER_USERNAME);
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Override
    @BeforeAll
    protected void init() {
        initDatabase();
        userService.createUser(TEST_USER_USERNAME, TEST_USER_PASSWORD);
    }
}
