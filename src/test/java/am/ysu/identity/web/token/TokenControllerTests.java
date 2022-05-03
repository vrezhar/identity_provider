package am.ysu.identity.web.token;

import am.ysu.identity.AuthenticationServerTestsConfiguration;
import am.ysu.identity.controllers.APIEndpoints;
import am.ysu.identity.dto.request.AccessTokenRetrievalDto;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.jwt.TokenValidatorService;
import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.web.MVCTestHelper;
import am.ysu.security.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;
import java.util.List;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ContextConfiguration(classes = AuthenticationServerTestsConfiguration.class)
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class TokenControllerTests extends MVCTestHelper
{
    @Autowired
    TokenValidatorService tokenValidatorService;

    @Test
    void contextLoads()
    {
        assertNotNull(mockMvc);
        assertNotNull(userService);
        assertNotNull(clientService);
        assertNotNull(tokenService);
    }

    @Test
    @DisplayName("Test getting a service access token with correct credentials")
    void givenCorrectCredentials_fetchAServiceAccessToken()
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
            JWT serviceJWT = new JWT(accessToken);
            assertEquals(serviceJWT.getClaim(CustomJWTClaims.TOKEN_ID), tokenService.findServiceAccessToken(clientService.findById(TEST_CLIENT_ID).get()).get().getId().toString());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test signing a random JSON with server's private key and returning a JWT")
    void givenRandomData_signAndReturnAsJWT()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            String accessToken = getTokenFromResult(mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))).andReturn());
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            String dataToSign = "{\"test\": \"test\"}";
            String endpoint = APIEndpoints.SIGNATURE_ENDPOINT + "?produce_jwt=true";
            String newToken = getTokenFromResult(mockMvc.perform(post(endpoint).headers(new HttpHeaders(headers)).content(dataToSign)).andReturn());
            assertNotNull(newToken);
            JWT jwt = new JWT(newToken);
            assertEquals(jwt.getClaim("test"), "test");
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test exchanging id token with an access one")
    void byLoggingIn_AndGettingAnIdToken_exchangeWithAnAccessToken()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            final String serviceToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + serviceToken));
            final MvcResult loginResult = printAndExpect(
                    mockMvc.perform(
                            post(APIEndpoints.LOGIN_ENDPOINTS[0] + "?client_id=" + TEST_CLIENT_ID)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(String.format("{\"login\": \"%s\", \"password\": \"%s\"}", TEST_USER_USERNAME, TEST_USER_PASSWORD))
                                    .headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            ).andReturn();
            final String idToken = getTokenFromResult(loginResult);
            final var mapper = new ObjectMapper();
            final var payload = new AccessTokenRetrievalDto(
                    List.of("ROLE_INVESTOR", "ROLE_COMPANY"),
                    List.of("read"),
                    "EGU00001"
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + idToken));
            final MvcResult exchangeResult = printAndExpect(
                    mockMvc.perform(
                            post(APIEndpoints.LOGIN_ENDPOINTS[0] + "?client_id=" + TEST_CLIENT_ID)
                                    .contentType(MediaType.APPLICATION_JSON)
                                    .content(mapper.writeValueAsBytes(payload))
                                    .headers(new HttpHeaders(headers))
                    ),
                    status().isOk()
            ).andReturn();
            final String accessToken = getTokenFromResult(exchangeResult);
            final var owner = tokenValidatorService.validate(new JWT(accessToken));
            assertTrue(owner instanceof User);
            assertEquals(TEST_USER_USERNAME, ((User) owner).getUsername());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Override
    @BeforeAll
    protected void init() {
        initDatabase();
    }
}
