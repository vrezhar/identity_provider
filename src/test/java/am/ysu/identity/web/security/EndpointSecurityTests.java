package am.ysu.identity.web.security;

import am.ysu.identity.token.jwt.structure.CustomJWTClaims;
import am.ysu.identity.web.MVCTestHelper;
import am.ysu.security.jwt.JWT;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Collections;

import static am.ysu.identity.controllers.APIEndpoints.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class EndpointSecurityTests extends MVCTestHelper
{
    @BeforeAll
    public void init()
    {
        initDatabase();
        userService.createUser(TEST_USER_USERNAME, TEST_USER_PASSWORD);
    }

    @Test
    void contextLoads()
    {
        assertNotNull(tokenService);
        assertNotNull(userService);
        assertNotNull(clientService);
        assertNotNull(mockMvc);
    }

    @Test
    @DisplayName("Ensure that the database is initiated before running any additional tests")
    void databaseInitiated()
    {
        assertTrue(clientService.checkClient(TEST_CLIENT_ID, TEST_CLIENT_SECRET).isPresent());
        assertTrue(userService.checkCredentials(TEST_USER_USERNAME, TEST_USER_PASSWORD).isPresent());
    }

    //Service access token tests
    @Test
    @DisplayName("Test retrieving a service access token with correct client credentials")
    void givenValidClientCredentials_GetServiceAccessTokenAndCompareIds()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headerMap = getBasicHeaders();
        headerMap.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            printAndExpect(
                    mockMvc.perform(post(TOKEN_ENDPOINTS[0] + SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headerMap))),
                    status().isOk()
            ).andExpect(
                    result -> new JWT(MVCTestHelper.getTokenFromResult(result)).getClaim(CustomJWTClaims.TOKEN_ID)
                            .equals(findServiceAccessToken(TEST_CLIENT_ID).getId().toString())
            );
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }



    @Test
    @DisplayName("test denying access to service access endpoint with incorrect client credentials")
    void givenIncorrectClientCredentials_rejectTheRequestWithHttpStatusForbidden()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + "incorrect_secret").getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headerMap = getBasicHeaders();
        headerMap.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            printAndExpect(
                    mockMvc.perform(post(TOKEN_ENDPOINTS[0] + SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headerMap))),
                    status().isForbidden()
            );
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }
}
