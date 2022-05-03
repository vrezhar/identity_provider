package am.ysu.identity.web.key;

import am.ysu.identity.controllers.APIEndpoints;
import am.ysu.identity.domain.user.User;
import am.ysu.identity.service.KeyService;
import am.ysu.identity.web.MVCTestHelper;
import am.ysu.security.jwk.rsa.RsaJWK;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.util.MultiValueMap;

import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@AutoConfigureMockMvc
@SpringBootTest(properties = {"spring.main.lazy-initialization=true"})
@TestInstance(TestInstance.Lifecycle.PER_CLASS)
public class KeyControllerTests extends MVCTestHelper
{
    private static final String RANDOM_JWT = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImp0aSI6InRlc3QifQ.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMiwiZXhwIjoyNTE2MjM5MDIyfQ.VWXqecP5OZ-mNLLDH8xR5pgf-owIJMLcFc7koy7bqebWCoVVG3ak53NCOq6EbSUaHnsCqehGegcvLpfAaWo9snYV3uer40ZNQQsD0nus2mbLYFTTt3Tn8op4AbBFlAewcj3neNGat_H99MMe_8sX7GmHoSND6enSnNBgwUdu55P3Bim4bFKfOvSdw1Gp99Q9kklhEiANMmELpOnUBbuESsSqdnY_wPjPpJ6li4NeJEbPbGzSt2cKQpgDKb_R38am-5h7-jvtM9QxysS-G3-brNwpMog5MubRCcLlQI2ze92iTV6qLg7vspg08sel-SfhdeaKDhF0RfurSxXLQd-bIA";

    private KeyPair userKeys;

    @Autowired
    KeyPair serverKeys;

    @Autowired
    private KeyService keyService;

    @BeforeAll
    public void init()
    {
        super.initDatabase();
        User user = userService.createUser(TEST_USER_USERNAME, TEST_USER_PASSWORD);
        userKeys = keyService.generateKeyPairFor(user);
    }

    @Test
    void contextLoads()
    {
        assertNotNull(keyService);
        assertNotNull(mockMvc);
    }

    @Test
    @DisplayName("Test rejecting key fetching request without authorization")
    void onUnauthorizedRequest_rejectAndReturn401()
    {
        try{
            mockMvc.perform(MockMvcRequestBuilders.get(APIEndpoints.PUBLIC_KEY_RETRIEVAL_ENDPOINT)).andExpect(status().isUnauthorized());
        } catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Test rejecting key fetching request without authorization")
    void onUnauthorizedRequestWithInvalidJWT_rejectAndReturn401()
    {
        try{
            MultiValueMap<String, String> headers = getBasicHeaders();
            headers.put("Authorization", Collections.singletonList("Bearer " + RANDOM_JWT));
            mockMvc.perform(MockMvcRequestBuilders.get(APIEndpoints.PUBLIC_KEY_RETRIEVAL_ENDPOINT).headers(new HttpHeaders(headers))).andExpect(status().isUnauthorized());
        } catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Given correct access token be able to fetch the public key")
    void byFetchingAnAccessTokenAndIncludingItInTheRequest_getTheServersPublicKey()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            MvcResult result = printAndExpect(
                    mockMvc.perform(MockMvcRequestBuilders.get(APIEndpoints.PUBLIC_KEY_RETRIEVAL_ENDPOINT).headers(new HttpHeaders(headers))),
                    status().isOk()
            ).andReturn();
            RSAPublicKey publicKey = (RSAPublicKey)parseToObject(result, RsaJWK[].class)[0].toPublicKey();
            RSAPublicKey serverKey = (RSAPublicKey)serverKeys.getPublic();
            assertNotNull(publicKey);
            assertEquals(publicKey.getPublicExponent(), serverKey.getPublicExponent());
            assertEquals(publicKey.getModulus(), serverKey.getModulus());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("Given correct access token fetch the test user's public key")
    void byFetchingAnAccessTokenAndIncludingItInTheRequest_getAUsersPublicKey()
    {
        String authorizationHeaderValue = Base64.getEncoder().encodeToString((TEST_CLIENT_ID + ":" + TEST_CLIENT_SECRET).getBytes(StandardCharsets.UTF_8));
        MultiValueMap<String, String> headers = getBasicHeaders();
        headers.put("Authorization", Collections.singletonList("Basic " + authorizationHeaderValue));
        try{
            String accessToken = getTokenFromResult(
                    printAndExpect(
                            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT).headers(new HttpHeaders(headers))),
                            status().isOk()
                    ).andReturn()
            );
            headers.put("Authorization", Collections.singletonList("Bearer " + accessToken));
            MvcResult result = printAndExpect(
                    mockMvc.perform(get(APIEndpoints.PUBLIC_KEY_RETRIEVAL_ENDPOINT + "?username=" + TEST_USER_USERNAME).headers(new HttpHeaders(headers))),
                    status().isOk()
            ).andReturn();
            RSAPublicKey publicKey = (RSAPublicKey)parseToObject(result, RsaJWK[].class)[0].toPublicKey();
            RSAPublicKey userKey = (RSAPublicKey)userKeys.getPublic();
            assertNotNull(publicKey);
            assertEquals(publicKey.getPublicExponent(), userKey.getPublicExponent());
            assertEquals(publicKey.getModulus(), userKey.getModulus());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }
}
