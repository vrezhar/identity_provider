package am.ysu.identity.web;

import am.ysu.identity.AuthenticationServerTestsConfiguration;
import am.ysu.identity.controllers.APIEndpoints;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@ContextConfiguration(classes = AuthenticationServerTestsConfiguration.class)
public class GenericControllerTests
{
    @Autowired
    private MockMvc mockMvc;

    @Test
    void contextLoads()
    {
        assertNotNull(mockMvc);
    }

    @Test
    @DisplayName("Without having an access token test the response to be forbidden")
    void withNoServiceAccessToken_denyAccessToUserEndpoints()
    {
        try{
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.USER_REGISTRATION_ENDPOINT)).andExpect(status().isUnauthorized());
            mockMvc.perform(MockMvcRequestBuilders.put(APIEndpoints.USER_UPDATE_ENDPOINT)).andExpect(status().isUnauthorized());
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.USER_CREDENTIALS_VERIFICATION_ENDPOINT)).andExpect(status().isUnauthorized());
            mockMvc.perform(MockMvcRequestBuilders.delete(APIEndpoints.USER_DELETION_ENDPOINT)).andExpect(status().isUnauthorized());
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.FORGOT_PASSWORD_ENDPOINT)).andExpect(status().isUnauthorized());
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.PASSWORD_RECOVERY_ENDPOINT)).andExpect(status().isUnauthorized());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("With no access token test the response of the key endpoint to be forbidden")
    void withNoServiceAccessToken_denyAccessToKeyEndpoint()
    {
        try{
            mockMvc.perform(MockMvcRequestBuilders.get(APIEndpoints.PUBLIC_KEY_RETRIEVAL_ENDPOINT)).andExpect(status().isUnauthorized());
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }

    @Test
    @DisplayName("With no client credentials test service token endpoint response to be unauthorized")
    void withNoClientCredentials_denyAccessToServiceAccessTokenEndpoints()
    {
        try{
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.SERVICE_ACCESS_TOKEN_ENDPOINT)).andExpect(status().isNotFound());
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.ID_TOKEN_ENDPOINTS[0])).andExpect(status().isUnauthorized()).andExpect(header().exists("WWW-Authenticate"));
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.USER_ACCESS_TOKEN_ENDPOINT)).andExpect(status().isUnauthorized()).andExpect(header().exists("WWW-Authenticate"));
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.TOKEN_VALIDATION_ENDPOINT)).andExpect(status().isUnauthorized()).andExpect(header().exists("WWW-Authenticate"));
            mockMvc.perform(MockMvcRequestBuilders.post(APIEndpoints.TOKEN_ENDPOINTS[0] + APIEndpoints.TOKEN_REVOCATION_ENDPOINT)).andExpect(status().isUnauthorized()).andExpect(header().exists("WWW-Authenticate"));
        }
        catch (Exception e){
            fail(e.getMessage());
        }
    }
}
