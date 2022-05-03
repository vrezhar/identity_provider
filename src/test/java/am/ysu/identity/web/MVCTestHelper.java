package am.ysu.identity.web;

import am.ysu.identity.domain.tokens.ServiceAccessToken;
import am.ysu.identity.domain.tokens.AccessToken;
import am.ysu.identity.domain.Client;
import am.ysu.identity.service.ClientService;
import am.ysu.identity.service.user.UserService;
import am.ysu.identity.service.jwt.JWTTokenService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.ResultMatcher;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.UnsupportedEncodingException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.log;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;

/**
 * Helper methods for working with {@link org.springframework.test.web.servlet.MvcResult}, as well as operating with tokens
 */
public abstract class MVCTestHelper
{
    protected static final String TEST_CLIENT_ID = "aClient";
    protected static final String TEST_CLIENT_SECRET = "aSecret";
    protected static final String TEST_USER_USERNAME = "auser@example.com";
    protected static final String TEST_USER_PASSWORD = "password";

    protected MVCTestHelper(){}

    protected MockMvc mockMvc;
    protected ClientService clientService;
    protected UserService userService;
    protected JWTTokenService tokenService;

    protected void initDatabase()
    {
        Client client = new Client();
        client.setId(TEST_CLIENT_ID);
        client.setSecret(TEST_CLIENT_SECRET);
        clientService.save(client);
    }

    protected abstract void init();

    @Autowired
    public void setMockMvc(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    @Autowired
    public void setClientDetailsService(ClientService clientService) {
        this.clientService = clientService;
    }

    @Autowired
    public void setUserService(UserService userService) {
        this.userService = userService;
    }

    @Autowired
    public void setTokenService(JWTTokenService tokenService) {
        this.tokenService = tokenService;
    }

    protected ServiceAccessToken findServiceAccessToken(String clientId){
        return tokenService.findServiceAccessToken(clientService.findById(clientId).orElseThrow()).orElseThrow();
    }

    protected List<AccessToken> findUserAccessToken(String username){
        return tokenService.findUserAccessTokens(userService.findByUsername(username).orElseThrow());
    }

    public static String getTokenFromResult(MvcResult result) throws UnsupportedEncodingException, JsonProcessingException
    {
        String response = result.getResponse().getContentAsString();
        Object token = new ObjectMapper().readValue(response, Map.class).get("token");
        if(token != null){
            return (String)token;
        }
        return "";
    }

    public static String getKeyFromResult(MvcResult result) throws UnsupportedEncodingException, JsonProcessingException
    {
        String response = result.getResponse().getContentAsString();
        Object key = new ObjectMapper().readValue(response, Map.class).get("key");
        if(key != null){
            return (String)key;
        }
        return "";
    }

    public static <T> T parseToObject(MvcResult result, Class<T> objectType) throws UnsupportedEncodingException, JsonProcessingException
    {
        return new ObjectMapper().readValue(result.getResponse().getContentAsString(), objectType);
    }

    public static <T> T parseToObject(ResultActions result, Class<T> objectType) throws UnsupportedEncodingException, JsonProcessingException
    {
        return parseToObject(result.andReturn(), objectType);
    }

    public static String getContentAsString(ResultActions resultActions) throws UnsupportedEncodingException
    {
        return resultActions.andReturn().getResponse().getContentAsString();
    }

    public static <T> T logAndDoWithResult(ResultActions result, Function<MvcResult, T> operator) throws Exception {
        return operator.apply(result.andDo(log()).andReturn());
    }

    public static ResultActions logAndExpect(ResultActions result, ResultMatcher matcher) throws Exception {
        return result.andDo(log()).andExpect(matcher);
    }

    public static ResultActions printAndExpect(ResultActions result, ResultMatcher matcher) throws Exception{
        return result.andDo(print()).andExpect(matcher);
    }

    protected static MultiValueMap<String, String> getBasicHeaders()
    {
        MultiValueMap<String, String> headerMap = new LinkedMultiValueMap<>(3);
        headerMap.put("Accept", Collections.singletonList(MediaType.APPLICATION_JSON_VALUE));
        headerMap.put("Content-Type", Collections.singletonList(MediaType.APPLICATION_JSON_VALUE));
        return headerMap;
    }
}
