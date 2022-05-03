package am.ysu.identity.security;

import am.ysu.identity.security.filters.basic.ClientCredentialsProcessorFilter;
import am.ysu.identity.security.filters.jwt.GenericTokenVerifierFilter;
import am.ysu.identity.security.filters.jwt.ServiceAccessTokenProcessorFilter;
import am.ysu.identity.security.filters.jwt.UserTokenProcessorFilter;
import am.ysu.identity.util.errors.handler.RestAuthenticationEntryPoint;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

/**
 * Main web security configuration
 */
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final ClientCredentialsProcessorFilter clientCredentialsProcessorFilter;
    private final ServiceAccessTokenProcessorFilter serviceAccessTokenProcessorFilter;
    private final UserTokenProcessorFilter userTokenProcessorFilter;
    private final GenericTokenVerifierFilter tokenVerifierFilter;

    public WebSecurityConfiguration(final ClientCredentialsProcessorFilter clientCredentialsProcessorFilter,
                                    final ServiceAccessTokenProcessorFilter serviceAccessTokenProcessorFilter,
                                    final UserTokenProcessorFilter userTokenProcessorFilter,
                                    final GenericTokenVerifierFilter tokenVerifierFilter
    ) {
        this.clientCredentialsProcessorFilter = clientCredentialsProcessorFilter;
        this.serviceAccessTokenProcessorFilter = serviceAccessTokenProcessorFilter;
        this.userTokenProcessorFilter = userTokenProcessorFilter;
        this.tokenVerifierFilter = tokenVerifierFilter;
    }

    /**
     * Disables spring security's CSRF checks, the default login page and default basic http authorization, sets session creation policy to stateless
     * @see WebSecurityConfigurerAdapter#configure(HttpSecurity) for more details
     */
    @Override
    public void configure(HttpSecurity security) throws Exception {
        security
                .httpBasic()
                    .disable()
                .formLogin()
                    .disable()
                .csrf()
                    .disable()
                .cors()
                    .disable()
                .exceptionHandling()
                    .authenticationEntryPoint(new RestAuthenticationEntryPoint())
                .and()
                    .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS);

    }

    /**
     * Register the {@link ClientCredentialsProcessorFilter} for url-s it should apply to(overrides the default filter bean definition)
     * @return The filter bean
     */
    @Bean
    public FilterRegistrationBean<ClientCredentialsProcessorFilter> clientCredentialsFilter() {
        FilterRegistrationBean<ClientCredentialsProcessorFilter> registrationBean = new FilterRegistrationBean<>(clientCredentialsProcessorFilter);
        registrationBean.addUrlPatterns("/token/service/*");
        return registrationBean;
    }

    /**
     * Register the {@link ServiceAccessTokenProcessorFilter} for url-s it should apply to
     * @return The filter bean
     */
    @Bean
    public FilterRegistrationBean<ServiceAccessTokenProcessorFilter> serviceAccessTokenFilter() {
        FilterRegistrationBean<ServiceAccessTokenProcessorFilter> registrationBean = new FilterRegistrationBean<>(serviceAccessTokenProcessorFilter);
        registrationBean.addUrlPatterns("/login/*", "/sign/*", "/key/*", "/user/*", "/token/refresh/*", "/token/revoke/*");
        return registrationBean;
    }

    /**
     * Register the {@link UserTokenProcessorFilter} for url-s it should apply to
     * @return The filter bean
     */
    @Bean
    public FilterRegistrationBean<UserTokenProcessorFilter> userTokenFilter() {
        FilterRegistrationBean<UserTokenProcessorFilter> registrationBean = new FilterRegistrationBean<>(userTokenProcessorFilter);
        registrationBean.addUrlPatterns("/token/user/*");
        return registrationBean;
    }

    @Bean
    public FilterRegistrationBean<GenericTokenVerifierFilter> tokenVerifierFilter() {
        FilterRegistrationBean<GenericTokenVerifierFilter> registrationBean = new FilterRegistrationBean<>(tokenVerifierFilter);
        registrationBean.addUrlPatterns("/token/check/*");
        return registrationBean;
    }
}
