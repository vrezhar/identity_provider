package am.ysu.identity.security.conf;

import am.ysu.identity.util.jwt.provider.DatabaseKeyProvider;
import am.ysu.identity.util.jwt.provider.FileBasedKeyProvider;
import am.ysu.identity.util.jwt.provider.InMemoryKeyProvider;
import am.ysu.identity.util.jwt.KeyProvider;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;

@Configuration
public class ProviderConfiguration {

    @Bean("keyProvider")
    @ConditionalOnMissingBean({DatabaseKeyProvider.class, FileBasedKeyProvider.class})
    @Order(Ordered.LOWEST_PRECEDENCE)
    KeyProvider keyProvider() {
        return new InMemoryKeyProvider();
    }
}
