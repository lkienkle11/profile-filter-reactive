package com.microservices.config;

import com.microservices.ProfileFilter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConditionalOnWebApplication
public class ProfileFilterAutoConfiguration {
    @Bean
    public ProfileFilter profileFilter() {
        return new ProfileFilter();
    }
}
