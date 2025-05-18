package com.microservices.config;

import com.microservices.ProfileFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.web.server.WebFilter;

@AutoConfiguration
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.REACTIVE)
@ConditionalOnClass({WebFilter.class, ReactiveSecurityContextHolder.class})
public class ProfileFilterAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(ProfileFilter.class)
    public ProfileFilter profileFilter() {
        return new ProfileFilter();
    }
}
