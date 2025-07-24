package com.microservices.config;

import lombok.Data;
import lombok.experimental.FieldDefaults;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@FieldDefaults(level = lombok.AccessLevel.PRIVATE)
@ConfigurationProperties(prefix = "profile-filter.props")
public class ProfileFilterProperties {
    String decodeToken;
}
