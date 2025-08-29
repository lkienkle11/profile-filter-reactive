package com.microservices;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.microservices.config.ProfileFilterProperties;
import com.microservices.dto.security.UserInfo;
import com.microservices.dto.security.UserPrincipal;
import com.microservices.security.JwtTokenProvider;
import io.jsonwebtoken.Claims;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ProfileFilter implements WebFilter, Ordered {
    private static final ObjectMapper objectMapper;

    static {
        objectMapper = new ObjectMapper();
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
//        objectMapper.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_EMPTY);
    }

    ProfileFilterProperties props;

    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();

        String nextToken = headers.getFirst("X-Next-Token");
        String decodeToken = props.getDecodeToken();

        if (!StringUtils.hasText(nextToken) || !StringUtils.hasText(decodeToken)) {
            // Nếu không có X-Next-Token hoặc X-Decode-Key, bỏ qua filter
            return chain.filter(exchange);
        }

        JwtTokenProvider jwtTokenProvider = new JwtTokenProvider(decodeToken);

        try {
            Claims claims = jwtTokenProvider.parseClaims(nextToken);
            if (!"next_token".equals(claims.get("type"))) {
                return chain.filter(exchange);
            }
            String userInfoObj = (String) claims.get("user");
            if (!StringUtils.hasText(userInfoObj)) {
                return chain.filter(exchange);
            }
            UserInfo userInfo = objectMapper.readValue(userInfoObj, UserInfo.class);
            if (userInfo == null) {
                return chain.filter(exchange);
            }
            List<GrantedAuthority> authorities = new ArrayList<>();
            if (userInfo.getRoles() != null) {
                userInfo.getRoles()
                        .stream()
                        .filter(StringUtils::hasText)
                        .forEach(role -> authorities.add(new SimpleGrantedAuthority(role)));
            }
            if (userInfo.getPermissions() != null) {
                userInfo.getPermissions()
                        .stream()
                        .filter(StringUtils::hasText)
                        .forEach(permission -> authorities.add(new SimpleGrantedAuthority(permission)));
            }
            // Tạo principal
            UserPrincipal principal = UserPrincipal.builder()
                    .id(userInfo.getId())
                    .userName(userInfo.getUserName())
                    .firstName(userInfo.getFirstName())
                    .lastName(userInfo.getLastName())
                    .avatar(userInfo.getAvatar())
                    .userCode(userInfo.getUserCode())
                    .email(userInfo.getEmail())
                    .phoneNumber(userInfo.getPhoneNumber())
                    .address(userInfo.getAddress())
                    .gender(userInfo.getGender())
                    .isEnabled(userInfo.getIsEnabled())
                    .userTz(userInfo.getUserTz())
                    .authorities(authorities)
                    .build();
            // Tạo authentication token
            UsernamePasswordAuthenticationToken auth =
                    new UsernamePasswordAuthenticationToken(principal, null, authorities);
            ServerHttpRequest mutatedReq = exchange.getRequest().mutate()
                    .header("X-Token-ID", headers.getFirst("X-Token-ID"))
                    .build();
            ServerWebExchange mutatedExchange = exchange.mutate()
                    .request(mutatedReq)
                    .build();

            // Đặt vào reactive security context và forward request
            return chain.filter(mutatedExchange)
                    .contextWrite(ReactiveSecurityContextHolder.withAuthentication(auth));
        } catch (Exception e) {
            // Nếu có lỗi khi giải mã token, bỏ qua filter
            return chain.filter(exchange);
        }
    }
}

