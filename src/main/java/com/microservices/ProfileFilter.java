package com.microservices;

import com.microservices.dto.security.UserPrincipal;
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
import java.util.Arrays;
import java.util.List;

@Component
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class ProfileFilter implements WebFilter, Ordered {
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 100;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        HttpHeaders headers = exchange.getRequest().getHeaders();
        String userIdHeader = headers.getFirst("X-User-Id");

        // Nếu không có X-User-Id, bỏ qua filter
        if (!StringUtils.hasText(userIdHeader)) {
            return chain.filter(exchange);
        }

        // Lấy thông tin user từ header
        long userId = Long.parseLong(userIdHeader);
        String username = headers.getFirst("X-Username");
        String rolesHeader = headers.getFirst("X-Authorities-Roles");
        String permsHeader = headers.getFirst("X-Authorities-Permissions");
        boolean enabled = Boolean.parseBoolean(headers.getFirst("X-User-Enabled"));
        String firstName = headers.getFirst("X-User-FirstName");
        String lastName = headers.getFirst("X-User-LastName");
        String avatar = headers.getFirst("X-User-Avatar");
        String userCode = headers.getFirst("X-User-Code");
        boolean gender = Boolean.parseBoolean(headers.getFirst("X-User-Gender"));
        String email = headers.getFirst("X-User-Email");
        String phone = headers.getFirst("X-User-PhoneNumber");
        String address = headers.getFirst("X-User-Address");
        String userTz = headers.getFirst("X-User-UserTz");

        // Build danh sách authorities từ roles và permissions
        List<GrantedAuthority> authorities = new ArrayList<>();
        if (StringUtils.hasText(rolesHeader)) {
            Arrays.stream(rolesHeader.split(","))
                    .map(String::trim)
                    .filter(r -> !r.isEmpty())
                    .forEach(r -> authorities.add(new SimpleGrantedAuthority(r)));
        }
        if (StringUtils.hasText(permsHeader)) {
            Arrays.stream(permsHeader.split(","))
                    .map(String::trim)
                    .filter(p -> !p.isEmpty())
                    .forEach(p -> authorities.add(new SimpleGrantedAuthority(p)));
        }

        // Tạo principal
        UserPrincipal principal = UserPrincipal.builder()
                .id(userId)
                .userName(username)
                .firstName(firstName)
                .lastName(lastName)
                .avatar(avatar)
                .userCode(userCode)
                .email(email)
                .phoneNumber(phone)
                .address(address)
                .gender(gender)
                .isEnabled(enabled)
                .userTz(userTz)
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
    }
}

