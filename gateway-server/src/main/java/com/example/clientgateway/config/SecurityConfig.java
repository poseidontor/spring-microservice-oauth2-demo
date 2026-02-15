package com.example.clientgateway.config;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.convert.converter.Converter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;

import reactor.core.publisher.Mono;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Bean
    @Order(1)
    public SecurityWebFilterChain signupFilterChain(ServerHttpSecurity http) {
        http.securityMatcher(ServerWebExchangeMatchers.pathMatchers("/users/api/v1/signup"))
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges.anyExchange().permitAll());

        return http.build();
    }

    @Bean
    @Order(2)
    public SecurityWebFilterChain booksFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges -> exchanges.pathMatchers("/users/api/v1/get/**").hasRole("USER")
                        .anyExchange().authenticated())
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter())));

        return http.build();
    }

    @Bean
    @Order(3)
    public SecurityWebFilterChain defaultFilterChain(ServerHttpSecurity http) {
        http
                .authorizeExchange(exchanges -> exchanges.anyExchange().authenticated())
                .oauth2ResourceServer(oauth -> oauth.jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthConverter())));

        return http.build();
    }

    private Converter<Jwt, Mono<AbstractAuthenticationToken>> jwtAuthConverter() {
        return jwt -> {

            Object rolesClaim = jwt.getClaims().get("roles");

            List<String> roles;

            if (rolesClaim instanceof String roleStr) {
                roles = List.of(roleStr);
            } else if (rolesClaim instanceof List<?> list) {
                roles = list.stream().map(Object::toString).toList();
            } else {
                roles = List.of();
            }

            var authorities = roles.stream()

                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            return Mono.just(new JwtAuthenticationToken(jwt, authorities));
        };
    }

}
