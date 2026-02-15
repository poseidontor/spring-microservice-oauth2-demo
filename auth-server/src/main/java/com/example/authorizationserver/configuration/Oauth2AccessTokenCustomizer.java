package com.example.authorizationserver.configuration;

import java.util.Collections;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

@Component

public class Oauth2AccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {

        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims(claims -> {
                Object principal = context.getPrincipal().getPrincipal();
                User user = (User) principal;

                Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities()).stream()
                        // .map(role -> role.replace("^ROLE_", ""))
                        .collect(Collectors.collectingAndThen(Collectors.toSet(),
                                Collections::unmodifiableSet));
                claims.put("roles", roles);
            });
        }

    }

}

/*
 * Add role base authorization.
 */