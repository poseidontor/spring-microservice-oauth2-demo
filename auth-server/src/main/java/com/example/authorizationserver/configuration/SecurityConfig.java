package com.example.authorizationserver.configuration;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.StrictHttpFirewall;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;

import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;

import lombok.NonNull;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

        @NonNull
        private final Oauth2AccessTokenCustomizer oauth2AccessTokenCustomizer;

        @Bean
        @Order(1)
        public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
                OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer
                                .authorizationServer();

                http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
                                .with(authorizationServerConfigurer,
                                                authorizationServer -> authorizationServer
                                                                .oidc(Customizer.withDefaults()))
                                .authorizeHttpRequests((authorize) -> authorize.anyRequest().authenticated());

                http
                                .exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
                                                new LoginUrlAuthenticationEntryPoint("/login"),
                                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)))
                                .oauth2ResourceServer(resourceServer -> resourceServer.jwt(Customizer.withDefaults()));

                return http.build();
        }

        @Bean
        @Order(2)
        public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

                http
                                .formLogin(form -> form.usernameParameter("email")
                                                .passwordParameter("password")) // Enable form login
                                .authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());

                return http.build();
        }

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }

        @Bean
        public RegisteredClientRepository registeredClientRepository() {
                RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                                .clientId("gateway-client")
                                .clientSecret(passwordEncoder().encode("secret"))
                                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                                .redirectUri("http://localhost:8080/login/oauth2/code/gateway-client")
                                // .redirectUri("http://localhost:8080/*")
                                // .redirectUri("https://oauth.pstmn.io/v1/callback")
                                .postLogoutRedirectUri("http://localhost:8080/")
                                .scope(OidcScopes.OPENID)
                                .scope(OidcScopes.PROFILE)
                                .scope(OidcScopes.EMAIL)
                                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                                .build();
                return new InMemoryRegisteredClientRepository(oidcClient);
        }

        @Bean
        OAuth2TokenGenerator<OAuth2Token> tokenGenerator(JWKSource<SecurityContext> jwkSource) {
                JwtEncoder jwtEncoder = new NimbusJwtEncoder(jwkSource);
                JwtGenerator jwtAccessTokenGenerator = new JwtGenerator(jwtEncoder);
                jwtAccessTokenGenerator.setJwtCustomizer(oauth2AccessTokenCustomizer);

                return new DelegatingOAuth2TokenGenerator(jwtAccessTokenGenerator);
        }

        @Bean
        public HttpFirewall allowSemicolonHttpFirewall() {
                StrictHttpFirewall firewall = new StrictHttpFirewall();
                firewall.setAllowSemicolon(true);
                return firewall;
        }

        @Bean
        public WebSecurityCustomizer webSecurityCustomizer() {
                return web -> web.httpFirewall(allowSemicolonHttpFirewall());
        }
}
