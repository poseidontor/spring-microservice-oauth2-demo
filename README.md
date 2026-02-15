# Building a Spring Cloud Microservices Stack with OAuth2: Authorization Server, Gateway, Eureka, and a Resource Server

Short brief
---------------

This project demonstrates a compact Spring Cloud microservices stack that shows an understanding of Spring Authorization Server (OAuth2), Spring Cloud Gateway, Eureka service registry, and a Spring Cloud Resource Server. The sample services implemented are:

- `auth-server`: a Spring Authorization Server that issues JWT access tokens and customizes token claims.
- `eureka-server`: a service registry (Eureka).
- `gateway-server`: a Spring Cloud Gateway that routes traffic to downstream services and handles resource-server concerns.
- `user-service`: a resource server (and simple user-management service) that persists users and exposes secure REST endpoints.

This write-up describes the architecture, highlights key code snippets, and explains how OAuth2 and role-based authorization are wired in this project.

Project Architecture
---------------------

At a high level the system looks like this:

- Client -> `gateway-server` (OAuth2 client / resource-proxy)
- `gateway-server` -> `user-service` (load-balanced via Eureka)
- `auth-server` provides authorization (issuing JWT with custom `roles` claim)
- `eureka-server` provides service discovery

The gateway is registered as an OAuth2 client with the `auth-server`. The `auth-server` issues JWTs that include a `roles` claim (customized). The gateway strips the incoming `Authorization` header before forwarding to `user-service` (the resource server expects JWT validation, or the gateway can forward tokens depending on configuration).

Key Components and Code
------------------------

1) `auth-server` — Authorization Server and token customization

The `SecurityConfig` in the `auth-server` wires the authorization server endpoints and registers an OAuth2 client (the gateway). It also composes a JWT token generator and injects a customizer that places roles into the token claims.

Excerpt (important beans):

```java
@Bean
public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("gateway-client")
                    .clientSecret(passwordEncoder().encode("{JWT_SECRET"))
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("http://localhost:8080/login/oauth2/code/gateway-client")
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
```

The `Oauth2AccessTokenCustomizer` adds a `roles` claim to access tokens, which downstream services (gateway/resource server) can use to enforce role-based access.

```java
@Component
public class Oauth2AccessTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {
    @Override
    public void customize(JwtEncodingContext context) {
        if (OAuth2TokenType.ACCESS_TOKEN.equals(context.getTokenType())) {
            context.getClaims().claims(claims -> {
                Object principal = context.getPrincipal().getPrincipal();
                User user = (User) principal;

                Set<String> roles = AuthorityUtils.authorityListToSet(user.getAuthorities()).stream()
                        .collect(Collectors.collectingAndThen(Collectors.toSet(),
                                Collections::unmodifiableSet));
                claims.put("roles", roles);
            });
        }
    }
}
```

2) `gateway-server` — Routing and Resource Server configuration

The gateway defines a simple route for the user service and configures security for both public and protected endpoints. The route removes the `Authorization` header before forwarding so the downstream service can independently validate tokens if required (or the gateway can be a thin proxy).

Route config snippet:

```java
@Bean
public RouteLocator customerServiceRoute(RouteLocatorBuilder builder) {
    return builder.routes()
                    .route("customer-service", r -> r.path("/users/**")
                                    .filters(f -> f.removeRequestHeader("Authorization"))
                                    .uri("lb://USERSERVICE"))

                    .build();
}
```

Gateway security config highlights how JWT `roles` claim is converted into authorities for Spring Security in a reactive context.

```java
@Bean
@Order(2)
public SecurityWebFilterChain booksFilterChain(ServerHttpSecurity http) {
    http
        .authorizeExchange(exchanges -> exchanges.pathMatchers("/users/api/v1/get/**").hasRole("USER")
            .anyExchange().authenticated())
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
        var authorities = roles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
        return Mono.just(new JwtAuthenticationToken(jwt, authorities));
    };
}
```

3) `user-service` — Resource server and user management

`user-service` is a typical Spring Boot application exposing a small REST API for signup and retrieval. The `CustomerController` shows endpoints for signup and fetch-by-id.

```java
@RestController
@AllArgsConstructor
@RequestMapping("/api/v1")
public class CustomerController {

    private final ICustomerService customerService;

    @PostMapping("/signup")
    public ResponseEntity<SignupResponseDto> signup(@RequestBody SignupRequestDto signupRequest) {
        SignupResponseDto signupResponse = customerService.saveCustomer(signupRequest);
        return ResponseEntity.ok(signupResponse);
    }

    @GetMapping("/get/{id}")
    public ResponseEntity<UserDto> getCustomerById(@PathVariable Long id) {
        UserDto userDto = customerService.getCustomerById(id);
        return ResponseEntity.status(HttpStatus.OK).body(userDto);
    }
}
```

Domain model snippet (Customer entity):

```java
@Entity
@Table(name = "customers")
public class Customer extends BaseEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Email
    @Column(name = "email", nullable = false, unique = true)
    private String email;

    @Column(name = "first_name", nullable = false)
    private String firstName;

    @Column(name = "last_name", nullable = false)
    private String lastName;

    @Column(name = "pwd", nullable = false)
    private String pwd;

    @Enumerated(EnumType.STRING)
    @Column(name = "role", nullable = false)
    private RoleEnum role;
}
```

Service impl (signup + password encoding and duplicate check):

```java
public SignupResponseDto saveCustomer(SignupRequestDto signupRequest) {
    customerRepository.findByEmail(signupRequest.getEmail()).ifPresent((customer) -> {
        throw new EntityAlreadyExists("Customer", "email", customer.getEmail());
    });
    Customer customer = Customer.builder()
            .email(signupRequest.getEmail())
            .firstName(signupRequest.getFirstName())
            .lastName(signupRequest.getLastName())
            .pwd(passwordEncoder.encode(signupRequest.getPassword()))
            .role(RoleEnum.USER)
            .build();
    Customer savedCustomer = customerRepository.save(customer);
    return SignupResponseDto.builder()
            .email(savedCustomer.getEmail())
            .firstName(savedCustomer.getFirstName())
            .lastName(savedCustomer.getLastName())
            .build();
}
```

Configuration and properties
----------------------------

Important properties from `user-service`:

```properties
spring.application.name=userservice
server.port=8081
spring.datasource.url=jdbc:mysql://localhost:3306/ecommusers?useSSL=false
spring.datasource.username={DB_USER}
spring.datasource.password={DB_PASS}
spring.liquibase.enabled=true
spring.liquibase.change-log=classpath:db/changelog/db.changelog-master.yaml
spring.security.oauth2.resourceserver.jwt.issuer-uri=http://172.31.226.220:9000
server.servlet.context-path=/users
eureka.client.service-url.defaultZone=http://localhost:8761/eureka/
```

Notes on security: the `issuer-uri` should match the `auth-server`'s token issuer. The gateway and resource server both use the JWT `roles` claim for fine-grained authorization.

Putting it all together — OAuth2 flow
------------------------------------

1. The user hits the gateway which is configured as an OAuth2 client.
2. The gateway initiates the Authorization Code flow with the `auth-server`.
3. The `auth-server` authenticates the user and emits a JWT access token (with `roles` claim customized by `Oauth2AccessTokenCustomizer`).
4. The client (or gateway) uses the token to call protected endpoints on `user-service` (or the gateway forwards token as needed).
5. The resource server validates the JWT (via `issuer-uri` and JWKs) and converts the `roles` claim into authorities for role checks.

Why this architecture is useful
-------------------------------

- Separation of concerns: authorization is centralized in `auth-server`.
- Gateway provides a single entry point and can enforce cross-cutting concerns (CORS, rate-limiting, authentication mapping).
- Eureka enables runtime discovery to scale services without hard-coded endpoints.
- Including `roles` in JWT allows stateless, scalable role-based security.

Extending the project
----------------------

- Add refresh token rotation and revocation support.
- Persist clients instead of `InMemoryRegisteredClientRepository` (use JDBC or a management UI).
- Harden security for production: secure client secrets, use HTTPS, tune CORS, set cookie flags.
- Add more services and secure inter-service communication with mTLS if needed.

Conclusion
-----------

This project is a compact but complete demonstration of Spring Authorization Server, Spring Cloud Gateway, Eureka service discovery, and a resource server using JWT-based OAuth2 authentication and role-based authorization. The included customizations (like adding `roles` to JWT) show practical steps that help maintain stateless security in microservice deployments.