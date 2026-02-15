package com.example.clientgateway.config;

import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RouteConfig {

        @Bean
        public RouteLocator customerServiceRoute(RouteLocatorBuilder builder) {
                return builder.routes()
                                .route("customer-service", r -> r.path("/users/**")
                                                .filters(f -> f.removeRequestHeader("Authorization"))
                                                .uri("lb://USERSERVICE"))

                                .build();
        }
}
