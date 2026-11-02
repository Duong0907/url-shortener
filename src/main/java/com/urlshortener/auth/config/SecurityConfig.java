package com.urlshortener.auth.config;

import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.urlshortener.auth.oauth.CookieAuthorizationRequestRepository;
import com.urlshortener.auth.oauth.OAuth2LoginHandler;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.resource.web.BearerTokenAuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import tools.jackson.databind.json.JsonMapper;

@Configuration
public class SecurityConfig {

    static final String OAUTH2_AUTHORIZATION_BASE = "/api/auth/oauth2/authorization";
    static final String OAUTH2_CALLBACK_BASE = "/api/auth/oauth2/code/*";

    private final SecretKey jwtKey;

    public SecurityConfig(@Value("${app.jwt.secret}") String secret) {
        byte[] bytes = secret.getBytes(StandardCharsets.UTF_8);
        if (bytes.length < 32) {
            throw new IllegalStateException("JWT_SECRET must be at least 32 bytes");
        }

        this.jwtKey = new SecretKeySpec(bytes, "HmacSHA256");
    }

    @Bean
    SecurityFilterChain securityFilterChain(
        HttpSecurity http,
        CookieAuthorizationRequestRepository authorizationRequests,
        OAuth2LoginHandler oauth2LoginHandler
    ) throws Exception {
        http.csrf(csrf -> csrf.disable())
            .cors(Customizer.withDefaults())
            .sessionManagement(session ->
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            .authorizeHttpRequests(auth ->
                auth
                    .requestMatchers(HttpMethod.POST, "/api/links")
                    .permitAll()
                    .requestMatchers("/api/auth/**")
                    .permitAll()
                    .requestMatchers("/api/**")
                    .authenticated()
                    .anyRequest()
                    .permitAll()
            )
            .oauth2ResourceServer(oauth -> oauth.jwt(Customizer.withDefaults()))
            // Provider login (Google, ...) under /api/auth/oauth2/**. The handler issues our own
            // tokens, so the provider's tokens are never stored.
            .oauth2Login(oauth ->
                oauth
                    // Any explicit login page turns off Spring's generated /login page.
                    .loginPage(OAUTH2_AUTHORIZATION_BASE)
                    .authorizationEndpoint(endpoint ->
                        endpoint
                            .baseUri(OAUTH2_AUTHORIZATION_BASE)
                            .authorizationRequestRepository(authorizationRequests)
                    )
                    .redirectionEndpoint(endpoint -> endpoint.baseUri(OAUTH2_CALLBACK_BASE))
                    .authorizedClientRepository(new DiscardingAuthorizedClientRepository())
                    .successHandler(oauth2LoginHandler)
                    .failureHandler(oauth2LoginHandler)
            )
            // oauth2Login would otherwise redirect unauthenticated browser requests to Google.
            // API callers must keep getting a 401.
            .exceptionHandling(exceptions ->
                exceptions.authenticationEntryPoint(new BearerTokenAuthenticationEntryPoint())
            );

        return http.build();
    }

    @Bean
    CookieAuthorizationRequestRepository authorizationRequestRepository(
        JsonMapper json,
        @Value("${app.refresh-token.cookie-secure}") boolean secureCookie
    ) {
        return new CookieAuthorizationRequestRepository(jwtKey, json, secureCookie);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    JwtEncoder jwtEncoder() {
        return new NimbusJwtEncoder(new ImmutableSecret<>(jwtKey));
    }

    @Bean
    JwtDecoder jwtDecoder() {
        return NimbusJwtDecoder.withSecretKey(jwtKey).macAlgorithm(MacAlgorithm.HS256).build();
    }

    @Bean
    CorsConfigurationSource corsConfigurationSource(
        @Value("${app.cors.allowed-origins}") List<String> origins
    ) {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedOrigins(origins);
        config.setAllowedMethods(List.of("GET", "POST", "PATCH", "DELETE"));
        config.setAllowedHeaders(List.of("Authorization", "Content-Type"));
        config.setAllowCredentials(true);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/api/**", config);

        return source;
    }

    // The default repository keeps provider tokens in the session or in memory. We only need
    // the user's identity once, so nothing is kept.
    private static final class DiscardingAuthorizedClientRepository
        implements OAuth2AuthorizedClientRepository
    {

        @Override
        public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(
            String clientRegistrationId,
            Authentication principal,
            HttpServletRequest request
        ) {
            return null;
        }

        @Override
        public void saveAuthorizedClient(
            OAuth2AuthorizedClient authorizedClient,
            Authentication principal,
            HttpServletRequest request,
            HttpServletResponse response
        ) {}

        @Override
        public void removeAuthorizedClient(
            String clientRegistrationId,
            Authentication principal,
            HttpServletRequest request,
            HttpServletResponse response
        ) {}
    }
}
