package com.urlshortener.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.urlshortener.auth.service.SocialProfile;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.function.Consumer;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.JwsHeader;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;

// Signs tokens with a local RSA key, so Google's real JWKS is never called.
class GoogleIdTokenVerifierTest {

    static final String CLIENT_ID = "client-123";

    static KeyPair googleKey;
    static KeyPair otherKey;

    @BeforeAll
    static void generateKeys() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        googleKey = generator.generateKeyPair();
        otherKey = generator.generateKeyPair();
    }

    final GoogleIdTokenVerifier verifier = new GoogleIdTokenVerifier(
        NimbusJwtDecoder.withPublicKey((RSAPublicKey) googleKey.getPublic()).build(),
        CLIENT_ID
    );

    @Test
    void acceptsValidToken() {
        assertThat(verifier.verify(token(claims -> {}))).isEqualTo(
            new SocialProfile("google", "google-sub-1", "a@example.com", true)
        );
    }

    @Test
    void acceptsIssuerWithoutScheme() {
        String idToken = token(claims -> claims.issuer("accounts.google.com"));

        assertThat(verifier.verify(idToken).providerUserId()).isEqualTo("google-sub-1");
    }

    @Test
    void rejectsWrongAudience() {
        assertInvalid(token(claims -> claims.audience(List.of("other-client"))));
    }

    @Test
    void rejectsWrongIssuer() {
        assertInvalid(token(claims -> claims.issuer("https://evil.example")));
    }

    @Test
    void rejectsExpiredToken() {
        Instant now = Instant.now();

        assertInvalid(
            token(claims ->
                claims
                    .issuedAt(now.minus(1, ChronoUnit.HOURS))
                    .expiresAt(now.minus(10, ChronoUnit.MINUTES))
            )
        );
    }

    @Test
    void rejectsTokenSignedByOtherKey() {
        assertInvalid(token(otherKey, claims -> {}));
    }

    @Test
    void rejectsMalformedToken() {
        assertInvalid("not-a-jwt");
    }

    @Test
    void missingEmailClaimGivesUnverifiedProfile() {
        String idToken = token(claims ->
            claims.claims(all -> {
                all.remove("email");
                all.remove("email_verified");
            })
        );

        SocialProfile profile = verifier.verify(idToken);

        assertThat(profile.email()).isNull();
        assertThat(profile.emailVerified()).isFalse();
    }

    @Test
    void jwksFailureIsNotReportedAsInvalidToken() {
        // Port 1 refuses connections, like Google's JWKS endpoint being down.
        GoogleIdTokenVerifier unreachable = new GoogleIdTokenVerifier(
            NimbusJwtDecoder.withJwkSetUri("http://127.0.0.1:1/certs").build(),
            CLIENT_ID
        );

        assertThatThrownBy(() -> unreachable.verify(token(claims -> {})))
            .isInstanceOf(JwtException.class)
            .isNotInstanceOf(BadJwtException.class);
    }

    private void assertInvalid(String idToken) {
        assertThatThrownBy(() -> verifier.verify(idToken)).isInstanceOfSatisfying(
            ApiException.class,
            e -> assertThat(e.getErrorType()).isEqualTo(ErrorType.GOOGLE_TOKEN_INVALID)
        );
    }

    private static String token(Consumer<JwtClaimsSet.Builder> customize) {
        return token(googleKey, customize);
    }

    private static String token(KeyPair key, Consumer<JwtClaimsSet.Builder> customize) {
        Instant now = Instant.now();
        JwtClaimsSet.Builder claims = JwtClaimsSet.builder()
            .issuer("https://accounts.google.com")
            .audience(List.of(CLIENT_ID))
            .subject("google-sub-1")
            .claim("email", "a@example.com")
            .claim("email_verified", true)
            .issuedAt(now)
            .expiresAt(now.plus(5, ChronoUnit.MINUTES));
        customize.accept(claims);

        RSAKey jwk = new RSAKey.Builder((RSAPublicKey) key.getPublic())
            .privateKey((RSAPrivateKey) key.getPrivate())
            .keyID("test-key")
            .build();
        NimbusJwtEncoder encoder = new NimbusJwtEncoder(new ImmutableJWKSet<>(new JWKSet(jwk)));

        return encoder
            .encode(
                JwtEncoderParameters.from(
                    JwsHeader.with(SignatureAlgorithm.RS256).keyId("test-key").build(),
                    claims.build()
                )
            )
            .getTokenValue();
    }
}
