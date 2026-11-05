package com.urlshortener.auth.oauth;

import com.urlshortener.auth.service.SocialProfile;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import java.util.List;
import java.util.Set;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtClaimValidator;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.stereotype.Component;

// Checks the ID token Google One Tap hands the UI. The decoder is a field, not a bean:
// a second JwtDecoder bean would clash with the one that validates our own access tokens.
@Component
public class GoogleIdTokenVerifier {

    static final String JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
    static final Set<String> ISSUERS = Set.of("accounts.google.com", "https://accounts.google.com");

    private final NimbusJwtDecoder decoder;

    @Autowired
    public GoogleIdTokenVerifier(
        @Value("${spring.security.oauth2.client.registration.google.client-id}") String clientId
    ) {
        this(NimbusJwtDecoder.withJwkSetUri(JWKS_URI).build(), clientId);
    }

    GoogleIdTokenVerifier(NimbusJwtDecoder decoder, String clientId) {
        // Without the audience check, a token Google issued to another app would log in here.
        decoder.setJwtValidator(
            JwtValidators.createDefaultWithValidators(
                List.of(
                    new JwtClaimValidator<String>(JwtClaimNames.ISS, ISSUERS::contains),
                    new JwtClaimValidator<List<String>>(
                        JwtClaimNames.AUD,
                        aud -> aud != null && aud.contains(clientId)
                    )
                )
            )
        );
        this.decoder = decoder;
    }

    // Only a bad token is the caller's fault. Other JwtExceptions (e.g. Google's JWKS is
    // unreachable) propagate as a 500.
    public SocialProfile verify(String idToken) {
        Jwt jwt;
        try {
            jwt = decoder.decode(idToken);
        } catch (BadJwtException e) {
            throw new ApiException(ErrorType.GOOGLE_TOKEN_INVALID, e.getMessage());
        }

        return new SocialProfile(
            "google",
            jwt.getSubject(),
            jwt.getClaimAsString("email"),
            Boolean.TRUE.equals(jwt.getClaimAsBoolean("email_verified"))
        );
    }
}
