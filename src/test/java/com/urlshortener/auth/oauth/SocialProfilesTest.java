package com.urlshortener.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.urlshortener.auth.service.SocialProfile;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;

class SocialProfilesTest {

    @Test
    void mapsGoogleClaims() {
        OAuth2User user = user(
            Map.of("sub", "g1", "email", "a@example.com", "email_verified", true)
        );

        assertThat(SocialProfiles.from("google", user)).isEqualTo(
            new SocialProfile("google", "g1", "a@example.com", true)
        );
    }

    @Test
    void missingEmailVerifiedMeansFalse() {
        OAuth2User user = user(Map.of("sub", "g1", "email", "a@example.com"));

        assertThat(SocialProfiles.from("google", user).emailVerified()).isFalse();
    }

    @Test
    void emailVerifiedFalseStaysFalse() {
        OAuth2User user = user(
            Map.of("sub", "g1", "email", "a@example.com", "email_verified", false)
        );

        assertThat(SocialProfiles.from("google", user).emailVerified()).isFalse();
    }

    @Test
    void unknownProviderThrows() {
        OAuth2User user = user(Map.of("sub", "g1"));

        assertThatThrownBy(() -> SocialProfiles.from("myspace", user)).isInstanceOf(
            IllegalArgumentException.class
        );
    }

    private static OAuth2User user(Map<String, Object> attributes) {
        return new DefaultOAuth2User(List.of(), attributes, "sub");
    }
}
