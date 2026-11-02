package com.urlshortener.auth.oauth;

import com.urlshortener.auth.service.SocialProfile;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import org.springframework.security.oauth2.core.user.OAuth2User;

// Maps each provider's user info to the common shape. A new provider adds a case here.
@NoArgsConstructor(access = AccessLevel.PRIVATE)
final class SocialProfiles {

    static SocialProfile from(String registrationId, OAuth2User principal) {
        return switch (registrationId) {
            case "google" -> new SocialProfile(
                registrationId,
                principal.getAttribute("sub"),
                principal.getAttribute("email"),
                Boolean.TRUE.equals(principal.getAttribute("email_verified"))
            );
            default -> throw new IllegalArgumentException(
                "No profile mapping for provider " + registrationId
            );
        };
    }
}
