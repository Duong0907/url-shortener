package com.urlshortener.auth.controller;

import com.urlshortener.auth.service.AuthService;
import java.time.Duration;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

// The one place the refresh_token cookie is built, for password and social login alike.
@Component
@RequiredArgsConstructor
public class RefreshCookies {

    static final String NAME = "refresh_token";

    private final AuthService auth;

    @Value("${app.refresh-token.cookie-secure}")
    private final boolean secureCookie;

    public ResponseCookie issue(String token) {
        return build(token, auth.refreshTtl());
    }

    public ResponseCookie clear() {
        return build("", Duration.ZERO);
    }

    // Path limits the cookie to /api/auth, so it never rides along on link or
    // redirect requests.
    private ResponseCookie build(String value, Duration maxAge) {
        return ResponseCookie.from(NAME, value)
            .httpOnly(true)
            .secure(secureCookie)
            .sameSite("Strict")
            .path("/api/auth")
            .maxAge(maxAge)
            .build();
    }
}
