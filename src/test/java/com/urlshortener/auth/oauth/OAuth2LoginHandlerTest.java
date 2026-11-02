package com.urlshortener.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.when;

import com.urlshortener.auth.controller.RefreshCookies;
import com.urlshortener.auth.service.AuthService;
import com.urlshortener.auth.service.AuthService.Tokens;
import com.urlshortener.auth.service.SocialProfile;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

@ExtendWith(MockitoExtension.class)
class OAuth2LoginHandlerTest {

    static final String UI = "http://ui.test";
    static final SocialProfile PROFILE = new SocialProfile(
        "google",
        "g1",
        "alice@example.com",
        true
    );

    @Mock
    AuthService auth;

    OAuth2LoginHandler handler;

    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();

    @BeforeEach
    void setUp() {
        lenient().when(auth.refreshTtl()).thenReturn(Duration.ofDays(30));
        handler = new OAuth2LoginHandler(auth, new RefreshCookies(auth, true), UI);
    }

    @Test
    void successSetsRefreshCookieAndRedirectsToCallback() throws Exception {
        when(auth.loginWithProvider(PROFILE)).thenReturn(new Tokens("access-jwt", 900, "rt"));

        handler.onAuthenticationSuccess(request, response, googleLogin());

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo(UI + "/auth/callback");
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE))
            .startsWith("refresh_token=rt")
            .contains("Path=/api/auth")
            .contains("SameSite=Strict")
            .contains("HttpOnly");
        // The access token is fetched later via /api/auth/refresh, never sent in the redirect.
        for (String name : response.getHeaderNames()) {
            assertThat(response.getHeaders(name)).noneMatch(v -> v.contains("access-jwt"));
        }
    }

    @Test
    void successWithUnverifiedEmailRedirectsWithError() throws Exception {
        when(auth.loginWithProvider(any())).thenThrow(
            new ApiException(ErrorType.EMAIL_NOT_VERIFIED, "no verified email")
        );

        handler.onAuthenticationSuccess(request, response, googleLogin());

        assertThat(response.getRedirectedUrl()).isEqualTo(
            UI + "/auth/callback?error=email_not_verified"
        );
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void successWithUnexpectedErrorRedirectsWithOauthFailed() throws Exception {
        // E.g. a DB outage mid-login: the user is on a top-level navigation and must land
        // on the UI, not on a raw 500 page.
        when(auth.loginWithProvider(any())).thenThrow(
            new ApiException(ErrorType.INTERNAL_ERROR, "boom")
        );

        handler.onAuthenticationSuccess(request, response, googleLogin());

        assertThat(response.getRedirectedUrl()).isEqualTo(UI + "/auth/callback?error=oauth_failed");
        assertThat(response.getHeader(HttpHeaders.SET_COOKIE)).isNull();
    }

    @Test
    void successWithUnmappedProviderRedirectsWithOauthFailed() throws Exception {
        OAuth2AuthenticationToken unmapped = new OAuth2AuthenticationToken(
            new DefaultOAuth2User(List.of(), Map.of("sub", "x1"), "sub"),
            List.of(),
            "myspace"
        );

        handler.onAuthenticationSuccess(request, response, unmapped);

        assertThat(response.getRedirectedUrl()).isEqualTo(UI + "/auth/callback?error=oauth_failed");
    }

    @Test
    void failureAccessDeniedRedirectsWithAccessDenied() throws Exception {
        handler.onAuthenticationFailure(
            request,
            response,
            new OAuth2AuthenticationException(new OAuth2Error("access_denied"))
        );

        assertThat(response.getStatus()).isEqualTo(302);
        assertThat(response.getRedirectedUrl()).isEqualTo(
            UI + "/auth/callback?error=access_denied"
        );
    }

    @Test
    void failureOtherRedirectsWithOauthFailedAndHidesDetail() throws Exception {
        handler.onAuthenticationFailure(
            request,
            response,
            new OAuth2AuthenticationException(
                new OAuth2Error("invalid_state_parameter", "secret detail", null)
            )
        );

        assertThat(response.getRedirectedUrl()).isEqualTo(UI + "/auth/callback?error=oauth_failed");
    }

    private static OAuth2AuthenticationToken googleLogin() {
        DefaultOAuth2User user = new DefaultOAuth2User(
            List.of(),
            Map.of("sub", "g1", "email", "alice@example.com", "email_verified", true),
            "sub"
        );

        return new OAuth2AuthenticationToken(user, List.of(), "google");
    }
}
