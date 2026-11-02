package com.urlshortener.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;

import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import tools.jackson.databind.json.JsonMapper;

// The in-flight OAuth request lives in the browser, so everything read back is untrusted.
class CookieAuthorizationRequestRepositoryTest {

    static final SecretKey KEY = key("test-only-secret-that-is-at-least-32-bytes");
    static final JsonMapper JSON = JsonMapper.builder().build();

    CookieAuthorizationRequestRepository repository = new CookieAuthorizationRequestRepository(
        KEY,
        JSON,
        true
    );

    @Test
    void saveSetsLaxHttpOnlyCookieScopedToOauthPaths() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        repository.saveAuthorizationRequest(sample(), new MockHttpServletRequest(), response);

        assertThat(setCookie(response))
            .startsWith("oauth2_auth_request=")
            .contains("Path=/api/auth/oauth2")
            .contains("Max-Age=180")
            .contains("HttpOnly")
            .contains("Secure")
            .contains("SameSite=Lax");
    }

    @Test
    void saveOmitsSecureWhenConfiguredOff() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        new CookieAuthorizationRequestRepository(KEY, JSON, false).saveAuthorizationRequest(
            sample(),
            new MockHttpServletRequest(),
            response
        );

        assertThat(setCookie(response)).doesNotContain("Secure");
    }

    @Test
    void roundTripRestoresEveryField() {
        OAuth2AuthorizationRequest original = sample();

        OAuth2AuthorizationRequest loaded = repository.loadAuthorizationRequest(
            callback("s1", savedValue(original))
        );

        assertThat(loaded).isNotNull();
        assertThat(loaded.getAuthorizationUri()).isEqualTo(original.getAuthorizationUri());
        assertThat(loaded.getClientId()).isEqualTo(original.getClientId());
        assertThat(loaded.getRedirectUri()).isEqualTo(original.getRedirectUri());
        assertThat(loaded.getScopes()).isEqualTo(original.getScopes());
        assertThat(loaded.getState()).isEqualTo("s1");
        assertThat(loaded.getAdditionalParameters()).isEqualTo(original.getAdditionalParameters());
        assertThat(loaded.getAttributes()).isEqualTo(original.getAttributes());
        assertThat(loaded.getAuthorizationRequestUri()).isEqualTo(
            original.getAuthorizationRequestUri()
        );
    }

    @Test
    void loadRejectsStateMismatch() {
        assertThat(
            repository.loadAuthorizationRequest(callback("other", savedValue(sample())))
        ).isNull();
    }

    @Test
    void loadRejectsMissingStateParameter() {
        assertThat(
            repository.loadAuthorizationRequest(callback(null, savedValue(sample())))
        ).isNull();
    }

    @Test
    void loadRejectsMissingCookie() {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setParameter("state", "s1");

        assertThat(repository.loadAuthorizationRequest(request)).isNull();
    }

    @Test
    void loadRejectsTamperedPayload() {
        String value = savedValue(sample());
        char flipped = value.charAt(5) == 'A' ? 'B' : 'A';
        String tampered = value.substring(0, 5) + flipped + value.substring(6);

        assertThat(repository.loadAuthorizationRequest(callback("s1", tampered))).isNull();
    }

    @ParameterizedTest
    @ValueSource(strings = { "", "x", "a.b", "...", "bm90LWpzb24.c2ln", "%%%.%%%" })
    void loadRejectsGarbage(String value) {
        assertThat(repository.loadAuthorizationRequest(callback("s1", value))).isNull();
    }

    @Test
    void loadRejectsValidSignatureOverNonJson() {
        String payload = java.util.Base64.getUrlEncoder()
            .withoutPadding()
            .encodeToString("not json".getBytes(StandardCharsets.UTF_8));
        String signed = payload + "." + repository.sign(payload);

        assertThat(repository.loadAuthorizationRequest(callback("s1", signed))).isNull();
    }

    @Test
    void loadRejectsCookieSignedWithOtherKey() {
        String foreign = savedValue(
            new CookieAuthorizationRequestRepository(
                key("another-secret-that-is-also-32-bytes-long"),
                JSON,
                true
            ),
            sample()
        );

        assertThat(repository.loadAuthorizationRequest(callback("s1", foreign))).isNull();
    }

    @Test
    void removeExpiresCookieAndReturnsRequest() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        OAuth2AuthorizationRequest removed = repository.removeAuthorizationRequest(
            callback("s1", savedValue(sample())),
            response
        );

        assertThat(removed).isNotNull();
        assertThat(removed.getState()).isEqualTo("s1");
        assertThat(setCookie(response)).contains("Max-Age=0").contains("Path=/api/auth/oauth2");
    }

    @Test
    void removeExpiresCookieEvenWhenNothingValidWasStored() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        assertThat(repository.removeAuthorizationRequest(callback("s1", "x"), response)).isNull();
        assertThat(setCookie(response)).contains("Max-Age=0");
    }

    @Test
    void saveNullExpiresCookie() {
        MockHttpServletResponse response = new MockHttpServletResponse();

        repository.saveAuthorizationRequest(null, new MockHttpServletRequest(), response);

        assertThat(setCookie(response)).startsWith("oauth2_auth_request=;").contains("Max-Age=0");
    }

    private String savedValue(OAuth2AuthorizationRequest request) {
        return savedValue(repository, request);
    }

    private static String savedValue(
        CookieAuthorizationRequestRepository repo,
        OAuth2AuthorizationRequest request
    ) {
        MockHttpServletResponse response = new MockHttpServletResponse();
        repo.saveAuthorizationRequest(request, new MockHttpServletRequest(), response);
        String header = setCookie(response);

        return header.substring(header.indexOf('=') + 1, header.indexOf(';'));
    }

    private static MockHttpServletRequest callback(String state, String cookieValue) {
        MockHttpServletRequest request = new MockHttpServletRequest(
            "GET",
            "/api/auth/oauth2/code/google"
        );
        if (state != null) {
            request.setParameter("state", state);
        }
        request.setCookies(new Cookie(CookieAuthorizationRequestRepository.COOKIE, cookieValue));

        return request;
    }

    private static String setCookie(MockHttpServletResponse response) {
        return response.getHeader(HttpHeaders.SET_COOKIE);
    }

    private static OAuth2AuthorizationRequest sample() {
        return OAuth2AuthorizationRequest.authorizationCode()
            .authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
            .clientId("client-1")
            .redirectUri("http://localhost:3000/api/auth/oauth2/code/google")
            .scopes(Set.of("openid", "email"))
            .state("s1")
            .additionalParameters(
                Map.of("code_challenge", "ch", "code_challenge_method", "S256", "nonce", "nh")
            )
            .attributes(Map.of("registration_id", "google", "nonce", "n1", "code_verifier", "v1"))
            .authorizationRequestUri("https://accounts.google.com/o/oauth2/v2/auth?state=s1")
            .build();
    }

    private static SecretKey key(String secret) {
        return new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256");
    }
}
