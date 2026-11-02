package com.urlshortener.auth.oauth;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import tools.jackson.databind.json.JsonMapper;

// Keeps the in-flight OAuth request (state, PKCE verifier, nonce) in a signed cookie,
// because the API has no HTTP session. The cookie is plain JSON plus an HMAC, never a
// Java-serialized object, so a forged cookie can at most be rejected.
@RequiredArgsConstructor
public class CookieAuthorizationRequestRepository
    implements AuthorizationRequestRepository<OAuth2AuthorizationRequest>
{

    public static final String COOKIE = "oauth2_auth_request";

    static final String PATH = "/api/auth/oauth2";
    static final Duration MAX_AGE = Duration.ofSeconds(180);

    private static final Base64.Encoder ENCODER = Base64.getUrlEncoder().withoutPadding();
    private static final Base64.Decoder DECODER = Base64.getUrlDecoder();

    private final SecretKey key;
    private final JsonMapper json;
    private final boolean secureCookie;

    // Only the fields Spring needs to finish the flow. Attribute values are all strings.
    private record Stored(
        String authorizationUri,
        String clientId,
        String redirectUri,
        Set<String> scopes,
        String state,
        Map<String, Object> additionalParameters,
        Map<String, Object> attributes,
        String authorizationRequestUri
    ) {}

    @Override
    public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
        String state = request.getParameter(OAuth2ParameterNames.STATE);
        OAuth2AuthorizationRequest stored = read(request);
        if (stored == null || state == null || !state.equals(stored.getState())) {
            return null;
        }

        return stored;
    }

    @Override
    public void saveAuthorizationRequest(
        OAuth2AuthorizationRequest authorizationRequest,
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        if (authorizationRequest == null) {
            expire(response);
            return;
        }

        Stored stored = new Stored(
            authorizationRequest.getAuthorizationUri(),
            authorizationRequest.getClientId(),
            authorizationRequest.getRedirectUri(),
            authorizationRequest.getScopes(),
            authorizationRequest.getState(),
            authorizationRequest.getAdditionalParameters(),
            authorizationRequest.getAttributes(),
            authorizationRequest.getAuthorizationRequestUri()
        );
        String payload = ENCODER.encodeToString(json.writeValueAsBytes(stored));

        write(response, payload + "." + sign(payload), MAX_AGE);
    }

    // Always expires the cookie, so a callback URL can be used only once.
    @Override
    public OAuth2AuthorizationRequest removeAuthorizationRequest(
        HttpServletRequest request,
        HttpServletResponse response
    ) {
        OAuth2AuthorizationRequest loaded = loadAuthorizationRequest(request);
        expire(response);

        return loaded;
    }

    String sign(String payload) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);

            return ENCODER.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8)));
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    // Constant-time compare, so response timing does not reveal how much of a forged
    // signature was right.
    private boolean verify(String payload, String signature) {
        byte[] expected = sign(payload).getBytes(StandardCharsets.UTF_8);
        byte[] actual = signature.getBytes(StandardCharsets.UTF_8);

        return MessageDigest.isEqual(expected, actual);
    }

    // Returns null for anything missing, unsigned, tampered or unparseable.
    private OAuth2AuthorizationRequest read(HttpServletRequest request) {
        String value = cookieValue(request);
        int dot = value == null ? -1 : value.indexOf('.');
        if (dot <= 0) {
            return null;
        }

        String payload = value.substring(0, dot);
        if (!verify(payload, value.substring(dot + 1))) {
            return null;
        }

        try {
            Stored stored = json.readValue(DECODER.decode(payload), Stored.class);

            return OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri(stored.authorizationUri())
                .clientId(stored.clientId())
                .redirectUri(stored.redirectUri())
                .scopes(stored.scopes())
                .state(stored.state())
                .additionalParameters(stored.additionalParameters())
                .attributes(stored.attributes())
                .authorizationRequestUri(stored.authorizationRequestUri())
                .build();
        } catch (RuntimeException e) {
            // A correct signature over bad content means a bug or a key leak, not user input.
            return null;
        }
    }

    private static String cookieValue(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }
        for (Cookie cookie : cookies) {
            if (COOKIE.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }

        return null;
    }

    private void expire(HttpServletResponse response) {
        write(response, "", Duration.ZERO);
    }

    // SameSite=Lax, not Strict: the callback is a top-level navigation from the provider's
    // site, and browsers do not send Strict cookies on it.
    private void write(HttpServletResponse response, String value, Duration maxAge) {
        ResponseCookie cookie = ResponseCookie.from(COOKIE, value)
            .httpOnly(true)
            .secure(secureCookie)
            .sameSite("Lax")
            .path(PATH)
            .maxAge(maxAge)
            .build();
        response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());
    }
}
