package com.urlshortener.auth.oauth;

import com.urlshortener.auth.controller.RefreshCookies;
import com.urlshortener.auth.service.AuthService;
import com.urlshortener.auth.service.AuthService.Tokens;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

// Ends every provider login with a redirect to the UI's /auth/callback page.
// Success sets the refresh_token cookie; the UI then calls /api/auth/refresh for the
// access token, so no token ever appears in a URL.
@Slf4j
@Component
@RequiredArgsConstructor
public class OAuth2LoginHandler
    implements AuthenticationSuccessHandler, AuthenticationFailureHandler
{

    private final AuthService auth;
    private final RefreshCookies refreshCookies;

    @Value("${app.ui-base-url}")
    private final String uiBaseUrl;

    @Override
    public void onAuthenticationSuccess(
        HttpServletRequest request,
        HttpServletResponse response,
        Authentication authentication
    ) throws IOException {
        OAuth2AuthenticationToken login = (OAuth2AuthenticationToken) authentication;
        Tokens tokens;
        try {
            tokens = auth.loginWithProvider(
                SocialProfiles.from(login.getAuthorizedClientRegistrationId(), login.getPrincipal())
            );
        } catch (ApiException e) {
            if (e.getErrorType() != ErrorType.EMAIL_NOT_VERIFIED) {
                failUnexpectedly(response, e);
                return;
            }
            response.sendRedirect(callbackUrl() + "?error=email_not_verified");
            return;
        } catch (RuntimeException e) {
            // E.g. a DB outage or an unmapped provider. The user is mid top-level navigation,
            // so send them back to the UI instead of a raw 500 page.
            failUnexpectedly(response, e);
            return;
        }

        response.addHeader(
            HttpHeaders.SET_COOKIE,
            refreshCookies.issue(tokens.refreshToken()).toString()
        );
        response.sendRedirect(callbackUrl());
    }

    private void failUnexpectedly(HttpServletResponse response, RuntimeException e)
        throws IOException {
        log.error("OAuth2 login succeeded at the provider but failed here", e);
        response.sendRedirect(callbackUrl() + "?error=oauth_failed");
    }

    private String callbackUrl() {
        return uiBaseUrl + "/auth/callback";
    }

    // Provider error text stays in the log. The URL only carries a fixed code.
    @Override
    public void onAuthenticationFailure(
        HttpServletRequest request,
        HttpServletResponse response,
        AuthenticationException exception
    ) throws IOException {
        log.warn("OAuth2 login failed: {}", exception.getMessage());
        boolean cancelled =
            exception instanceof OAuth2AuthenticationException oauth &&
            "access_denied".equals(oauth.getError().getErrorCode());

        response.sendRedirect(
            callbackUrl() + "?error=" + (cancelled ? "access_denied" : "oauth_failed")
        );
    }
}
