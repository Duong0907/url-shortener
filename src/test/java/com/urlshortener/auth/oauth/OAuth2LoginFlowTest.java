package com.urlshortener.auth.oauth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import com.urlshortener.TestcontainersConfiguration;
import jakarta.servlet.http.Cookie;
import java.nio.charset.StandardCharsets;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

// The Spring-served half of Google sign-in: start redirect, state cookie and the
// failure redirects. A real code exchange needs Google, so it is checked by hand.
@SpringBootTest
@AutoConfigureMockMvc
@Import(TestcontainersConfiguration.class)
class OAuth2LoginFlowTest {

    static final String START = "/api/auth/oauth2/authorization/google";
    static final String CALLBACK = "/api/auth/oauth2/code/google";
    static final String UI_CALLBACK = "http://localhost:3000/auth/callback";

    @Autowired
    MockMvc mvc;

    @Test
    void startRedirectsToGoogleWithStateAndPkce() throws Exception {
        MvcResult result = mvc.perform(get(START)).andExpect(status().isFound()).andReturn();

        String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).startsWith("https://accounts.google.com/");
        UriComponents uri = UriComponentsBuilder.fromUriString(location).build();
        assertThat(uri.getQueryParams().getFirst("state")).isNotBlank();
        assertThat(uri.getQueryParams().getFirst("nonce")).isNotBlank();
        assertThat(uri.getQueryParams().getFirst("code_challenge")).isNotBlank();
        assertThat(uri.getQueryParams().getFirst("code_challenge_method")).isEqualTo("S256");
        assertThat(uri.getQueryParams().getFirst("redirect_uri")).isIn(
            "http://localhost:3000/api/auth/oauth2/code/google",
            "http%3A%2F%2Flocalhost%3A3000%2Fapi%2Fauth%2Foauth2%2Fcode%2Fgoogle"
        );
        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE))
            .startsWith(CookieAuthorizationRequestRepository.COOKIE + "=")
            .contains("SameSite=Lax");
        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void callbackWithoutCookieRedirectsWithOauthFailed() throws Exception {
        MvcResult result = mvc
            .perform(get(CALLBACK).param("code", "c").param("state", "s"))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(UI_CALLBACK + "?error=oauth_failed"))
            .andReturn();

        assertThat(result.getRequest().getSession(false)).isNull();
    }

    @Test
    void callbackWithTamperedCookieRedirectsWithOauthFailed() throws Exception {
        mvc.perform(
            get(CALLBACK)
                .param("code", "c")
                .param("state", "s")
                .cookie(new Cookie(CookieAuthorizationRequestRepository.COOKIE, "garbage"))
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(UI_CALLBACK + "?error=oauth_failed"));
    }

    @Test
    void userCancelRedirectsWithAccessDeniedAndExpiresTheCookie() throws Exception {
        MvcResult start = mvc.perform(get(START)).andReturn();
        // Query values in Location are URL-encoded (state may end in %3D); browsers decode them.
        String state = UriUtils.decode(
            UriComponentsBuilder.fromUriString(start.getResponse().getHeader(HttpHeaders.LOCATION))
                .build()
                .getQueryParams()
                .getFirst("state"),
            StandardCharsets.UTF_8
        );
        Cookie stateCookie = start
            .getResponse()
            .getCookie(CookieAuthorizationRequestRepository.COOKIE);

        MvcResult result = mvc
            .perform(
                get(CALLBACK)
                    .param("error", "access_denied")
                    .param("state", state)
                    .cookie(stateCookie)
            )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(UI_CALLBACK + "?error=access_denied"))
            .andReturn();

        assertThat(result.getResponse().getHeader(HttpHeaders.SET_COOKIE)).contains("Max-Age=0");
        assertThat(result.getRequest().getSession(false)).isNull();
    }
}
