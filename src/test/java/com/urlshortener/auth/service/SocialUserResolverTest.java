package com.urlshortener.auth.service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.urlshortener.auth.entity.User;
import com.urlshortener.auth.entity.UserIdentity;
import com.urlshortener.auth.repository.UserIdentityRepository;
import com.urlshortener.auth.repository.UserRepository;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

// The five resolution rules from the design, with repositories as mocks.
@ExtendWith(MockitoExtension.class)
class SocialUserResolverTest {

    static final SocialProfile PROFILE = new SocialProfile(
        "google",
        "sub-1",
        "alice@example.com",
        true
    );

    @Mock
    UserRepository users;

    @Mock
    UserIdentityRepository identities;

    SocialUserResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new SocialUserResolver(users, identities);
    }

    @Test
    void returnsLinkedUserByProviderSubjectEvenIfTheEmailChanged() {
        User linked = withId(new User("old@example.com", "hash"));
        when(identities.findByProviderAndProviderUserId("google", "sub-1")).thenReturn(
            Optional.of(new UserIdentity(linked.getId(), "google", "sub-1"))
        );
        when(users.findById(linked.getId())).thenReturn(Optional.of(linked));

        User resolved = resolver.resolve(PROFILE);

        assertThat(resolved).isSameAs(linked);
        verify(users, never()).findByEmail(any());
        verify(users, never()).saveAndFlush(any());
        verify(identities, never()).saveAndFlush(any());
    }

    @Test
    void rejectsMissingEmail() {
        assertRejected(new SocialProfile("google", "sub-1", null, true));
    }

    @Test
    void rejectsUnverifiedEmail() {
        assertRejected(new SocialProfile("google", "sub-1", "alice@example.com", false));
    }

    @Test
    void linksExistingUserByNormalizedEmail() {
        User existing = withId(new User("alice@example.com", "hash"));
        existing.verifyEmail();
        when(users.findByEmail("alice@example.com")).thenReturn(Optional.of(existing));

        User resolved = resolver.resolve(
            new SocialProfile("google", "sub-1", "  Alice@Example.COM ", true)
        );

        assertThat(resolved).isSameAs(existing);
        assertThat(existing.getPasswordHash()).isEqualTo("hash");
        UserIdentity identity = savedIdentity();
        assertThat(identity.getUserId()).isEqualTo(existing.getId());
        assertThat(identity.getProvider()).isEqualTo("google");
        assertThat(identity.getProviderUserId()).isEqualTo("sub-1");
    }

    @Test
    void linkingUnverifiedUserClearsPasswordAndVerifies() {
        User existing = withId(new User("alice@example.com", "attacker-chosen"));
        existing.startVerification("h", Instant.now().plusSeconds(600));
        when(users.findByEmail("alice@example.com")).thenReturn(Optional.of(existing));

        resolver.resolve(PROFILE);

        assertThat(existing.getPasswordHash()).isNull();
        assertThat(existing.isEmailVerified()).isTrue();
        assertThat(existing.getVerificationTokenHash()).isNull();
    }

    @Test
    void createsSocialUserWhenNothingMatches() {
        when(users.saveAndFlush(any(User.class))).thenAnswer(call -> withId(call.getArgument(0)));

        User created = resolver.resolve(PROFILE);

        assertThat(created.getEmail()).isEqualTo("alice@example.com");
        assertThat(created.getPasswordHash()).isNull();
        assertThat(created.isEmailVerified()).isTrue();
        assertThat(savedIdentity().getUserId()).isEqualTo(created.getId());
    }

    private void assertRejected(SocialProfile profile) {
        assertThatThrownBy(() -> resolver.resolve(profile)).isInstanceOfSatisfying(
            ApiException.class,
            e -> assertThat(e.getErrorType()).isEqualTo(ErrorType.EMAIL_NOT_VERIFIED)
        );
        verify(users, never()).saveAndFlush(any());
        verify(identities, never()).saveAndFlush(any());
    }

    private UserIdentity savedIdentity() {
        ArgumentCaptor<UserIdentity> saved = ArgumentCaptor.forClass(UserIdentity.class);
        verify(identities).saveAndFlush(saved.capture());

        return saved.getValue();
    }

    private static User withId(User user) {
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());

        return user;
    }
}
