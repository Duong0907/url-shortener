package com.urlshortener.auth.repository;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.urlshortener.TestcontainersConfiguration;
import com.urlshortener.auth.entity.User;
import com.urlshortener.auth.entity.UserIdentity;
import jakarta.persistence.EntityManager;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.transaction.annotation.Transactional;

// Checks the schema rules from V4 against a real Postgres. Each test rolls back.
@SpringBootTest
@Import(TestcontainersConfiguration.class)
@Transactional
class UserIdentityRepositoryTest {

    @Autowired
    UserRepository users;

    @Autowired
    UserIdentityRepository identities;

    @Autowired
    EntityManager entityManager;

    @Test
    void socialUserWithoutPasswordIsStored() {
        User saved = users.saveAndFlush(User.social(uniqueEmail()));
        entityManager.clear();

        User reloaded = users.findById(saved.getId()).orElseThrow();
        assertThat(reloaded.getPasswordHash()).isNull();
        assertThat(reloaded.isEmailVerified()).isTrue();
    }

    @Test
    void findsIdentityByProviderAndSubject() {
        User user = users.saveAndFlush(User.social(uniqueEmail()));
        String subject = uniqueSubject();
        identities.saveAndFlush(new UserIdentity(user.getId(), "google", subject));

        assertThat(identities.findByProviderAndProviderUserId("google", subject))
            .get()
            .extracting(UserIdentity::getUserId)
            .isEqualTo(user.getId());
        assertThat(identities.findByProviderAndProviderUserId("google", uniqueSubject())).isEmpty();
        assertThat(identities.findByProviderAndProviderUserId("github", subject)).isEmpty();
    }

    @Test
    void duplicateProviderSubjectViolatesTheNamedUniqueConstraint() {
        // AuthService.loginWithProvider retries on this violation. If it changes, races break.
        User first = users.saveAndFlush(User.social(uniqueEmail()));
        User second = users.saveAndFlush(User.social(uniqueEmail()));
        String subject = uniqueSubject();
        identities.saveAndFlush(new UserIdentity(first.getId(), "google", subject));

        assertThatThrownBy(() ->
            identities.saveAndFlush(new UserIdentity(second.getId(), "google", subject))
        )
            .isInstanceOf(DataIntegrityViolationException.class)
            .rootCause()
            .hasMessageContaining("uk_user_identities_provider_subject");
    }

    @Test
    void deletingAUserDeletesTheirIdentities() {
        User user = users.saveAndFlush(User.social(uniqueEmail()));
        UserIdentity identity = identities.saveAndFlush(
            new UserIdentity(user.getId(), "google", uniqueSubject())
        );

        users.delete(user);
        users.flush();
        entityManager.clear();

        assertThat(identities.existsById(identity.getId())).isFalse();
    }

    @Test
    void identityWithAnUnknownUserIsRejected() {
        UserIdentity orphan = new UserIdentity(UUID.randomUUID(), "google", uniqueSubject());

        assertThatThrownBy(() -> identities.saveAndFlush(orphan)).isInstanceOf(
            DataIntegrityViolationException.class
        );
    }

    private static String uniqueEmail() {
        return "user-" + UUID.randomUUID() + "@example.com";
    }

    private static String uniqueSubject() {
        return "sub-" + UUID.randomUUID();
    }
}
