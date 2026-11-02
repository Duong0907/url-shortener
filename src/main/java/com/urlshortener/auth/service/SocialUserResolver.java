package com.urlshortener.auth.service;

import com.urlshortener.auth.entity.User;
import com.urlshortener.auth.entity.UserIdentity;
import com.urlshortener.auth.repository.UserIdentityRepository;
import com.urlshortener.auth.repository.UserRepository;
import com.urlshortener.error.ApiException;
import com.urlshortener.error.ErrorType;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class SocialUserResolver {

    private final UserRepository users;
    private final UserIdentityRepository identities;

    // Finds the user behind a provider login, linking or creating one when needed.
    // A unique violation means a parallel login won; the caller retries in a new transaction.
    @Transactional
    public User resolve(SocialProfile profile) {
        var linked = identities
            .findByProviderAndProviderUserId(profile.provider(), profile.providerUserId())
            .flatMap(identity -> users.findById(identity.getUserId()));
        if (linked.isPresent()) {
            return linked.get();
        }

        if (profile.email() == null || !profile.emailVerified()) {
            throw new ApiException(
                ErrorType.EMAIL_NOT_VERIFIED,
                "Provider did not return a verified email"
            );
        }

        String email = AuthService.normalize(profile.email());
        User user = users
            .findByEmail(email)
            .map(existing -> {
                existing.confirmEmailFromProvider();
                return existing;
            })
            .orElseGet(() -> users.saveAndFlush(User.social(email)));

        identities.saveAndFlush(
            new UserIdentity(user.getId(), profile.provider(), profile.providerUserId())
        );

        return user;
    }
}
