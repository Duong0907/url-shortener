package com.urlshortener.auth.repository;

import com.urlshortener.auth.entity.UserIdentity;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserIdentityRepository extends JpaRepository<UserIdentity, UUID> {
    Optional<UserIdentity> findByProviderAndProviderUserId(String provider, String providerUserId);
}
