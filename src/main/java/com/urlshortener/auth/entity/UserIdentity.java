package com.urlshortener.auth.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.Instant;
import java.util.UUID;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NoArgsConstructor;

// A provider account (e.g. Google) linked to a user.
@Entity
@Table(name = "user_identities")
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class UserIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "user_id", nullable = false, updatable = false)
    private UUID userId;

    // Spring client registration id, e.g. "google".
    @Column(nullable = false, updatable = false, length = 32)
    private String provider;

    // The provider's stable user id, e.g. Google's "sub" claim.
    @Column(name = "provider_user_id", nullable = false, updatable = false, length = 255)
    private String providerUserId;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt = Instant.now();

    public UserIdentity(UUID userId, String provider, String providerUserId) {
        this.userId = userId;
        this.provider = provider;
        this.providerUserId = providerUserId;
    }
}
