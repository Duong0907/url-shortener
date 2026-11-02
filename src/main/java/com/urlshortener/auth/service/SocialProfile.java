package com.urlshortener.auth.service;

// What every provider (Google, GitHub, ...) is mapped to before we look up the user.
public record SocialProfile(
    String provider,
    String providerUserId,
    String email,
    boolean emailVerified
) {}
