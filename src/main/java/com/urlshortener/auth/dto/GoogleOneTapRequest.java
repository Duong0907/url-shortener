package com.urlshortener.auth.dto;

import jakarta.validation.constraints.NotBlank;

// credential is the Google ID token that Google Identity Services hands the UI.
public record GoogleOneTapRequest(@NotBlank String credential) {}
