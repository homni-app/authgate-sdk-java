package io.authgate.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;

/**
 * Immutable token obtained via {@code client_credentials} grant.
 *
 * <p>Designed exclusively for machine-to-machine communication:
 * no refresh token, no user context — just an access token with an expiry.</p>
 */
public final class ServiceToken {

    private static final Duration EXPIRY_MARGIN = Duration.ofSeconds(30);

    private final String accessToken;
    private final Instant expiresAt;

    public ServiceToken(String accessToken, Instant expiresAt) {
        Objects.requireNonNull(accessToken, "accessToken must not be null");
        if (accessToken.isBlank()) {
            throw new IllegalArgumentException("accessToken must not be blank");
        }
        this.accessToken = accessToken;
        this.expiresAt = Objects.requireNonNull(expiresAt, "expiresAt must not be null");
    }

    /**
     * Returns {@code true} if the token will expire within 30 seconds.
     */
    public boolean isExpiringSoon() {
        return Instant.now().plus(EXPIRY_MARGIN).isAfter(expiresAt);
    }

    /**
     * Returns the raw access token string.
     */
    public String accessToken() {
        return accessToken;
    }

    @Override
    public String toString() {
        return "ServiceToken[expiresAt=" + expiresAt + ", expiringSoon=" + isExpiringSoon() + "]";
    }
}
