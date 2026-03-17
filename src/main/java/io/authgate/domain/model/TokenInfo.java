package io.authgate.domain.model;

import java.time.Duration;
import java.time.Instant;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Token pair returned after successful authorization.
 * Encapsulates access/refresh tokens with lifecycle behavior.
 */
public final class TokenInfo {

    private final String accessToken;
    private final String refreshToken;
    private final Duration expiresIn;
    private final String tokenType;
    private final Instant obtainedAt;

    private TokenInfo(Builder builder) {
        this.accessToken = Objects.requireNonNull(builder.accessToken);
        this.refreshToken = builder.refreshToken;
        this.expiresIn = Objects.requireNonNull(builder.expiresIn);
        this.tokenType = Objects.requireNonNullElse(builder.tokenType, "Bearer");
        this.obtainedAt = Instant.now();
    }

    public boolean isExpired() {
        return Instant.now().isAfter(obtainedAt.plus(expiresIn));
    }

    public boolean canRefresh() {
        return refreshToken != null && !refreshToken.isBlank();
    }

    public void describeAccessTokenTo(Consumer<String> consumer) {
        consumer.accept(accessToken);
    }

    public void describeAuthorizationHeaderTo(Consumer<String> consumer) {
        consumer.accept("Bearer " + accessToken);
    }

    public void describeRefreshTokenTo(Consumer<String> consumer) {
        if (refreshToken != null) consumer.accept(refreshToken);
    }

    public void describeExpiresInTo(Consumer<Duration> consumer) {
        consumer.accept(expiresIn);
    }

    /**
     * Converts the access token into a {@link BearerToken} for validation.
     */
    public BearerToken toBearerToken() {
        return new BearerToken(accessToken);
    }

    @Override
    public String toString() {
        return "TokenInfo[type=" + tokenType + ", expired=" + isExpired() + ", canRefresh=" + canRefresh() + "]";
    }

    public static final class Builder {
        private String accessToken;
        private String refreshToken;
        private Duration expiresIn;
        private String tokenType;

        public Builder() {}

        public Builder accessToken(String v) { this.accessToken = v; return this; }
        public Builder refreshToken(String v) { this.refreshToken = v; return this; }
        public Builder expiresIn(Duration v) { this.expiresIn = v; return this; }
        public Builder expiresInSeconds(long v) { this.expiresIn = Duration.ofSeconds(v); return this; }
        public Builder tokenType(String v) { this.tokenType = v; return this; }

        public TokenInfo build() { return new TokenInfo(this); }
    }
}
