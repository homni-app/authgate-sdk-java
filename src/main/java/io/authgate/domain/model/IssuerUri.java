package io.authgate.domain.model;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Value Object representing a normalized OIDC issuer URI.
 * Guarantees trailing slash for consistent comparison.
 */
public final class IssuerUri {

    private final String normalized;

    public IssuerUri(String raw, boolean requireHttps) {
        Objects.requireNonNull(raw, "Issuer URI must not be null");
        if (raw.isBlank()) {
            throw new IllegalArgumentException("Issuer URI must not be blank");
        }
        if (requireHttps && !raw.startsWith("https://")) {
            throw new IllegalArgumentException("Issuer URI must use HTTPS: " + raw);
        }
        this.normalized = raw.endsWith("/") ? raw : raw + "/";
    }

    public IssuerUri(String raw) {
        this(raw, false);
    }

    /**
     * Compares this issuer URI with a raw issuer string, normalizing both.
     */
    public boolean matches(String issuer) {
        if (issuer == null) return false;
        var other = issuer.endsWith("/") ? issuer : issuer + "/";
        return normalized.equals(other);
    }

    /**
     * Resolves a sub-path relative to this issuer URI.
     * E.g., {@code resolvePath(".well-known/openid-configuration")}.
     */
    public String resolvePath(String path) {
        Objects.requireNonNull(path);
        return normalized + path;
    }

    public void describeTo(Consumer<String> consumer) {
        consumer.accept(normalized);
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof IssuerUri other && normalized.equals(other.normalized));
    }

    @Override
    public int hashCode() {
        return Objects.hash(normalized);
    }

    @Override
    public String toString() {
        return normalized;
    }
}
