package io.authgate.domain.model;

import java.io.Closeable;
import java.util.Arrays;
import java.util.Objects;

/**
 * Sensitive value wrapper that stores secrets in {@code char[]} instead of {@code String}.
 *
 * <p>Unlike {@code String}, the backing array can be explicitly zeroed via {@link #wipe()}
 * or {@link #close()}, reducing the window during which the secret is readable in heap memory.</p>
 *
 * <p>{@link #toString()} is intentionally masked to prevent accidental leakage in logs.</p>
 */
public final class SecretValue implements Closeable {

    private final char[] chars;
    private volatile boolean wiped;

    public SecretValue(String value) {
        Objects.requireNonNull(value, "secret must not be null");
        if (value.isBlank()) {
            throw new IllegalArgumentException("secret must not be blank");
        }
        this.chars = value.toCharArray();
    }

    /**
     * Returns the secret as a {@code String} for short-lived use (e.g. HTTP form body).
     *
     * @throws IllegalStateException if the secret has been wiped
     */
    public String asString() {
        if (wiped) {
            throw new IllegalStateException("secret has been wiped");
        }
        return new String(chars);
    }

    /**
     * Zeroes the backing array, making the secret unreadable.
     * Safe to call multiple times.
     */
    public void wipe() {
        Arrays.fill(chars, '\0');
        wiped = true;
    }

    @Override
    public void close() {
        wipe();
    }

    @Override
    public String toString() {
        return "***";
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof SecretValue that)) return false;
        return Arrays.equals(chars, that.chars);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(chars);
    }
}
