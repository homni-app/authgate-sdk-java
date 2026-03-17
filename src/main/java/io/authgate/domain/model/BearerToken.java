package io.authgate.domain.model;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Opaque bearer token. Never exposes raw value via getters.
 * Controlled extraction only through {@link #describeTo} or {@link #applyAsHeader}.
 */
public final class BearerToken {

    private final String value;

    public BearerToken(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Bearer token must not be blank");
        }
        this.value = value;
    }

    public void describeTo(Consumer<String> consumer) {
        consumer.accept(value);
    }

    public void applyAsHeader(Consumer<String> headerConsumer) {
        headerConsumer.accept("Bearer " + value);
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof BearerToken t && value.equals(t.value));
    }

    @Override
    public int hashCode() {
        return Objects.hash(value);
    }

    @Override
    public String toString() {
        return "BearerToken[***]";
    }
}
