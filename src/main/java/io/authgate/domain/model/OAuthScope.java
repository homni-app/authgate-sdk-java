package io.authgate.domain.model;

import java.util.Objects;

/**
 * OAuth 2.1 scope — self-validating value object.
 *
 * <p>Guarantees: non-null, non-blank, no whitespace.
 * An invalid scope is impossible by construction.</p>
 */
public record OAuthScope(String value) {

    public OAuthScope {
        Objects.requireNonNull(value, "scope must not be null");
        if (value.isBlank())
            throw new IllegalArgumentException("scope must not be blank");
        if (!value.equals(value.strip()) || value.chars().anyMatch(Character::isWhitespace))
            throw new IllegalArgumentException("scope must not contain whitespace: '" + value + "'");
    }

    @Override
    public String toString() {
        return value;
    }
}
