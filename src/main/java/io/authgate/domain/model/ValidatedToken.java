package io.authgate.domain.model;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;

/**
 * Validated JWT claims. Provides authorization-decision behavior
 * and access to identity attributes.
 */
public final class ValidatedToken {

    private final String subject;
    private final String issuer;
    private final Set<String> scopes;
    private final Set<String> audiences;
    private final Instant expiration;

    private ValidatedToken(Builder builder) {
        if (builder.subject == null || builder.subject.isBlank()) {
            throw new IllegalArgumentException("subject must not be blank");
        }
        if (builder.issuer == null || builder.issuer.isBlank()) {
            throw new IllegalArgumentException("issuer must not be blank");
        }
        this.subject = builder.subject;
        this.issuer = builder.issuer;
        this.scopes = Collections.unmodifiableSet(Objects.requireNonNullElse(builder.scopes, Set.of()));
        this.audiences = Collections.unmodifiableSet(Objects.requireNonNullElse(builder.audiences, Set.of()));
        this.expiration = Objects.requireNonNull(builder.expiration);
    }

    // ── Accessors ────────────────────────────────────────────────

    /** The token subject ({@code sub} claim) — identifies the user or service. */
    public String subject() { return subject; }

    /** The token issuer ({@code iss} claim). */
    public String issuer() { return issuer; }

    /** Granted scopes ({@code scope} claim). Unmodifiable. */
    public Set<String> scopes() { return scopes; }

    /** Token audiences ({@code aud} claim). Unmodifiable. */
    public Set<String> audiences() { return audiences; }

    /** Token expiration time ({@code exp} claim). */
    public Instant expiration() { return expiration; }

    // ── Authorization Decisions ──────────────────────────────────

    /** Returns {@code true} if the token belongs to the given subject. */
    public boolean belongsTo(String subjectId) {
        return subject.equals(subjectId);
    }

    /** Returns {@code true} if the token contains the given scope. */
    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    /** Returns {@code true} if the token is intended for the given audience. */
    public boolean isIntendedFor(String audience) {
        return audiences.contains(audience);
    }

    /** Returns {@code true} if the token has expired (using system UTC clock). */
    public boolean hasExpired() {
        return hasExpired(Clock.systemUTC());
    }

    /** Returns {@code true} if the token has expired according to the given clock. */
    public boolean hasExpired(Clock clock) {
        return clock.instant().isAfter(expiration);
    }

    /** Returns {@code true} if this token was issued by the given issuer URI. */
    public boolean isIssuedBy(IssuerUri expected) {
        return expected.matches(issuer);
    }

    // ── Fluent Authorization Chain ──────────────────────────────

    /**
     * Starts a fluent authorization check on this token.
     *
     * <pre>{@code
     * token.require().scope("admin").subject(userId).orThrow();
     * }</pre>
     */
    public AuthorizationChain require() {
        return new AuthorizationChain(new ValidationOutcome.Valid(this));
    }

    @Override
    public String toString() {
        return "ValidatedToken[sub=***, scopes=" + scopes + "]";
    }

    public static final class Builder {
        private String subject;
        private String issuer;
        private Set<String> scopes;
        private Set<String> audiences;
        private Instant expiration;

        public Builder() {}

        public Builder subject(String v) { this.subject = v; return this; }
        public Builder issuer(String v) { this.issuer = v; return this; }
        public Builder scopes(Set<String> v) { this.scopes = v; return this; }
        public Builder audiences(Set<String> v) { this.audiences = v; return this; }
        public Builder expiration(Instant v) { this.expiration = v; return this; }

        public ValidatedToken build() { return new ValidatedToken(this); }
    }
}
