package io.authgate.domain.model;

import java.time.Clock;
import java.time.Instant;
import java.util.Collections;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Validated JWT claims. Exposes authorization-decision behavior only.
 * External code asks "can this token do X?" — never "give me the raw claims."
 */
public final class ValidatedToken {

    private final String subject;
    private final String issuer;
    private final Set<String> scopes;
    private final Set<String> audiences;
    private final Instant expiration;
    private final Instant issuedAt;
    private final String clientId;

    private ValidatedToken(Builder builder) {
        this.subject = Objects.requireNonNull(builder.subject);
        this.issuer = Objects.requireNonNull(builder.issuer);
        this.scopes = Collections.unmodifiableSet(Objects.requireNonNullElse(builder.scopes, Set.of()));
        this.audiences = Collections.unmodifiableSet(Objects.requireNonNullElse(builder.audiences, Set.of()));
        this.expiration = Objects.requireNonNull(builder.expiration);
        this.issuedAt = builder.issuedAt;
        this.clientId = builder.clientId;
    }

    // ── Authorization Decisions ──────────────────────────────────

    public boolean belongsTo(String subjectId) {
        return subject.equals(subjectId);
    }

    public boolean hasScope(String scope) {
        return scopes.contains(scope);
    }

    public boolean hasAllScopes(Set<String> required) {
        return scopes.containsAll(required);
    }

    public boolean hasAnyScope(Set<String> candidates) {
        return candidates.stream().anyMatch(scopes::contains);
    }

    public boolean isIntendedFor(String audience) {
        return audiences.contains(audience);
    }

    public boolean issuedByClient(String expectedClientId) {
        return clientId != null && clientId.equals(expectedClientId);
    }

    public boolean hasExpired() {
        return hasExpired(Clock.systemUTC());
    }

    public boolean hasExpired(Clock clock) {
        return clock.instant().isAfter(expiration);
    }

    /**
     * Checks whether this token was issued by the given issuer URI, with normalization.
     */
    public boolean isIssuedBy(IssuerUri expected) {
        return expected.matches(issuer);
    }

    // ── Controlled State Extraction (Tell, Don't Ask) ────────────

    public void describeSubjectTo(Consumer<String> consumer) {
        consumer.accept(subject);
    }

    public void describeIssuerTo(Consumer<String> consumer) {
        consumer.accept(issuer);
    }

    public void describeScopesTo(Consumer<Set<String>> consumer) {
        consumer.accept(scopes);
    }

    public void describeAudiencesTo(Consumer<Set<String>> consumer) {
        consumer.accept(audiences);
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
        private Instant issuedAt;
        private String clientId;

        public Builder() {}

        public Builder subject(String v) { this.subject = v; return this; }
        public Builder issuer(String v) { this.issuer = v; return this; }
        public Builder scopes(Set<String> v) { this.scopes = v; return this; }
        public Builder audiences(Set<String> v) { this.audiences = v; return this; }
        public Builder expiration(Instant v) { this.expiration = v; return this; }
        public Builder issuedAt(Instant v) { this.issuedAt = v; return this; }
        public Builder clientId(String v) { this.clientId = v; return this; }

        public ValidatedToken build() { return new ValidatedToken(this); }
    }
}
