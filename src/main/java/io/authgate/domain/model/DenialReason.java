package io.authgate.domain.model;

/**
 * Typed reason why authorization was denied on a valid token.
 * Each variant carries the specific value that caused the mismatch.
 *
 * <pre>{@code
 * switch (denialReason) {
 *     case DenialReason.MissingScope m    -> log.warn("Need scope: {}", m.scope());
 *     case DenialReason.AudienceMismatch a -> log.warn("Wrong audience: {}", a.audience());
 *     case DenialReason.SubjectMismatch s  -> log.warn("Wrong subject: {}", s.subject());
 * }
 * }</pre>
 */
public sealed interface DenialReason {

    /** Human-readable description of the denial. */
    String description();

    /** Token lacks a required scope. */
    record MissingScope(String scope) implements DenialReason {
        @Override
        public String description() {
            return "Missing required scope: " + scope;
        }
    }

    /** Token is not intended for the required audience. */
    record AudienceMismatch(String audience) implements DenialReason {
        @Override
        public String description() {
            return "Token not intended for audience: " + audience;
        }
    }

    /** Token does not belong to the required subject. */
    record SubjectMismatch(String subject) implements DenialReason {
        @Override
        public String description() {
            return "Token does not belong to subject: " + subject;
        }
    }
}
