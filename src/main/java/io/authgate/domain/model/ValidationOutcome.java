package io.authgate.domain.model;

/**
 * Algebraic data type for token validation results.
 * Sealed — exhaustive pattern matching in Java 21.
 *
 * <pre>{@code
 * switch (outcome) {
 *     case ValidationOutcome.Valid v -> v.token().hasScope("admin");
 *     case ValidationOutcome.Rejected r -> r.describeReasonTo(log::warn);
 * }
 * }</pre>
 */
public sealed interface ValidationOutcome {

    // ── Variants ─────────────────────────────────────────────────

    record Valid(ValidatedToken token) implements ValidationOutcome {
    }

    record Rejected(RejectionReason reason) implements ValidationOutcome {

        public void describeReasonTo(java.util.function.Consumer<String> consumer) {
            reason.describeTo(consumer);
        }

        public void describeCodeTo(java.util.function.Consumer<String> consumer) {
            reason.describeCodeTo(consumer);
        }
    }
}
