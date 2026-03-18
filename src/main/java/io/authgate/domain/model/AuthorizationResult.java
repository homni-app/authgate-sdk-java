package io.authgate.domain.model;

/**
 * Outcome of a combined validation + authorization check.
 * Three variants — exhaustive pattern matching in Java 21.
 *
 * <pre>{@code
 * switch (sdk.authorize(jwt).scope("admin").evaluate()) {
 *     case AuthorizationResult.Granted g  -> g.token().subject();
 *     case AuthorizationResult.Denied d   -> log.warn(d.reason().description());
 *     case AuthorizationResult.Rejected r -> log.warn(r.reason().description());
 * }
 * }</pre>
 */
public sealed interface AuthorizationResult {

    /** Authorization granted. Contains the validated token. */
    record Granted(ValidatedToken token) implements AuthorizationResult {}

    /** Token is valid but lacks required permissions. Contains a typed {@link DenialReason}. */
    record Denied(DenialReason reason) implements AuthorizationResult {}

    /** Token itself is invalid (expired, bad signature, etc.). Contains the rejection reason. */
    record Rejected(RejectionReason reason) implements AuthorizationResult {}
}
