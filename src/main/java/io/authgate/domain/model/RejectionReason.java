package io.authgate.domain.model;

import java.util.function.Consumer;

public enum RejectionReason {

    TOKEN_EXPIRED("token_expired", "Token has expired"),
    INVALID_SIGNATURE("invalid_signature", "Token signature is invalid"),
    ISSUER_MISMATCH("issuer_mismatch", "Token issuer does not match expected issuer"),
    AUDIENCE_MISMATCH("audience_mismatch", "Token audience does not match expected audience"),
    INSUFFICIENT_SCOPE("insufficient_scope", "Token does not contain the required scopes"),
    MALFORMED_TOKEN("malformed_token", "Token is malformed or cannot be parsed"),
    REVOKED("revoked", "Token has been revoked"),
    UNKNOWN("unknown", "Unknown validation failure");

    private final String code;
    private final String description;

    RejectionReason(String code, String description) {
        this.code = code;
        this.description = description;
    }

    public void describeTo(Consumer<String> consumer) {
        consumer.accept(description);
    }

    public void describeCodeTo(Consumer<String> consumer) {
        consumer.accept(code);
    }
}
