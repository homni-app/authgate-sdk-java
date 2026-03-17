package io.authgate.domain.exception;

import io.authgate.domain.model.RejectionReason;

public final class TokenValidationException extends AuthGateException {

    private final RejectionReason reason;

    public TokenValidationException(RejectionReason reason) {
        super(formatMessage(reason));
        this.reason = reason;
    }

    public TokenValidationException(RejectionReason reason, Throwable cause) {
        super(formatMessage(reason), cause);
        this.reason = reason;
    }

    public void describeReasonTo(java.util.function.Consumer<RejectionReason> consumer) {
        consumer.accept(reason);
    }

    private static String formatMessage(RejectionReason reason) {
        var sb = new StringBuilder("Token validation failed: ");
        reason.describeTo(sb::append);
        return sb.toString();
    }
}
