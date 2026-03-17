package io.authgate.domain.service;

import io.authgate.domain.model.IssuerUri;
import io.authgate.domain.model.RejectionReason;
import io.authgate.domain.model.ValidatedToken;
import io.authgate.domain.model.ValidationOutcome;

import java.time.Clock;
import java.time.Duration;
import java.util.Objects;

/**
 * Domain service: applies business validation rules to a validated token.
 * Pure domain — no ports, no infrastructure.
 */
public final class TokenValidationRules {

    private final IssuerUri expectedIssuer;
    private final String expectedAudience;
    private final Clock clock;

    public TokenValidationRules(IssuerUri expectedIssuer, String expectedAudience, Duration clockSkewTolerance) {
        this.expectedIssuer = Objects.requireNonNull(expectedIssuer);
        this.expectedAudience = expectedAudience;
        this.clock = Clock.offset(Clock.systemUTC(), clockSkewTolerance.negated());
    }

    public TokenValidationRules(IssuerUri expectedIssuer, String expectedAudience) {
        this(expectedIssuer, expectedAudience, Duration.ZERO);
    }

    public ValidationOutcome validate(ValidatedToken token) {
        if (token.hasExpired(clock)) {
            return new ValidationOutcome.Rejected(RejectionReason.TOKEN_EXPIRED);
        }

        if (!token.isIssuedBy(expectedIssuer)) {
            return new ValidationOutcome.Rejected(RejectionReason.ISSUER_MISMATCH);
        }

        if (expectedAudience != null && !expectedAudience.isBlank()
                && !token.isIntendedFor(expectedAudience)) {
            return new ValidationOutcome.Rejected(RejectionReason.AUDIENCE_MISMATCH);
        }

        return new ValidationOutcome.Valid(token);
    }
}
