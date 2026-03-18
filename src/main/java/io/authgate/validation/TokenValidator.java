package io.authgate.validation;

import io.authgate.application.port.JwtProcessor;
import io.authgate.application.port.JwtProcessor.JwtProcessingResult;
import io.authgate.application.port.JwtProcessor.ParsedClaims;
import io.authgate.domain.model.RejectionReason;
import io.authgate.domain.model.ValidatedToken;
import io.authgate.domain.model.ValidationOutcome;
import io.authgate.domain.service.TokenValidationRules;

import java.util.Objects;

/**
 * Orchestrates JWT validation: delegates cryptographic verification to {@link JwtProcessor}
 * and applies domain rules via {@link TokenValidationRules}.
 *
 * <p>This class contains no infrastructure dependencies — all library-specific
 * logic lives behind the {@link JwtProcessor} port.</p>
 */
public final class TokenValidator {

    private final JwtProcessor jwtProcessor;
    private final TokenValidationRules validationRules;

    public TokenValidator(JwtProcessor jwtProcessor, TokenValidationRules validationRules) {
        this.jwtProcessor = Objects.requireNonNull(jwtProcessor);
        this.validationRules = Objects.requireNonNull(validationRules);
    }

    /**
     * Validates a raw JWT string. Returns a sealed {@link ValidationOutcome}.
     */
    public ValidationOutcome validate(String rawJwt) {
        Objects.requireNonNull(rawJwt, "rawJwt must not be null");

        return switch (jwtProcessor.process(rawJwt)) {
            case JwtProcessingResult.Success s -> {
                var token = mapToValidatedToken(s.claims());
                yield validationRules.validate(token);
            }
            case JwtProcessingResult.SignatureInvalid e ->
                    new ValidationOutcome.Rejected(RejectionReason.INVALID_SIGNATURE);
            case JwtProcessingResult.Malformed e ->
                    new ValidationOutcome.Rejected(RejectionReason.MALFORMED_TOKEN);
            case JwtProcessingResult.ProcessingError e ->
                    new ValidationOutcome.Rejected(RejectionReason.UNKNOWN);
        };
    }

    /**
     * Validates from an Authorization header ({@code "Bearer xxx"}).
     */
    public ValidationOutcome validateFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return new ValidationOutcome.Rejected(RejectionReason.MALFORMED_TOKEN);
        }
        var rawJwt = authorizationHeader.substring(7).trim();
        return validate(rawJwt);
    }

    private ValidatedToken mapToValidatedToken(ParsedClaims claims) {
        return new ValidatedToken.Builder()
                .subject(claims.subject())
                .issuer(claims.issuer())
                .expiration(claims.expiration())
                .scopes(claims.scopes())
                .audiences(claims.audiences())
                .build();
    }
}
