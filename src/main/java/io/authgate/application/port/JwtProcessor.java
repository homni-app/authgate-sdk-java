package io.authgate.application.port;

import io.authgate.domain.model.OAuthScope;

import java.time.Instant;
import java.util.Set;

/**
 * Outbound port for JWT processing (signature verification, claims parsing).
 *
 * <p> Default implementation: {@code NimbusJwtProcessor}.</p>
 */
public interface JwtProcessor {

    /**
     * Verifies the JWT signature and parses its claims.
     *
     * @param rawJwt the raw JWT string
     * @return processing result — never {@code null}
     */
    JwtProcessingResult process(String rawJwt);

    sealed interface JwtProcessingResult {

        /** Signature valid, claims parsed successfully. */
        record Success(ParsedClaims claims) implements JwtProcessingResult {}

        /** JWS signature or structure is invalid. */
        record SignatureInvalid(String message) implements JwtProcessingResult {}

        /** Token cannot be parsed as a valid JWT. */
        record Malformed(String message) implements JwtProcessingResult {}

        /** Unexpected processing error (key source failure, etc.). */
        record ProcessingError(String message) implements JwtProcessingResult {}
    }

    /**
     * Library-agnostic representation of parsed JWT claims.
     */
    record ParsedClaims(
            String subject,
            String issuer,
            Instant expiration,
            Set<OAuthScope> scopes,
            Set<String> audiences
    ) {}
}
