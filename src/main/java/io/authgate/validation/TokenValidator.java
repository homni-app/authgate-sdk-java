package io.authgate.validation;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.authgate.application.port.EndpointDiscovery;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.*;
import io.authgate.domain.service.TokenValidationRules;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Validates bearer tokens locally using the IdP's JWKS endpoint.
 * JWKS keys are cached and refreshed automatically by Nimbus.
 *
 * <p>The JWT processor is initialized once on first use and reused.
 * Nimbus handles JWKS key rotation automatically via {@code retrying(true)}.</p>
 */
public final class TokenValidator {

    private static final Logger log = LoggerFactory.getLogger(TokenValidator.class);

    private final EndpointDiscovery endpointDiscovery;
    private final TokenValidationRules validationRules;
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public TokenValidator(EndpointDiscovery endpointDiscovery, TokenValidationRules validationRules) {
        this.endpointDiscovery = Objects.requireNonNull(endpointDiscovery);
        this.validationRules = Objects.requireNonNull(validationRules);
    }

    /**
     * Validates a raw JWT string. Returns a sealed {@link ValidationOutcome}.
     */
    public ValidationOutcome validate(String rawJwt) {
        Objects.requireNonNull(rawJwt, "rawJwt must not be null");

        ensureProcessorInitialized();

        JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(rawJwt, null);
        } catch (com.nimbusds.jose.proc.BadJOSEException e) {
            log.debug("JWT signature/structure validation failed: {}", e.getMessage());
            return new ValidationOutcome.Rejected(RejectionReason.INVALID_SIGNATURE);
        } catch (ParseException e) {
            log.debug("JWT parse error: {}", e.getMessage());
            return new ValidationOutcome.Rejected(RejectionReason.MALFORMED_TOKEN);
        } catch (Exception e) {
            log.error("Unexpected error during JWT processing", e);
            return new ValidationOutcome.Rejected(RejectionReason.UNKNOWN);
        }

        var token = mapToValidatedToken(claims);
        return validationRules.validate(token);
    }

    /**
     * Validates from an Authorization header ("Bearer xxx").
     */
    public ValidationOutcome validateFromHeader(String authorizationHeader) {
        if (authorizationHeader == null || !authorizationHeader.regionMatches(true, 0, "Bearer ", 0, 7)) {
            throw new IllegalArgumentException("Invalid Authorization header: expected 'Bearer <token>'");
        }
        var rawJwt = authorizationHeader.substring(7).trim();
        return validate(rawJwt);
    }

    // ── Internal ─────────────────────────────────────────────────

    private ValidatedToken mapToValidatedToken(JWTClaimsSet claims) {
        var builder = new ValidatedToken.Builder()
                .subject(claims.getSubject())
                .issuer(claims.getIssuer())
                .expiration(claims.getExpirationTime().toInstant())
                .scopes(extractScopes(claims))
                .audiences(claims.getAudience() != null ? new HashSet<>(claims.getAudience()) : Set.of());

        if (claims.getIssueTime() != null) {
            builder.issuedAt(claims.getIssueTime().toInstant());
        }

        var clientId = extractStringClaim(claims, "azp");
        if (clientId == null) clientId = extractStringClaim(claims, "client_id");
        if (clientId != null) builder.clientId(clientId);

        return builder.build();
    }

    private void ensureProcessorInitialized() {
        if (jwtProcessor == null) {
            synchronized (this) {
                if (jwtProcessor == null) {
                    var endpoints = endpointDiscovery.discover();
                    var jwksUriRef = new AtomicReference<String>();
                    endpoints.describeJwksUriTo(jwksUriRef::set);
                    initializeProcessor(jwksUriRef.get());
                }
            }
        }
    }

    private void initializeProcessor(String jwksUri) {
        try {
            JWKSource<SecurityContext> jwkSource = JWKSourceBuilder
                    .create(new URL(jwksUri))
                    .retrying(true)
                    .build();

            var keySelector = new JWSVerificationKeySelector<SecurityContext>(
                    new HashSet<>(Set.of(
                            JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
                            JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512
                    )),
                    jwkSource
            );

            ConfigurableJWTProcessor<SecurityContext> processor = new DefaultJWTProcessor<>();
            processor.setJWSTypeVerifier(new DefaultJOSEObjectTypeVerifier<>(
                    com.nimbusds.jose.JOSEObjectType.JWT,
                    new com.nimbusds.jose.JOSEObjectType("at+jwt"),
                    null
            ));
            processor.setJWSKeySelector(keySelector);
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().build(),
                    new HashSet<>(Set.of("sub", "iss", "exp"))
            ));

            this.jwtProcessor = processor;
            log.info("JWT processor initialized with JWKS from: {}", jwksUri);
        } catch (Exception e) {
            throw new IdentityProviderException("Failed to initialize JWKS processor from " + jwksUri, e);
        }
    }

    private Set<String> extractScopes(JWTClaimsSet claims) {
        var scope = extractStringClaim(claims, "scope");
        if (scope != null && !scope.isBlank()) {
            return new HashSet<>(Arrays.asList(scope.split("\\s+")));
        }
        try {
            var list = claims.getStringListClaim("scope");
            if (list != null) return new HashSet<>(list);
        } catch (ParseException ignored) {}
        return Set.of();
    }

    private String extractStringClaim(JWTClaimsSet claims, String name) {
        try { return claims.getStringClaim(name); }
        catch (ParseException e) { return null; }
    }
}
