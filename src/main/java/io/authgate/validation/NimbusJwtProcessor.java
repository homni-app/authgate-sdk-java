package io.authgate.validation;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.JWKSourceBuilder;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTClaimsVerifier;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.JwtProcessor;
import io.authgate.domain.exception.IdentityProviderException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URL;
import java.text.ParseException;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Nimbus JOSE+JWT implementation of {@link JwtProcessor}.
 *
 * <p>Verifies JWT signatures using the IdP's JWKS endpoint.
 * JWKS keys are cached and refreshed automatically by Nimbus via {@code retrying(true)}.</p>
 *
 * <p>Thread-safe. The JWT processor is initialized lazily on first use
 * with a private {@link ReentrantLock} and timeout to prevent deadlocks.</p>
 */
public final class NimbusJwtProcessor implements JwtProcessor {

    private static final Logger log = LoggerFactory.getLogger(NimbusJwtProcessor.class);
    private static final long INIT_TIMEOUT_SECONDS = 30;

    private final EndpointDiscovery endpointDiscovery;
    private final ReentrantLock initLock = new ReentrantLock();
    private volatile ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public NimbusJwtProcessor(EndpointDiscovery endpointDiscovery) {
        this.endpointDiscovery = Objects.requireNonNull(endpointDiscovery);
    }

    @Override
    public JwtProcessingResult process(String rawJwt) {
        Objects.requireNonNull(rawJwt, "rawJwt must not be null");
        ensureProcessorInitialized();

        JWTClaimsSet claims;
        try {
            claims = jwtProcessor.process(rawJwt, null);
        } catch (BadJOSEException e) {
            log.debug("JWT signature/structure validation failed: {}", e.getMessage());
            return new JwtProcessingResult.SignatureInvalid(e.getMessage());
        } catch (ParseException e) {
            log.debug("JWT parse error: {}", e.getMessage());
            return new JwtProcessingResult.Malformed(e.getMessage());
        } catch (JOSEException e) {
            log.warn("Unexpected JOSE error during JWT processing", e);
            return new JwtProcessingResult.ProcessingError(e.getMessage());
        }

        return new JwtProcessingResult.Success(mapToParsedClaims(claims));
    }

    private ParsedClaims mapToParsedClaims(JWTClaimsSet claims) {
        return new ParsedClaims(
                claims.getSubject(),
                claims.getIssuer(),
                claims.getExpirationTime() != null ? claims.getExpirationTime().toInstant() : null,
                extractScopes(claims),
                claims.getAudience() != null ? new HashSet<>(claims.getAudience()) : Set.of()
        );
    }

    private void ensureProcessorInitialized() {
        if (jwtProcessor != null) {
            return;
        }
        try {
            if (!initLock.tryLock(INIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)) {
                throw new IdentityProviderException(
                        "Timeout waiting for JWT processor initialization after " + INIT_TIMEOUT_SECONDS + "s");
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdentityProviderException("Interrupted while waiting for JWT processor initialization", e);
        }
        try {
            if (jwtProcessor == null) {
                initializeProcessor(endpointDiscovery.discover().jwksUri());
            }
        } finally {
            initLock.unlock();
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
                    JOSEObjectType.JWT,
                    new JOSEObjectType("at+jwt"),
                    null
            ));
            processor.setJWSKeySelector(keySelector);
            processor.setJWTClaimsSetVerifier(new DefaultJWTClaimsVerifier<>(
                    new JWTClaimsSet.Builder().build(),
                    new HashSet<>(Set.of("sub", "iss", "exp"))
            ));

            this.jwtProcessor = processor;
            log.info("JWT processor initialized with JWKS from: {}", jwksUri);
        } catch (IOException e) {
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
        } catch (ParseException e) {
            log.trace("Scope claim is not a string list, skipping list extraction", e);
        }
        return Set.of();
    }

    private String extractStringClaim(JWTClaimsSet claims, String name) {
        try {
            return claims.getStringClaim(name);
        } catch (ParseException e) {
            log.trace("Failed to extract claim '{}' as string", name, e);
            return null;
        }
    }
}
