package io.authgate;

import io.authgate.application.port.CacheStore;
import io.authgate.application.port.HttpTransport;
import io.authgate.cache.InMemoryCacheStore;
import io.authgate.config.AuthGateConfiguration;
import io.authgate.credentials.ClientCredentialsClient;
import io.authgate.discovery.OidcDiscoveryClient;
import io.authgate.domain.model.AuthorizationChain;
import io.authgate.domain.model.IssuerUri;
import io.authgate.domain.model.OAuthScope;
import io.authgate.domain.model.ServiceToken;
import io.authgate.domain.model.ValidationOutcome;
import io.authgate.domain.service.TokenValidationRules;
import io.authgate.http.CircuitBreakerHttpTransport;
import io.authgate.http.DefaultHttpTransport;
import io.authgate.validation.NimbusJwtProcessor;
import io.authgate.validation.TokenValidator;

import java.util.Objects;
import java.util.Set;

/**
 * AuthGate SDK — single entry point for standalone (non-Spring) usage.
 *
 * <h2>Minimal setup:</h2>
 * <pre>{@code
 * var sdk = new AuthGate(new AuthGateConfiguration.Builder()
 *     .issuerUri("https://idp.example.com/realms/my-realm/")
 *     .clientId("my-client")
 *     .build());
 * }</pre>
 *
 * <h2>Token validation:</h2>
 * <pre>{@code
 * switch (sdk.validateToken(jwt)) {
 *     case ValidationOutcome.Valid v   -> v.token().hasScope("admin");
 *     case ValidationOutcome.Rejected r -> log.warn(r.reason().description());
 * }
 * }</pre>
 */
public final class AuthGate {

    private final TokenValidator tokenValidator;
    private final ClientCredentialsClient clientCredentialsClient;

    public AuthGate(AuthGateConfiguration config) {
        this(config, new InMemoryCacheStore());
    }

    public AuthGate(AuthGateConfiguration config, CacheStore cacheStore) {
        this(config, cacheStore, new DefaultHttpTransport(config.httpTimeout()));
    }

    public AuthGate(AuthGateConfiguration config, CacheStore cacheStore, HttpTransport httpTransport) {
        Objects.requireNonNull(config);
        Objects.requireNonNull(cacheStore);
        Objects.requireNonNull(httpTransport);

        var transport = new CircuitBreakerHttpTransport(
                httpTransport,
                config.circuitBreakerFailureThreshold(),
                config.circuitBreakerResetTimeout());

        var issuerUri = new IssuerUri(config.issuerUri(), config.requireHttps());
        var discoveryClient = new OidcDiscoveryClient(issuerUri, transport, cacheStore, config.discoveryTtl());

        var jwtProcessor = new NimbusJwtProcessor(discoveryClient);
        var validationRules = new TokenValidationRules(issuerUri, config.audience(), config.clockSkewTolerance());
        this.tokenValidator = new TokenValidator(jwtProcessor, validationRules);

        this.clientCredentialsClient = config.clientSecret() != null
                ? new ClientCredentialsClient(
                        discoveryClient, transport, config.clientId(),
                        config.clientSecret())
                : null;
    }

    // ── Token Validation ───────────────────────────────────────

    /**
     * Validates a raw JWT string and returns the outcome.
     *
     * <p>Use when you already extracted the token from the request (e.g. from a custom header,
     * query parameter, or WebSocket message). For the standard {@code Authorization: Bearer ...}
     * header, prefer {@link #validateTokenFromHeader(String)}.</p>
     *
     * <p>Returns {@link ValidationOutcome.Valid} or {@link ValidationOutcome.Rejected} —
     * use pattern matching to handle each case. Does not throw on invalid tokens.</p>
     *
     * <pre>{@code
     * String jwt = request.getParameter("access_token");
     * switch (sdk.validateToken(jwt)) {
     *     case ValidationOutcome.Valid v   -> ...;
     *     case ValidationOutcome.Rejected r -> ...;
     * }
     * }</pre>
     *
     * @param rawJwt the raw JWT string (without "Bearer " prefix)
     * @return validation outcome — never {@code null}
     */
    public ValidationOutcome validateToken(String rawJwt) {
        return tokenValidator.validate(rawJwt);
    }

    /**
     * Validates a JWT from the standard {@code Authorization: Bearer <token>} header.
     *
     * <p>Extracts the token from the header value (strips "Bearer " prefix),
     * then validates signature, expiration, issuer, and audience.</p>
     *
     * <pre>{@code
     * String authHeader = request.getHeader("Authorization");
     * switch (sdk.validateTokenFromHeader(authHeader)) {
     *     case ValidationOutcome.Valid v   -> ...;
     *     case ValidationOutcome.Rejected r -> ...;
     * }
     * }</pre>
     *
     * @param authorizationHeader the full header value, e.g. {@code "Bearer eyJhbG..."}
     * @return validation outcome — never {@code null}
     */
    public ValidationOutcome validateTokenFromHeader(String authorizationHeader) {
        return tokenValidator.validateFromHeader(authorizationHeader);
    }

    // ── Authorization ────────────────────────────────────────────

    /**
     * Validates a raw JWT and returns a fluent authorization chain for permission checks.
     *
     * <p>Use when you need to enforce specific scopes, audience, or subject on the token.
     * The chain supports two styles: exception-based ({@code orThrow()}) and
     * polymorphic ({@code evaluate()}).</p>
     *
     * <p><b>Exception-based</b> — zero handling, catch globally (e.g. {@code @ExceptionHandler}).
     * Throws {@code TokenValidationException} (401) or {@code AccessDeniedException} (403):</p>
     * <pre>{@code
     * // Any authenticated user
     * ValidatedToken token = sdk.authorize(rawJwt).orThrow();
     *
     * // Admin-only(or another role) endpoint
     * sdk.authorize(rawJwt).scope("admin").orThrow();
     *
     * // Admin + resource owner check
     * sdk.authorize(rawJwt).scope("admin").subject(userId).orThrow();
     * }</pre>
     *
     * <p><b>Polymorphic</b> — handle each case explicitly:</p>
     * <pre>{@code
     * switch (sdk.authorize(rawJwt).scope("admin").evaluate()) {
     *     case AuthorizationResult.Granted g  -> ok(g.token());
     *     case AuthorizationResult.Denied d   -> log.warn(d.reason());
     *     case AuthorizationResult.Rejected r -> log.warn(r.reason().description());
     * }
     * }</pre>
     *
     * @param rawJwt the raw JWT string (without "Bearer " prefix)
     */
    public AuthorizationChain authorize(String rawJwt) {
        return new AuthorizationChain(tokenValidator.validate(rawJwt));
    }

    /**
     * Validates a JWT from {@code Authorization: Bearer <token>} header and returns
     * a fluent authorization chain. This is the most common entry point for REST APIs.
     *
     * <pre>{@code
     * @GetMapping("/users/{id}")
     * public ResponseEntity<?> getUser(@RequestHeader("Authorization") String auth,
     *                                  @PathVariable String id) {
     *     sdk.authorizeFromHeader(auth).scope("user:read").orThrow();
     *     return ResponseEntity.ok(userService.findById(id));
     * }
     * }</pre>
     *
     * @param authorizationHeader the full header value, e.g. {@code "Bearer eyJhbG..."}
     * @see #authorize(String)
     */
    public AuthorizationChain authorizeFromHeader(String authorizationHeader) {
        return new AuthorizationChain(tokenValidator.validateFromHeader(authorizationHeader));
    }

    // ── Client Credentials ───────────────────────────────────────

    /**
     * Acquires a service token with the given scopes via {@code client_credentials} grant.
     *
     * <p>Use for machine-to-machine calls where each target service requires different scopes.
     * Tokens are cached per scope-set and refreshed automatically before expiry.</p>
     *
     * <pre>{@code
     * // Order Service calls User Service
     * ServiceToken token = sdk.acquireServiceToken(Set.of("user:read"));
     * httpClient.header("Authorization", "Bearer " + token.accessToken());
     *
     * // Same service, different scopes for different targets
     * ServiceToken userToken = sdk.acquireServiceToken(Set.of("user:read"));
     * ServiceToken billingToken = sdk.acquireServiceToken(Set.of("billing:read"));
     * }</pre>
     *
     * @param scopes OAuth 2.1 scopes to request
     * @return cached or freshly acquired service token
     * @throws IllegalStateException if {@code clientSecret} is not configured
     */
    public ServiceToken acquireServiceToken(Set<OAuthScope> scopes) {
        return requireCredentialsClient().acquire(scopes);
    }

    // ── Internal ─────────────────────────────────────────────────

    private ClientCredentialsClient requireCredentialsClient() {
        if (clientCredentialsClient == null) {
            throw new IllegalStateException(
                    "Client credentials not available — clientSecret must be configured");
        }
        return clientCredentialsClient;
    }
}
