package io.authgate;

import io.authgate.application.port.CacheStore;
import io.authgate.application.port.HttpTransport;
import io.authgate.cache.InMemoryCacheStore;
import io.authgate.config.AuthGateConfiguration;
import io.authgate.credentials.ClientCredentialsClient;
import io.authgate.credentials.TokenEndpointClient;
import io.authgate.discovery.OidcDiscoveryClient;
import io.authgate.domain.model.AuthorizationChain;
import io.authgate.domain.model.IssuerUri;
import io.authgate.domain.model.OAuthScope;
import io.authgate.domain.model.ServiceToken;
import io.authgate.domain.model.UserInfo;
import io.authgate.domain.model.ValidationOutcome;
import io.authgate.http.CircuitBreakerHttpTransport;
import io.authgate.http.DefaultHttpTransport;
import io.authgate.userinfo.UserInfoClient;
import io.authgate.validation.NimbusJwtProcessor;
import io.authgate.validation.TokenValidator;

import java.io.Closeable;
import java.io.IOException;
import java.util.Objects;
import java.util.Set;

/**
 * AuthGate SDK — single entry point for standalone (non-Spring) usage.
 *
 * <h2>Minimal setup:</h2>
 * <pre>{@code
 * var sdk = AuthGate.builder(new AuthGateConfiguration.Builder()
 *         .issuerUri("https://idp.example.com/realms/my-realm/")
 *         .clientId("my-client")
 *         .build())
 *     .build();
 * }</pre>
 *
 * <h2>Custom infrastructure:</h2>
 * <pre>{@code
 * var sdk = AuthGate.builder(config)
 *     .cacheStore(redisCacheStore)
 *     .httpTransport(customTransport)
 *     .build();
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
public final class AuthGate implements Closeable {

    private final TokenValidator tokenValidator;
    private final ClientCredentialsClient clientCredentialsClient;
    private final UserInfoClient userInfoClient;
    private final HttpTransport httpTransport;

    private AuthGate(TokenValidator tokenValidator,
                     ClientCredentialsClient clientCredentialsClient,
                     UserInfoClient userInfoClient,
                     HttpTransport httpTransport) {
        this.tokenValidator = tokenValidator;
        this.clientCredentialsClient = clientCredentialsClient;
        this.userInfoClient = userInfoClient;
        this.httpTransport = httpTransport;
    }

    public static Builder builder(AuthGateConfiguration config) {
        return new Builder(config);
    }

    public static final class Builder {

        private final AuthGateConfiguration config;
        private CacheStore cacheStore;
        private HttpTransport httpTransport;

        private Builder(AuthGateConfiguration config) {
            this.config = Objects.requireNonNull(config, "config");
        }

        public Builder cacheStore(CacheStore cacheStore) {
            this.cacheStore = Objects.requireNonNull(cacheStore, "cacheStore");
            return this;
        }

        public Builder httpTransport(HttpTransport httpTransport) {
            this.httpTransport = Objects.requireNonNull(httpTransport, "httpTransport");
            return this;
        }

        public AuthGate build() {
            CacheStore cache = this.cacheStore != null
                    ? this.cacheStore
                    : new InMemoryCacheStore();

            HttpTransport transport = this.httpTransport != null
                    ? this.httpTransport
                    : new DefaultHttpTransport(config.httpTimeout());

            CircuitBreakerHttpTransport circuitBreaker = new CircuitBreakerHttpTransport(
                    transport,
                    config.circuitBreakerFailureThreshold(),
                    config.circuitBreakerResetTimeout());

            IssuerUri issuerUri = new IssuerUri(config.issuerUri(), config.requireHttps());
            OidcDiscoveryClient discoveryClient = new OidcDiscoveryClient(
                    issuerUri, circuitBreaker, cache, config.discoveryTtl());

            NimbusJwtProcessor jwtProcessor = new NimbusJwtProcessor(discoveryClient);
            TokenValidator tokenValidator = new TokenValidator(
                    jwtProcessor, issuerUri, config.audience(), config.clockSkewTolerance());

            TokenEndpointClient tokenEndpointClient = new TokenEndpointClient(
                    discoveryClient, circuitBreaker);

            ClientCredentialsClient clientCredentialsClient = config.clientSecret() != null
                    ? new ClientCredentialsClient(
                            tokenEndpointClient, config.clientId(),
                            config.clientSecret(), config.serviceTokenCacheSize())
                    : null;

            UserInfoClient userInfoClient = new UserInfoClient(
                    discoveryClient, circuitBreaker, cache, config.userInfoCacheTtl());

            return new AuthGate(tokenValidator, clientCredentialsClient, userInfoClient, transport);
        }
    }

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

    // ── UserInfo ─────────────────────────────────────────────────

    /**
     * Fetches OIDC UserInfo claims for the given access token.
     *
     * <p>Calls the Identity Provider's {@code userinfo_endpoint} (discovered automatically)
     * and returns standard OIDC claims (email, name, etc.). Responses are cached
     * to avoid redundant IdP calls.</p>
     *
     * <pre>{@code
     * UserInfo info = sdk.fetchUserInfo(accessToken);
     * String email = info.email();
     * }</pre>
     *
     * @param accessToken a valid OAuth 2.1 access token
     * @return user info claims — never {@code null}
     * @throws io.authgate.domain.exception.IdentityProviderException if the IdP call fails
     *         or the provider does not advertise a userinfo_endpoint
     */
    public UserInfo fetchUserInfo(String accessToken) {
        return userInfoClient.fetch(accessToken);
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

    @Override
    public void close() throws IOException {
        if (httpTransport instanceof Closeable closeable) {
            closeable.close();
        }
    }

    private ClientCredentialsClient requireCredentialsClient() {
        if (clientCredentialsClient == null) {
            throw new IllegalStateException(
                    "Client credentials not available — clientSecret must be configured");
        }
        return clientCredentialsClient;
    }
}
