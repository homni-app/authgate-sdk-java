package io.authgate;

import io.authgate.config.AuthGateConfiguration;
import io.authgate.credentials.ClientCredentialsClient;
import io.authgate.discovery.OidcDiscoveryClient;
import io.authgate.domain.model.DelegationContext;
import io.authgate.domain.model.IssuerUri;
import io.authgate.domain.model.TokenInfo;
import io.authgate.domain.model.ValidatedToken;
import io.authgate.domain.model.ValidationOutcome;
import io.authgate.domain.service.DelegationPolicy;
import io.authgate.domain.service.TokenValidationRules;
import io.authgate.filter.BearerTokenFilter;
import io.authgate.http.DefaultHttpTransport;
import io.authgate.validation.TokenValidator;

import java.time.Duration;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

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
 *     case ValidationOutcome.Rejected r -> r.describeReasonTo(log::warn);
 * }
 * }</pre>
 */
public final class AuthGate {

    private final TokenValidator tokenValidator;
    private final OidcDiscoveryClient discoveryClient;
    private final DefaultHttpTransport transport;
    private final DelegationPolicy delegationPolicy;
    private final String clientId;
    private final String clientSecret;
    private final String filterTokenAttribute;
    private volatile ClientCredentialsClient clientCredentialsClient;

    public AuthGate(AuthGateConfiguration config) {
        Objects.requireNonNull(config);

        var issuerUriStr = new AtomicReference<String>();
        var clientIdStr = new AtomicReference<String>();
        var clientSecretStr = new AtomicReference<String>();
        var audienceStr = new AtomicReference<String>();
        var httpTimeout = new AtomicReference<Duration>();
        var discoveryTtl = new AtomicReference<Duration>();
        var clockSkew = new AtomicReference<Duration>();
        var requireHttps = new AtomicReference<Boolean>();
        var delegationHeader = new AtomicReference<String>();
        var delegationScope = new AtomicReference<String>();
        var filterAttr = new AtomicReference<String>();

        config.describeIssuerUriTo(issuerUriStr::set);
        config.describeClientIdTo(clientIdStr::set);
        config.describeClientSecretTo(clientSecretStr::set);
        config.describeAudienceTo(audienceStr::set);
        config.describeHttpTimeoutTo(httpTimeout::set);
        config.describeDiscoveryTtlTo(discoveryTtl::set);
        config.describeClockSkewToleranceTo(clockSkew::set);
        config.describeRequireHttpsTo(requireHttps::set);
        config.describeDelegationHeaderNameTo(delegationHeader::set);
        config.describeDelegationScopeTo(delegationScope::set);
        config.describeFilterTokenAttributeTo(filterAttr::set);

        var issuerUri = new IssuerUri(issuerUriStr.get(), requireHttps.get());
        this.transport = new DefaultHttpTransport(httpTimeout.get());
        this.discoveryClient = new OidcDiscoveryClient(issuerUri, transport, discoveryTtl.get());

        var validationRules = new TokenValidationRules(issuerUri, audienceStr.get(), clockSkew.get());
        this.tokenValidator = new TokenValidator(discoveryClient, validationRules);
        this.delegationPolicy = new DelegationPolicy(delegationScope.get(), delegationHeader.get());
        this.clientId = clientIdStr.get();
        this.clientSecret = clientSecretStr.get();
        this.filterTokenAttribute = filterAttr.get();
    }

    // ── Behavioral Methods ───────────────────────────────────────

    /**
     * Validates a raw JWT string.
     */
    public ValidationOutcome validateToken(String rawJwt) {
        return tokenValidator.validate(rawJwt);
    }

    /**
     * Validates from an Authorization header ("Bearer xxx").
     */
    public ValidationOutcome validateTokenFromHeader(String authorizationHeader) {
        return tokenValidator.validateFromHeader(authorizationHeader);
    }

    /**
     * Evaluates delegation context.
     */
    public Optional<DelegationContext> evaluateDelegation(ValidatedToken token, String onBehalfOfHeader) {
        return delegationPolicy.evaluate(token, onBehalfOfHeader);
    }

    /**
     * Acquires a service token with the given scopes via client_credentials grant.
     * Lazy-initialized — requires a client secret to be configured.
     */
    public TokenInfo acquireClientToken(Set<String> scopes) {
        return ensureClientCredentials().acquireToken(scopes);
    }

    /**
     * Creates a servlet filter that protects endpoints with token validation.
     *
     * @param excludedPaths paths that do NOT require authentication (e.g. "/health", "/public")
     */
    public BearerTokenFilter createFilter(Set<String> excludedPaths) {
        return new BearerTokenFilter(tokenValidator, excludedPaths, filterTokenAttribute);
    }

    public BearerTokenFilter createFilter() {
        return new BearerTokenFilter(tokenValidator, Set.of(), filterTokenAttribute);
    }

    // ── Internal ─────────────────────────────────────────────────

    private ClientCredentialsClient ensureClientCredentials() {
        if (clientCredentialsClient == null) {
            synchronized (this) {
                if (clientCredentialsClient == null) {
                    clientCredentialsClient = new ClientCredentialsClient(
                            discoveryClient, transport, clientId, clientSecret
                    );
                }
            }
        }
        return clientCredentialsClient;
    }
}
