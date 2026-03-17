package io.authgate.config;

import java.time.Duration;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;

/**
 * Immutable SDK configuration.
 *
 * <p>Only {@code issuerUri} and {@code clientId} are required.
 * All OIDC endpoints are resolved automatically via
 * {@code {issuerUri}/.well-known/openid-configuration}.</p>
 *
 * <h2>Minimal configuration:</h2>
 * <pre>{@code
 * var config = new AuthGateConfiguration.Builder()
 *     .issuerUri("https://idp.example.com/realms/my-realm/")
 *     .clientId("my-client")
 *     .build();
 * }</pre>
 */
public final class AuthGateConfiguration {

    private final String issuerUri;
    private final String clientId;
    private final String clientSecret;
    private final String audience;
    private final Set<String> defaultScopes;
    private final Duration httpTimeout;
    private final Duration discoveryTtl;
    private final Duration clockSkewTolerance;
    private final boolean requireHttps;
    private final String delegationHeaderName;
    private final String delegationScope;
    private final String filterTokenAttribute;

    private AuthGateConfiguration(Builder builder) {
        this.issuerUri = Objects.requireNonNull(builder.issuerUri, "issuerUri must not be null");
        this.clientId = Objects.requireNonNull(builder.clientId, "clientId must not be null");
        this.clientSecret = builder.clientSecret;
        this.audience = builder.audience;
        this.defaultScopes = Objects.requireNonNullElse(builder.defaultScopes, Set.of("openid", "profile", "email"));
        this.httpTimeout = Objects.requireNonNullElse(builder.httpTimeout, Duration.ofSeconds(10));
        this.discoveryTtl = Objects.requireNonNullElse(builder.discoveryTtl, Duration.ofHours(1));
        this.clockSkewTolerance = Objects.requireNonNullElse(builder.clockSkewTolerance, Duration.ofSeconds(30));
        this.requireHttps = builder.requireHttps;
        this.delegationHeaderName = Objects.requireNonNullElse(builder.delegationHeaderName, "X-Acting-Subject");
        this.delegationScope = Objects.requireNonNullElse(builder.delegationScope, "service:delegate");
        this.filterTokenAttribute = Objects.requireNonNullElse(builder.filterTokenAttribute, "io.authgate.validated.token");
    }

    // ── Tell Don't Ask ────────────────────────────────────────────

    public void describeIssuerUriTo(Consumer<String> consumer) { consumer.accept(issuerUri); }
    public void describeClientIdTo(Consumer<String> consumer) { consumer.accept(clientId); }
    public void describeClientSecretTo(Consumer<String> consumer) { if (clientSecret != null) consumer.accept(clientSecret); }
    public void describeAudienceTo(Consumer<String> consumer) { if (audience != null) consumer.accept(audience); }
    public void describeDefaultScopesTo(Consumer<Set<String>> consumer) { consumer.accept(defaultScopes); }
    public void describeHttpTimeoutTo(Consumer<Duration> consumer) { consumer.accept(httpTimeout); }
    public void describeDiscoveryTtlTo(Consumer<Duration> consumer) { consumer.accept(discoveryTtl); }
    public void describeClockSkewToleranceTo(Consumer<Duration> consumer) { consumer.accept(clockSkewTolerance); }
    public void describeRequireHttpsTo(Consumer<Boolean> consumer) { consumer.accept(requireHttps); }
    public void describeDelegationHeaderNameTo(Consumer<String> consumer) { consumer.accept(delegationHeaderName); }
    public void describeDelegationScopeTo(Consumer<String> consumer) { consumer.accept(delegationScope); }
    public void describeFilterTokenAttributeTo(Consumer<String> consumer) { consumer.accept(filterTokenAttribute); }

    boolean isConfidentialClient() {
        return clientSecret != null && !clientSecret.isBlank();
    }

    public static final class Builder {
        private String issuerUri;
        private String clientId;
        private String clientSecret;
        private String audience;
        private Set<String> defaultScopes;
        private Duration httpTimeout;
        private Duration discoveryTtl;
        private Duration clockSkewTolerance;
        private boolean requireHttps;
        private String delegationHeaderName;
        private String delegationScope;
        private String filterTokenAttribute;

        public Builder() {}

        public Builder issuerUri(String v)                { this.issuerUri = v; return this; }
        public Builder clientId(String v)                 { this.clientId = v; return this; }
        public Builder clientSecret(String v)             { this.clientSecret = v; return this; }
        public Builder audience(String v)                 { this.audience = v; return this; }
        public Builder defaultScopes(Set<String> v)       { this.defaultScopes = v; return this; }
        public Builder httpTimeout(Duration v)            { this.httpTimeout = v; return this; }
        public Builder discoveryTtl(Duration v)           { this.discoveryTtl = v; return this; }
        public Builder clockSkewTolerance(Duration v)     { this.clockSkewTolerance = v; return this; }
        public Builder requireHttps(boolean v)            { this.requireHttps = v; return this; }
        public Builder delegationHeaderName(String v)     { this.delegationHeaderName = v; return this; }
        public Builder delegationScope(String v)          { this.delegationScope = v; return this; }
        public Builder filterTokenAttribute(String v)     { this.filterTokenAttribute = v; return this; }

        public AuthGateConfiguration build() {
            return new AuthGateConfiguration(this);
        }
    }
}
