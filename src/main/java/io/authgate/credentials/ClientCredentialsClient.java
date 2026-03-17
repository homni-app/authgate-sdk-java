package io.authgate.credentials;

import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.TokenInfo;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.atomic.AtomicReference;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Acquires and caches service tokens via OAuth 2.1 {@code client_credentials} grant.
 *
 * <p>Thread-safe. Automatically refreshes the token before expiry.</p>
 */
public final class ClientCredentialsClient {

    private static final Logger log = LoggerFactory.getLogger(ClientCredentialsClient.class);
    private static final Duration REFRESH_MARGIN = Duration.ofSeconds(30);

    private final EndpointDiscovery endpointDiscovery;
    private final HttpTransport transport;
    private final String clientId;
    private final String clientSecret;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final Map<String, CachedToken> tokenCache = new HashMap<>();

    public ClientCredentialsClient(
            EndpointDiscovery endpointDiscovery,
            HttpTransport transport,
            String clientId,
            String clientSecret
    ) {
        this.endpointDiscovery = Objects.requireNonNull(endpointDiscovery);
        this.transport = Objects.requireNonNull(transport);
        this.clientId = Objects.requireNonNull(clientId);
        if (clientSecret == null || clientSecret.isBlank()) {
            throw new IllegalArgumentException("client_credentials grant requires a client secret");
        }
        this.clientSecret = clientSecret;
    }

    /**
     * Acquires a service token with the given scopes.
     * Returns a cached token if still valid; fetches a new one otherwise.
     */
    public TokenInfo acquireToken(Set<String> scopes) {
        var cacheKey = String.join(" ", new TreeSet<>(scopes));

        // Fast path: read lock
        lock.readLock().lock();
        try {
            var cached = tokenCache.get(cacheKey);
            if (cached != null && !cached.needsRefresh()) {
                return cached.token();
            }
        } finally {
            lock.readLock().unlock();
        }

        // Slow path: write lock, re-check, fetch
        lock.writeLock().lock();
        try {
            var cached = tokenCache.get(cacheKey);
            if (cached != null && !cached.needsRefresh()) {
                return cached.token();
            }

            var token = fetchToken(scopes);
            tokenCache.put(cacheKey, new CachedToken(token, resolveRefreshAt(token)));
            log.info("Service token acquired for scopes: {}", cacheKey);
            return token;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private TokenInfo fetchToken(Set<String> scopes) {
        var endpoints = endpointDiscovery.discover();
        var endpointRef = new AtomicReference<String>();
        endpoints.describeTokenEndpointTo(endpointRef::set);

        var params = new LinkedHashMap<String, String>();
        params.put("grant_type", "client_credentials");
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("scope", String.join(" ", scopes));

        var response = transport.postForm(endpointRef.get(), params);

        if (!response.isSuccessful()) {
            throw new IdentityProviderException(
                    "client_credentials grant failed with HTTP " + response.statusCode());
        }

        var body = response.body();
        var error = body.get("error");
        if (error != null) {
            throw new IdentityProviderException(
                    "client_credentials grant failed: " + error + " — " + body.getOrDefault("error_description", "")
            );
        }

        return new TokenInfo.Builder()
                .accessToken(requireString(body, "access_token"))
                .expiresInSeconds(body.containsKey("expires_in") ? requireLong(body, "expires_in") : 3600)
                .tokenType(body.getOrDefault("token_type", "Bearer").toString())
                .build();
    }

    private String requireString(Map<String, Object> m, String key) {
        var v = m.get(key);
        if (v == null) throw new IdentityProviderException("Missing '" + key + "' in token response");
        return v.toString();
    }

    private long requireLong(Map<String, Object> m, String key) {
        var v = m.get(key);
        if (v == null) throw new IdentityProviderException("Missing '" + key + "' in token response");
        return v instanceof Number n ? n.longValue() : Long.parseLong(v.toString());
    }

    private record CachedToken(TokenInfo token, Instant refreshAt) {
        boolean needsRefresh() {
            return Instant.now().isAfter(refreshAt);
        }
    }

    private Instant resolveRefreshAt(TokenInfo token) {
        var result = new AtomicReference<>(Instant.now().plus(Duration.ofHours(1)));
        token.describeExpiresInTo(exp -> result.set(Instant.now().plus(exp).minus(REFRESH_MARGIN)));
        return result.get();
    }
}
