package io.authgate.credentials;

import io.authgate.domain.model.OAuthScope;
import io.authgate.domain.model.SecretValue;
import io.authgate.domain.model.ServiceToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Acquires and caches service tokens via OAuth 2.1 {@code client_credentials} grant.
 *
 * <p>Thread-safe. Uses {@link ConcurrentHashMap#compute} for atomic check-and-fetch,
 * preventing thundering herd on cache miss. Tokens live only in process memory.</p>
 */
public final class ClientCredentialsClient {

    private static final Logger log = LoggerFactory.getLogger(ClientCredentialsClient.class);

    private final TokenEndpointClient tokenEndpointClient;
    private final String clientId;
    private final SecretValue clientSecret;
    private final int maxCacheSize;
    private final ConcurrentHashMap<String, ServiceToken> tokenCache = new ConcurrentHashMap<>();

    public ClientCredentialsClient(
            TokenEndpointClient tokenEndpointClient,
            String clientId,
            SecretValue clientSecret,
            int maxCacheSize
    ) {
        this.tokenEndpointClient = Objects.requireNonNull(tokenEndpointClient);
        this.clientId = Objects.requireNonNull(clientId);
        this.clientSecret = Objects.requireNonNull(clientSecret, "client_credentials grant requires a client secret");
        if (maxCacheSize <= 0) {
            throw new IllegalArgumentException("maxCacheSize must be positive");
        }
        this.maxCacheSize = maxCacheSize;
    }

    /**
     * Acquires a service token with the given scopes.
     * Returns a cached token if not expiring soon; fetches a new one otherwise.
     */
    public ServiceToken acquire(Set<OAuthScope> scopes) {
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes must not be empty");
        }

        String scopeKey = scopes.stream()
                .map(OAuthScope::value)
                .sorted()
                .collect(Collectors.joining(" "));

        return tokenCache.compute(scopeKey, (key, cached) -> {
            if (cached != null && !cached.isExpiringSoon()) {
                return cached;
            }
            evictExpiredEntries();
            if (tokenCache.size() >= maxCacheSize) {
                log.warn("Service token cache at capacity ({}), evicting oldest entry", maxCacheSize);
                evictOldest();
            }
            ServiceToken token = fetchToken(scopes);
            log.info("Service token acquired for scopes: {}", key);
            return token;
        });
    }

    private void evictExpiredEntries() {
        tokenCache.entrySet().removeIf(e -> e.getValue().isExpiringSoon());
    }

    private void evictOldest() {
        tokenCache.entrySet().stream()
                .min(Comparator.comparing(e -> e.getValue().expiresAt()))
                .map(Map.Entry::getKey)
                .ifPresent(tokenCache::remove);
    }

    private ServiceToken fetchToken(Set<OAuthScope> scopes) {
        LinkedHashMap<String, String> params = new LinkedHashMap<>();
        params.put("grant_type", "client_credentials");
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret.asString());
        params.put("scope", scopes.stream()
                .map(OAuthScope::value)
                .collect(Collectors.joining(" ")));

        return tokenEndpointClient.requestToken("client_credentials", params);
    }
}
