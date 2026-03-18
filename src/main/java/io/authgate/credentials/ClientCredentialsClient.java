package io.authgate.credentials;

import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.OAuthScope;
import io.authgate.domain.model.ServiceToken;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Acquires and caches service tokens via OAuth 2.1 {@code client_credentials} grant.
 *
 * <p>Thread-safe. Uses {@link ConcurrentHashMap#compute} for atomic check-and-fetch,
 * preventing thundering herd on cache miss. Tokens live only in process memory.</p>
 */
public final class ClientCredentialsClient {

    private static final Logger log = LoggerFactory.getLogger(ClientCredentialsClient.class);
    private static final int MAX_CACHE_SIZE = 64;

    private final EndpointDiscovery endpointDiscovery;
    private final HttpTransport transport;
    private final String clientId;
    private final String clientSecret;
    private final ConcurrentHashMap<String, ServiceToken> tokenCache = new ConcurrentHashMap<>();

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
     * Returns a cached token if not expiring soon; fetches a new one otherwise.
     */
    public ServiceToken acquire(Set<OAuthScope> scopes) {
        Objects.requireNonNull(scopes, "scopes must not be null");
        if (scopes.isEmpty()) {
            throw new IllegalArgumentException("scopes must not be empty");
        }

        var scopeKey = scopes.stream()
                .map(OAuthScope::value)
                .sorted()
                .collect(java.util.stream.Collectors.joining(" "));

        if (tokenCache.size() >= MAX_CACHE_SIZE) {
            log.warn("Service token cache exceeded {} entries, clearing", MAX_CACHE_SIZE);
            tokenCache.clear();
        }

        return tokenCache.compute(scopeKey, (key, cached) -> {
            if (cached != null && !cached.isExpiringSoon()) {
                return cached;
            }
            var token = fetchToken(scopes);
            log.info("Service token acquired for scopes: {}", key);
            return token;
        });
    }

    private ServiceToken fetchToken(Set<OAuthScope> scopes) {
        var tokenEndpoint = endpointDiscovery.discover().tokenEndpoint();

        var params = new LinkedHashMap<String, String>();
        params.put("grant_type", "client_credentials");
        params.put("client_id", clientId);
        params.put("client_secret", clientSecret);
        params.put("scope", scopes.stream()
                .map(OAuthScope::value)
                .collect(java.util.stream.Collectors.joining(" ")));

        var response = transport.postForm(tokenEndpoint, params);

        if (!response.isSuccessful()) {
            throw new IdentityProviderException(
                    "client_credentials grant failed with HTTP " + response.statusCode());
        }

        var body = response.body();
        var error = body.get("error");
        if (error != null) {
            throw new IdentityProviderException(
                    "client_credentials grant failed: " + error + " — "
                            + body.getOrDefault("error_description", ""));
        }

        return ServiceTokenMapper.fromTokenResponse(body);
    }
}
