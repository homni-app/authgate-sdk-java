package io.authgate.discovery;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.authgate.application.port.CacheStore;
import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.DiscoveredEndpoints;
import io.authgate.domain.model.EndpointUrl;
import io.authgate.domain.model.IssuerUri;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Duration;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.ReentrantLock;

/**
 * Fetches and caches the OIDC Discovery document from
 * {@code {issuerUri}/.well-known/openid-configuration}.
 *
 * <p>Thread-safe. Uses {@link CacheStore} for caching and a {@link ReentrantLock}
 * to prevent thundering herd on cache miss.</p>
 */
public final class OidcDiscoveryClient implements EndpointDiscovery {

    private static final Logger log = LoggerFactory.getLogger(OidcDiscoveryClient.class);
    private static final Duration DEFAULT_TTL = Duration.ofHours(1);
    private static final Duration LOCK_TIMEOUT = Duration.ofSeconds(30);
    private static final String WELL_KNOWN_PATH = ".well-known/openid-configuration";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final IssuerUri issuerUri;
    private final HttpTransport transport;
    private final CacheStore cacheStore;
    private final Duration cacheTtl;
    private final String cacheKey;
    private final ReentrantLock fetchLock = new ReentrantLock();
    private volatile DiscoveredEndpoints cachedEndpoints;

    public OidcDiscoveryClient(IssuerUri issuerUri, HttpTransport transport,
                               CacheStore cacheStore, Duration cacheTtl) {
        this.issuerUri  = Objects.requireNonNull(issuerUri);
        this.transport  = Objects.requireNonNull(transport);
        this.cacheStore = Objects.requireNonNull(cacheStore);
        this.cacheTtl   = Objects.requireNonNullElse(cacheTtl, DEFAULT_TTL);
        this.cacheKey   = "authgate:discovery:" + issuerUri;
    }

    public OidcDiscoveryClient(IssuerUri issuerUri, HttpTransport transport, CacheStore cacheStore) {
        this(issuerUri, transport, cacheStore, DEFAULT_TTL);
    }

    @Override
    public DiscoveredEndpoints discover() {
        DiscoveredEndpoints endpoints = cachedEndpoints;
        if (endpoints != null) {
            return endpoints;
        }
        OidcDiscoveryDocument doc = resolveDocument();

        EndpointUrl tokenEndpoint = new EndpointUrl(doc.resolveTokenEndpoint());
        EndpointUrl jwksUri = new EndpointUrl(doc.resolveJwksUri());
        validateEndpointOrigin(tokenEndpoint, "token_endpoint");
        validateEndpointOrigin(jwksUri, "jwks_uri");

        endpoints = new DiscoveredEndpoints(this.issuerUri, tokenEndpoint, jwksUri);
        cachedEndpoints = endpoints;
        return endpoints;
    }

    private OidcDiscoveryDocument resolveDocument() {
        String json = cacheStore.get(cacheKey);
        if (json != null) {
            return deserialize(json);
        }

        boolean acquired;
        try {
            acquired = fetchLock.tryLock(LOCK_TIMEOUT.toMillis(), TimeUnit.MILLISECONDS);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IdentityProviderException("Interrupted while waiting for OIDC discovery lock");
        }
        if (!acquired) {
            throw new IdentityProviderException(
                    "Timed out waiting for OIDC discovery lock after " + LOCK_TIMEOUT.toSeconds() + "s");
        }
        try {
            json = cacheStore.get(cacheKey);
            if (json != null) {
                return deserialize(json);
            }

            OidcDiscoveryDocument doc = fetchDiscoveryDocument();
            cacheStore.put(cacheKey, serialize(doc), cacheTtl);
            cachedEndpoints = null;
            return doc;
        } finally {
            fetchLock.unlock();
        }
    }

    private OidcDiscoveryDocument fetchDiscoveryDocument() {
        String discoveryUrl = issuerUri.resolvePath(WELL_KNOWN_PATH);
        log.debug("Fetching OIDC discovery from: {}", discoveryUrl);

        try {
            HttpTransport.TransportResponse response = transport.fetchJson(discoveryUrl);
            if (!response.isSuccessful()) {
                throw new IdentityProviderException(
                        "OIDC discovery returned HTTP " + response.statusCode() + " from " + discoveryUrl);
            }
            OidcDiscoveryDocument doc = new OidcDiscoveryDocument(response.body());
            log.info("OIDC discovery loaded from: {}", discoveryUrl);
            return doc;
        } catch (IdentityProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityProviderException("Failed to fetch OIDC discovery from " + discoveryUrl, e);
        }
    }

    private void validateEndpointOrigin(EndpointUrl endpoint, String fieldName) {
        String issuerHost = URI.create(issuerUri.value()).getHost();
        if (!endpoint.host().equals(issuerHost)) {
            throw new IdentityProviderException(
                    "OIDC discovery '" + fieldName + "' host '" + endpoint.host()
                            + "' does not match issuer host '" + issuerHost + "'");
        }
    }

    private String serialize(OidcDiscoveryDocument doc) {
        try {
            return MAPPER.writeValueAsString(Map.of(
                    "issuer", doc.resolveIssuer(),
                    "token_endpoint", doc.resolveTokenEndpoint(),
                    "jwks_uri", doc.resolveJwksUri()
            ));
        } catch (JsonProcessingException e) {
            throw new IdentityProviderException("Failed to serialize discovery document", e);
        }
    }

    private OidcDiscoveryDocument deserialize(String json) {
        try {
            Map<String, Object> map = MAPPER.readValue(json, MAP_TYPE);
            return new OidcDiscoveryDocument(map);
        } catch (JsonProcessingException e) {
            throw new IdentityProviderException("Failed to deserialize discovery document", e);
        }
    }
}
