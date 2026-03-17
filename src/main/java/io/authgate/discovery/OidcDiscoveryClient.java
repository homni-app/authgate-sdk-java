package io.authgate.discovery;

import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.DiscoveredEndpoints;
import io.authgate.domain.model.IssuerUri;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.Objects;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * Fetches and caches the OIDC Discovery document from
 * {@code {issuerUri}/.well-known/openid-configuration}.
 *
 * <p>Thread-safe. Uses read-write lock for concurrent access with lazy refresh.</p>
 */
public final class OidcDiscoveryClient implements EndpointDiscovery {

    private static final Logger log = LoggerFactory.getLogger(OidcDiscoveryClient.class);
    private static final Duration DEFAULT_TTL = Duration.ofHours(1);
    private static final String WELL_KNOWN_PATH = ".well-known/openid-configuration";

    private final IssuerUri issuerUri;
    private final HttpTransport transport;
    private final Duration cacheTtl;

    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private volatile OidcDiscoveryDocument cached;

    public OidcDiscoveryClient(IssuerUri issuerUri, HttpTransport transport, Duration cacheTtl) {
        this.issuerUri = Objects.requireNonNull(issuerUri);
        this.transport = Objects.requireNonNull(transport);
        this.cacheTtl = Objects.requireNonNullElse(cacheTtl, DEFAULT_TTL);
    }

    public OidcDiscoveryClient(IssuerUri issuerUri, HttpTransport transport) {
        this(issuerUri, transport, DEFAULT_TTL);
    }

    @Override
    public DiscoveredEndpoints discover() {
        var doc = resolveDocument();
        return new DiscoveredEndpoints(
                new IssuerUri(doc.resolveIssuer()),
                doc.resolveTokenEndpoint(),
                doc.resolveJwksUri()
        );
    }

    /**
     * Forces a refresh of the cached discovery document.
     */
    public DiscoveredEndpoints refresh() {
        lock.writeLock().lock();
        try {
            cached = fetchDiscoveryDocument();
            return new DiscoveredEndpoints(
                    new IssuerUri(cached.resolveIssuer()),
                    cached.resolveTokenEndpoint(),
                    cached.resolveJwksUri()
            );
        } finally {
            lock.writeLock().unlock();
        }
    }

    private OidcDiscoveryDocument resolveDocument() {
        // Fast path: read lock, check cache
        lock.readLock().lock();
        try {
            if (cached != null && !cached.isExpired(cacheTtl)) {
                return cached;
            }
        } finally {
            lock.readLock().unlock();
        }

        // Slow path: write lock, re-check, fetch
        lock.writeLock().lock();
        try {
            if (cached != null && !cached.isExpired(cacheTtl)) {
                return cached;
            }
            cached = fetchDiscoveryDocument();
            return cached;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private OidcDiscoveryDocument fetchDiscoveryDocument() {
        var discoveryUrl = issuerUri.resolvePath(WELL_KNOWN_PATH);
        log.debug("Fetching OIDC discovery from: {}", discoveryUrl);

        try {
            var response = transport.fetchJson(discoveryUrl);
            if (!response.isSuccessful()) {
                throw new IdentityProviderException(
                        "OIDC discovery returned HTTP " + response.statusCode() + " from " + discoveryUrl);
            }
            var doc = new OidcDiscoveryDocument(response.body());
            log.info("OIDC discovery loaded from: {}", discoveryUrl);
            return doc;
        } catch (IdentityProviderException e) {
            throw e;
        } catch (Exception e) {
            throw new IdentityProviderException("Failed to fetch OIDC discovery from " + discoveryUrl, e);
        }
    }
}
