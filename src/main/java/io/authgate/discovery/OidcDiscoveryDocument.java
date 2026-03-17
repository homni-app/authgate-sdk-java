package io.authgate.discovery;

import io.authgate.domain.exception.IdentityProviderException;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;

/**
 * Cached OIDC Discovery document (RFC 8414).
 * Parsed from {@code {issuer}/.well-known/openid-configuration}.
 * Immutable once created — refresh by replacing the instance.
 */
final class OidcDiscoveryDocument {

    private final String issuer;
    private final String tokenEndpoint;
    private final String jwksUri;
    private final String authorizationEndpoint;
    private final String userinfoEndpoint;
    private final Instant fetchedAt;

    OidcDiscoveryDocument(Map<String, Object> raw) {
        this.issuer = requireString(raw, "issuer");
        this.tokenEndpoint = requireString(raw, "token_endpoint");
        this.jwksUri = requireString(raw, "jwks_uri");
        this.authorizationEndpoint = optionalString(raw, "authorization_endpoint");
        this.userinfoEndpoint = optionalString(raw, "userinfo_endpoint");
        this.fetchedAt = Instant.now();
    }

    String resolveTokenEndpoint() {
        return tokenEndpoint;
    }

    String resolveJwksUri() {
        return jwksUri;
    }

    String resolveIssuer() {
        return issuer;
    }

    boolean isExpired(Duration ttl) {
        return Instant.now().isAfter(fetchedAt.plus(ttl));
    }

    private String requireString(Map<String, Object> map, String key) {
        var val = map.get(key);
        if (val == null) {
            throw new IdentityProviderException("OIDC discovery document missing required field: " + key);
        }
        return val.toString();
    }

    private String optionalString(Map<String, Object> map, String key) {
        var val = map.get(key);
        return val != null ? val.toString() : null;
    }
}
