package io.authgate.discovery;

import io.authgate.domain.exception.IdentityProviderException;

import java.util.Map;

/**
 * OIDC Discovery document (RFC 8414).
 * Parsed from {@code {issuer}/.well-known/openid-configuration}.
 * Immutable once created — refresh by replacing the instance.
 */
final class OidcDiscoveryDocument {

    private final String issuer;
    private final String tokenEndpoint;
    private final String jwksUri;

    OidcDiscoveryDocument(Map<String, Object> raw) {
        this.issuer = requireString(raw, "issuer");
        this.tokenEndpoint = requireString(raw, "token_endpoint");
        this.jwksUri = requireString(raw, "jwks_uri");
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

    private String requireString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val == null) {
            throw new IdentityProviderException("OIDC discovery document missing required field: " + key);
        }
        return val.toString();
    }

}
