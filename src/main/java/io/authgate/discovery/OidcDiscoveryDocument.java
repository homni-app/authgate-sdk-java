package io.authgate.discovery;

import io.authgate.domain.exception.IdentityProviderException;

import java.util.Map;

/**
 * OIDC Discovery document (RFC 8414).
 * Parsed from {@code {issuer}/.well-known/openid-configuration}.
 * Immutable once created — refresh by replacing the instance.
 */
final class OidcDiscoveryDocument {

    final String issuer;
    final String tokenEndpoint;
    final String jwksUri;
    final String userInfoEndpoint;

    OidcDiscoveryDocument(Map<String, Object> raw) {
        this.issuer = requireString(raw, "issuer");
        this.tokenEndpoint = requireString(raw, "token_endpoint");
        this.jwksUri = requireString(raw, "jwks_uri");
        this.userInfoEndpoint = optionalString(raw, "userinfo_endpoint");
    }

    private String requireString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        if (val == null) {
            throw new IdentityProviderException("OIDC discovery document missing required field: " + key);
        }
        return val.toString();
    }

    private String optionalString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : null;
    }

}
