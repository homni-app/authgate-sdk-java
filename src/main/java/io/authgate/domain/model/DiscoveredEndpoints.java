package io.authgate.domain.model;

import java.util.Objects;

/**
 * Value object representing discovered OIDC endpoints from an Identity Provider.
 *
 * <p>Contains the three essential endpoints resolved from
 * {@code {issuerUri}/.well-known/openid-configuration}.</p>
 */
public record DiscoveredEndpoints(IssuerUri issuerUri, EndpointUrl tokenEndpoint, EndpointUrl jwksUri) {

    public DiscoveredEndpoints {
        Objects.requireNonNull(issuerUri);
        Objects.requireNonNull(tokenEndpoint);
        Objects.requireNonNull(jwksUri);
    }
}
