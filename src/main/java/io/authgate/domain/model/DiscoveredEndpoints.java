package io.authgate.domain.model;

import java.util.Objects;

/**
 * Value object representing discovered OIDC endpoints from an Identity Provider.
 *
 * <p>Contains endpoints resolved from
 * {@code {issuerUri}/.well-known/openid-configuration}.
 * The {@code userInfoEndpoint} is nullable — RECOMMENDED but not REQUIRED per OIDC spec.</p>
 */
public final class DiscoveredEndpoints {

    public final IssuerUri issuerUri;
    public final EndpointUrl tokenEndpoint;
    public final EndpointUrl jwksUri;
    public final EndpointUrl userInfoEndpoint;

    public DiscoveredEndpoints(IssuerUri issuerUri, EndpointUrl tokenEndpoint,
                               EndpointUrl jwksUri, EndpointUrl userInfoEndpoint) {
        this.issuerUri = Objects.requireNonNull(issuerUri);
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint);
        this.jwksUri = Objects.requireNonNull(jwksUri);
        this.userInfoEndpoint = userInfoEndpoint;
    }

    public DiscoveredEndpoints(IssuerUri issuerUri, EndpointUrl tokenEndpoint, EndpointUrl jwksUri) {
        this(issuerUri, tokenEndpoint, jwksUri, null);
    }

    public boolean hasUserInfoEndpoint() {
        return userInfoEndpoint != null;
    }
}
