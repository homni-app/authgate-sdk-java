package io.authgate.domain.model;

import java.util.Objects;
import java.util.function.Consumer;

/**
 * Value Object representing discovered OIDC endpoints from an Identity Provider.
 */
public final class DiscoveredEndpoints {

    private final IssuerUri issuerUri;
    private final String tokenEndpoint;
    private final String jwksUri;

    public DiscoveredEndpoints(IssuerUri issuerUri, String tokenEndpoint, String jwksUri) {
        this.issuerUri = Objects.requireNonNull(issuerUri);
        this.tokenEndpoint = Objects.requireNonNull(tokenEndpoint);
        this.jwksUri = Objects.requireNonNull(jwksUri);
    }

    public void describeIssuerUriTo(Consumer<IssuerUri> consumer) {
        consumer.accept(issuerUri);
    }

    public void describeTokenEndpointTo(Consumer<String> consumer) {
        consumer.accept(tokenEndpoint);
    }

    public void describeJwksUriTo(Consumer<String> consumer) {
        consumer.accept(jwksUri);
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof DiscoveredEndpoints other
                && issuerUri.equals(other.issuerUri)
                && tokenEndpoint.equals(other.tokenEndpoint)
                && jwksUri.equals(other.jwksUri));
    }

    @Override
    public int hashCode() {
        return Objects.hash(issuerUri, tokenEndpoint, jwksUri);
    }

    @Override
    public String toString() {
        return "DiscoveredEndpoints[issuer=" + issuerUri + "]";
    }
}
