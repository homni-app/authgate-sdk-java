package io.authgate.domain.model;

import java.net.URI;
import java.util.Objects;

/**
 * Value Object for a validated OIDC endpoint URL.
 * Guarantees non-null, non-blank, valid URI with scheme and host.
 */
public final class EndpointUrl {

    private final String url;

    public EndpointUrl(String url) {
        Objects.requireNonNull(url, "Endpoint URL must not be null");
        if (url.isBlank()) {
            throw new IllegalArgumentException("Endpoint URL must not be blank");
        }
        URI uri = URI.create(url);
        if (uri.getScheme() == null || uri.getHost() == null) {
            throw new IllegalArgumentException(
                    "Endpoint URL must have scheme and host: " + url);
        }
        this.url = url;
    }

    public String value() {
        return url;
    }

    public String host() {
        return URI.create(url).getHost();
    }

    @Override
    public boolean equals(Object o) {
        return this == o || (o instanceof EndpointUrl other && url.equals(other.url));
    }

    @Override
    public int hashCode() {
        return url.hashCode();
    }

    @Override
    public String toString() {
        return url;
    }
}
