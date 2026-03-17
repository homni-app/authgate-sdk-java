package io.authgate.application.port;

import io.authgate.domain.model.DiscoveredEndpoints;

/**
 * Outbound port for OIDC endpoint discovery.
 */
public interface EndpointDiscovery {

    DiscoveredEndpoints discover();
}
