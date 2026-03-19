package io.authgate.credentials;

import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.ServiceToken;

import java.util.Map;
import java.util.Objects;

/**
 * Shared client for the OAuth 2.1 token endpoint.
 *
 * <p>Encapsulates the common flow: resolve endpoint via OIDC discovery →
 * POST form parameters → validate HTTP response → map to {@link ServiceToken}.
 * Grant-specific clients ({@code ClientCredentialsClient}, future {@code TokenExchangeClient})
 * build their own parameter maps and delegate here.</p>
 */
public final class TokenEndpointClient {

    private final EndpointDiscovery endpointDiscovery;
    private final HttpTransport transport;

    public TokenEndpointClient(EndpointDiscovery endpointDiscovery, HttpTransport transport) {
        this.endpointDiscovery = Objects.requireNonNull(endpointDiscovery);
        this.transport = Objects.requireNonNull(transport);
    }

    /**
     * Posts form parameters to the token endpoint and returns the parsed token.
     *
     * @param grantType grant type name for error messages (e.g. {@code "client_credentials"})
     * @param params    form parameters to POST
     * @return parsed service token — never {@code null}
     * @throws IdentityProviderException on HTTP failure or OAuth error response
     */
    public ServiceToken requestToken(String grantType, Map<String, String> params) {
        String tokenEndpoint = endpointDiscovery.discover().tokenEndpoint.value();
        HttpTransport.TransportResponse response = transport.postForm(tokenEndpoint, params);

        if (!response.isSuccessful()) {
            throw new IdentityProviderException(
                    grantType + " grant failed with HTTP " + response.statusCode());
        }

        Map<String, Object> body = response.body();
        Object error = body.get("error");
        if (error != null) {
            throw new IdentityProviderException(
                    grantType + " grant failed: " + error + " — "
                            + body.getOrDefault("error_description", ""));
        }

        return ServiceTokenMapper.fromTokenResponse(body);
    }
}
