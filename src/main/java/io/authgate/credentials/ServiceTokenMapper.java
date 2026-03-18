package io.authgate.credentials;

import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.ServiceToken;

import java.time.Instant;
import java.util.Map;

/**
 * Maps an OAuth 2.1 token response to a domain {@link ServiceToken}.
 */
final class ServiceTokenMapper {

    private ServiceTokenMapper() {}

    /**
     * Creates a {@code ServiceToken} from a standard OAuth 2.1 token response body.
     *
     * @throws IdentityProviderException if {@code access_token} is missing or not a string
     */
    static ServiceToken fromTokenResponse(Map<String, Object> body) {
        var accessToken = body.get("access_token");
        if (accessToken == null) {
            throw new IdentityProviderException("Missing 'access_token' in token response");
        }

        long expiresInSeconds = body.containsKey("expires_in")
                ? ((Number) body.get("expires_in")).longValue()
                : 3600;

        return new ServiceToken(accessToken.toString(), Instant.now().plusSeconds(expiresInSeconds));
    }
}
