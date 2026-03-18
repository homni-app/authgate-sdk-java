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
        Object accessToken = body.get("access_token");
        if (accessToken == null) {
            throw new IdentityProviderException("Missing 'access_token' in token response");
        }

        long expiresInSeconds = parseExpiresIn(body.get("expires_in"));

        return new ServiceToken(accessToken.toString(), Instant.now().plusSeconds(expiresInSeconds));
    }

    private static long parseExpiresIn(Object value) {
        return switch (value) {
            case Number n -> n.longValue();
            case String s -> {
                try {
                    yield Long.parseLong(s);
                } catch (NumberFormatException e) {
                    throw new IdentityProviderException(
                            "Invalid 'expires_in' value in token response: " + s, e);
                }
            }
            case null -> 3600L;
            default -> 3600L;
        };
    }
}
