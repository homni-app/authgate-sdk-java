package io.authgate.userinfo;

import io.authgate.application.port.CacheStore;
import io.authgate.application.port.EndpointDiscovery;
import io.authgate.application.port.HttpTransport;
import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.DiscoveredEndpoints;
import io.authgate.domain.model.UserInfo;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.util.HexFormat;
import java.util.Map;
import java.util.Objects;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Fetches and caches OIDC UserInfo responses.
 *
 * <p>Thread-safe — all mutable state is in {@link CacheStore}.</p>
 */
public final class UserInfoClient {

    private static final String CACHE_PREFIX = "authgate:userinfo:";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};

    private final EndpointDiscovery discovery;
    private final HttpTransport transport;
    private final CacheStore cacheStore;
    private final Duration cacheTtl;

    public UserInfoClient(EndpointDiscovery discovery, HttpTransport transport,
                          CacheStore cacheStore, Duration cacheTtl) {
        this.discovery  = Objects.requireNonNull(discovery);
        this.transport  = Objects.requireNonNull(transport);
        this.cacheStore = Objects.requireNonNull(cacheStore);
        this.cacheTtl   = Objects.requireNonNull(cacheTtl);
    }

    public UserInfo fetch(String accessToken) {
        Objects.requireNonNull(accessToken, "accessToken must not be null");

        String cacheKey = CACHE_PREFIX + sha256Hex(accessToken);

        String cached = cacheStore.get(cacheKey);
        if (cached != null) {
            return UserInfoMapper.fromResponse(deserialize(cached));
        }

        DiscoveredEndpoints endpoints = discovery.discover();
        if (!endpoints.hasUserInfoEndpoint()) {
            throw new IdentityProviderException(
                    "Identity provider does not advertise a userinfo_endpoint");
        }

        String url = endpoints.userInfoEndpoint.value();
        HttpTransport.TransportResponse response = transport.fetchJsonWithBearer(url, accessToken);

        if (!response.isSuccessful()) {
            String error = optionalString(response.body(), "error");
            String description = optionalString(response.body(), "error_description");
            throw new IdentityProviderException(
                    "UserInfo request failed with HTTP " + response.statusCode()
                            + " (" + error + "): " + description);
        }

        cacheStore.put(cacheKey, serialize(response.body()), cacheTtl);
        return UserInfoMapper.fromResponse(response.body());
    }

    private static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    private static String serialize(Map<String, Object> body) {
        try {
            return MAPPER.writeValueAsString(body);
        } catch (JsonProcessingException e) {
            throw new IdentityProviderException("Failed to serialize UserInfo response", e);
        }
    }

    private static Map<String, Object> deserialize(String json) {
        try {
            return MAPPER.readValue(json, MAP_TYPE);
        } catch (JsonProcessingException e) {
            throw new IdentityProviderException("Failed to deserialize cached UserInfo", e);
        }
    }

    private static String optionalString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return val != null ? val.toString() : null;
    }
}
