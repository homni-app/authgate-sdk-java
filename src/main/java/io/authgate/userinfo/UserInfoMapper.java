package io.authgate.userinfo;

import io.authgate.domain.exception.IdentityProviderException;
import io.authgate.domain.model.UserInfo;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Maps a raw JSON response from the OIDC UserInfo endpoint to a {@link UserInfo} domain model.
 */
final class UserInfoMapper {

    private static final Set<String> STANDARD_CLAIMS = Set.of(
            "sub", "email", "email_verified", "name", "given_name", "family_name",
            "preferred_username", "picture", "locale", "zoneinfo",
            "phone_number", "phone_number_verified", "updated_at"
    );

    private UserInfoMapper() {}

    static UserInfo fromResponse(Map<String, Object> body) {
        String subject = optionalString(body, "sub");
        if (subject == null || subject.isBlank()) {
            throw new IdentityProviderException("Missing 'sub' claim in UserInfo response");
        }

        Map<String, Object> custom = new LinkedHashMap<>();
        for (Map.Entry<String, Object> entry : body.entrySet()) {
            if (!STANDARD_CLAIMS.contains(entry.getKey())) {
                custom.put(entry.getKey(), entry.getValue());
            }
        }

        return new UserInfo(
                subject,
                optionalString(body, "email"),
                optionalBoolean(body, "email_verified"),
                optionalString(body, "name"),
                optionalString(body, "given_name"),
                optionalString(body, "family_name"),
                optionalString(body, "preferred_username"),
                optionalString(body, "picture"),
                optionalString(body, "locale"),
                optionalString(body, "zoneinfo"),
                optionalString(body, "phone_number"),
                optionalBoolean(body, "phone_number_verified"),
                optionalInstant(body, "updated_at"),
                custom
        );
    }

    private static String optionalString(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return switch (val) {
            case String s -> s;
            case null -> null;
            default -> val.toString();
        };
    }

    private static Boolean optionalBoolean(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return switch (val) {
            case Boolean b -> b;
            case String s -> Boolean.parseBoolean(s);
            case null -> null;
            default -> null;
        };
    }

    private static Instant optionalInstant(Map<String, Object> map, String key) {
        Object val = map.get(key);
        return switch (val) {
            case Number n -> Instant.ofEpochSecond(n.longValue());
            case String s -> Instant.ofEpochSecond(Long.parseLong(s));
            case null -> null;
            default -> null;
        };
    }
}
