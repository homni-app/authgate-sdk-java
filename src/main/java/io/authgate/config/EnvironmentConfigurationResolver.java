package io.authgate.config;

/**
 * Resolves SDK configuration from environment variables and system properties.
 *
 * <p>Environment variables use the {@code AUTHGATE_} prefix.
 * {@code issuerUri} and {@code clientId} are required — no default URLs.</p>
 */
public final class EnvironmentConfigurationResolver {

    private static final String ENV_ISSUER_URI = "AUTHGATE_ISSUER_URI";
    private static final String ENV_CLIENT_ID = "AUTHGATE_CLIENT_ID";
    private static final String ENV_CLIENT_SECRET = "AUTHGATE_CLIENT_SECRET";

    public AuthGateConfiguration resolve() {
        return new AuthGateConfiguration.Builder()
                .issuerUri(resolveRequired(ENV_ISSUER_URI, "authgate.issuer-uri"))
                .clientId(resolveRequired(ENV_CLIENT_ID, "authgate.client-id"))
                .clientSecret(resolveOptional(ENV_CLIENT_SECRET, "authgate.client-secret"))
                .build();
    }

    private String resolveRequired(String envVar, String systemProperty) {
        var env = System.getenv(envVar);
        if (env != null && !env.isBlank()) return env;

        var prop = System.getProperty(systemProperty);
        if (prop != null && !prop.isBlank()) return prop;

        throw new IllegalStateException(
                "Required configuration missing: set environment variable " + envVar
                + " or system property " + systemProperty);
    }

    private String resolveOptional(String envVar, String systemProperty) {
        var env = System.getenv(envVar);
        if (env != null && !env.isBlank()) return env;

        var prop = System.getProperty(systemProperty);
        return (prop != null && !prop.isBlank()) ? prop : null;
    }
}
