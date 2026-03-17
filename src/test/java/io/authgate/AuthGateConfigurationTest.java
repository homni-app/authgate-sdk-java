package io.authgate;

import io.authgate.config.AuthGateConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthGateConfigurationTest {

    @Test
    @DisplayName("Builder explicit values take highest priority")
    void explicitValuesWin() {
        var config = new AuthGateConfiguration.Builder()
                .issuerUri("https://custom.example.com/oidc/")
                .clientId("my-client")
                .clientSecret("secret")
                .audience("my-audience")
                .defaultScopes(Set.of("openid", "custom"))
                .build();

        var sdk = new AuthGate(config);
        assertThat(sdk).isNotNull();
    }

    @Test
    @DisplayName("Builder requires issuerUri")
    void requiresIssuerUri() {
        assertThatThrownBy(() -> new AuthGateConfiguration.Builder()
                .clientId("test")
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("issuerUri");
    }

    @Test
    @DisplayName("Builder requires clientId")
    void requiresClientId() {
        assertThatThrownBy(() -> new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientId");
    }

    @Test
    @DisplayName("Config describes values through consumers")
    void describesValuesThroughConsumers() {
        var config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("my-client")
                .audience("my-audience")
                .build();

        var issuerUri = new String[1];
        var clientId = new String[1];
        var audience = new String[1];
        config.describeIssuerUriTo(v -> issuerUri[0] = v);
        config.describeClientIdTo(v -> clientId[0] = v);
        config.describeAudienceTo(v -> audience[0] = v);

        assertThat(issuerUri[0]).isEqualTo("https://sso.example.com/");
        assertThat(clientId[0]).isEqualTo("my-client");
        assertThat(audience[0]).isEqualTo("my-audience");
    }

    @Test
    @DisplayName("Optional fields are only described when present")
    void optionalFieldsSkippedWhenNull() {
        var config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .build();

        var secretCalled = new boolean[1];
        var audienceCalled = new boolean[1];
        config.describeClientSecretTo(v -> secretCalled[0] = true);
        config.describeAudienceTo(v -> audienceCalled[0] = true);

        assertThat(secretCalled[0]).isFalse();
        assertThat(audienceCalled[0]).isFalse();
    }

    @Test
    @DisplayName("New config fields have sensible defaults")
    void newFieldsHaveDefaults() {
        var config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .build();

        var clockSkew = new Duration[1];
        var requireHttps = new boolean[1];
        var delegationHeader = new String[1];
        var delegationScope = new String[1];
        var filterAttr = new String[1];

        config.describeClockSkewToleranceTo(v -> clockSkew[0] = v);
        config.describeRequireHttpsTo(v -> requireHttps[0] = v);
        config.describeDelegationHeaderNameTo(v -> delegationHeader[0] = v);
        config.describeDelegationScopeTo(v -> delegationScope[0] = v);
        config.describeFilterTokenAttributeTo(v -> filterAttr[0] = v);

        assertThat(clockSkew[0]).isEqualTo(Duration.ofSeconds(30));
        assertThat(requireHttps[0]).isFalse();
        assertThat(delegationHeader[0]).isEqualTo("X-Acting-Subject");
        assertThat(delegationScope[0]).isEqualTo("service:delegate");
        assertThat(filterAttr[0]).isEqualTo("io.authgate.validated.token");
    }

    @Test
    @DisplayName("New config fields are customizable")
    void newFieldsAreCustomizable() {
        var config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .clockSkewTolerance(Duration.ofMinutes(2))
                .requireHttps(true)
                .delegationHeaderName("X-Custom-Acting")
                .delegationScope("custom:delegate")
                .filterTokenAttribute("custom.token.attr")
                .build();

        var clockSkew = new Duration[1];
        var requireHttps = new boolean[1];
        var delegationHeader = new String[1];
        var delegationScope = new String[1];
        var filterAttr = new String[1];

        config.describeClockSkewToleranceTo(v -> clockSkew[0] = v);
        config.describeRequireHttpsTo(v -> requireHttps[0] = v);
        config.describeDelegationHeaderNameTo(v -> delegationHeader[0] = v);
        config.describeDelegationScopeTo(v -> delegationScope[0] = v);
        config.describeFilterTokenAttributeTo(v -> filterAttr[0] = v);

        assertThat(clockSkew[0]).isEqualTo(Duration.ofMinutes(2));
        assertThat(requireHttps[0]).isTrue();
        assertThat(delegationHeader[0]).isEqualTo("X-Custom-Acting");
        assertThat(delegationScope[0]).isEqualTo("custom:delegate");
        assertThat(filterAttr[0]).isEqualTo("custom.token.attr");
    }
}
