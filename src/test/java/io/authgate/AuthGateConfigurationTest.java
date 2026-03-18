package io.authgate;

import io.authgate.config.AuthGateConfiguration;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthGateConfigurationTest {

    @Test
    @DisplayName("Builder explicit values take highest priority")
    void explicitValuesWin() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://custom.example.com/oidc/")
                .clientId("my-client")
                .clientSecret("secret")
                .audience("my-audience")
                .build();

        AuthGate sdk = new AuthGate(config);
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
    @DisplayName("Config exposes values through getters")
    void exposesValuesThroughGetters() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("my-client")
                .audience("my-audience")
                .build();

        assertThat(config.issuerUri()).isEqualTo("https://sso.example.com/");
        assertThat(config.clientId()).isEqualTo("my-client");
        assertThat(config.audience()).isEqualTo("my-audience");
    }

    @Test
    @DisplayName("Optional fields return null when not set")
    void optionalFieldsNullWhenNotSet() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .build();

        assertThat(config.clientSecret()).isNull();
        assertThat(config.audience()).isNull();
    }

    @Test
    @DisplayName("New config fields have sensible defaults")
    void newFieldsHaveDefaults() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .build();

        assertThat(config.clockSkewTolerance()).isEqualTo(Duration.ofSeconds(30));
        assertThat(config.requireHttps()).isTrue();
    }

    @Test
    @DisplayName("New config fields are customizable")
    void newFieldsAreCustomizable() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .clockSkewTolerance(Duration.ofMinutes(2))
                .requireHttps(false)
                .build();

        assertThat(config.clockSkewTolerance()).isEqualTo(Duration.ofMinutes(2));
        assertThat(config.requireHttps()).isFalse();
    }
}
