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

        AuthGate sdk = AuthGate.builder(config).build();
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
    @DisplayName("New config fields have sensible defaults")
    void newFieldsHaveDefaults() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .build();

        assertThat(config.clockSkewTolerance()).isEqualTo(Duration.ofSeconds(30));
        assertThat(config.requireHttps()).isTrue();
    }
}
