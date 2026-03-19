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
        assertThat(config.userInfoCacheTtl()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    @DisplayName("userInfoCacheTtl accepts custom value")
    void userInfoCacheTtlCustomValue() {
        AuthGateConfiguration config = new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .userInfoCacheTtl(Duration.ofMinutes(10))
                .build();

        assertThat(config.userInfoCacheTtl()).isEqualTo(Duration.ofMinutes(10));
    }

    @Test
    @DisplayName("userInfoCacheTtl rejects negative duration")
    void userInfoCacheTtlRejectsNegative() {
        assertThatThrownBy(() -> new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .userInfoCacheTtl(Duration.ofMinutes(-1))
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userInfoCacheTtl");
    }

    @Test
    @DisplayName("userInfoCacheTtl rejects zero duration")
    void userInfoCacheTtlRejectsZero() {
        assertThatThrownBy(() -> new AuthGateConfiguration.Builder()
                .issuerUri("https://sso.example.com/")
                .clientId("test")
                .userInfoCacheTtl(Duration.ZERO)
                .build())
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("userInfoCacheTtl");
    }
}
