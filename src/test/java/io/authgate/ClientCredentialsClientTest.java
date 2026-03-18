package io.authgate;

import io.authgate.credentials.ClientCredentialsClient;
import io.authgate.credentials.TokenEndpointClient;
import io.authgate.domain.model.OAuthScope;
import io.authgate.domain.model.SecretValue;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ClientCredentialsClient & OAuthScope — scope validation")
class ClientCredentialsClientTest {

    private final TokenEndpointClient tokenEndpointClient = new TokenEndpointClient(
            () -> { throw new UnsupportedOperationException(); },
            new io.authgate.application.port.HttpTransport() {
                @Override public TransportResponse postForm(String endpoint, java.util.Map<String, String> params) {
                    throw new UnsupportedOperationException();
                }
                @Override public TransportResponse fetchJson(String endpoint) {
                    throw new UnsupportedOperationException();
                }
            });

    private final ClientCredentialsClient client = new ClientCredentialsClient(
            tokenEndpointClient,
            "test-client",
            new SecretValue("test-secret"),
            64
    );

    @Nested
    @DisplayName("OAuthScope — value object validation")
    class OAuthScopeTests {

        @Test
        void rejectsNullScope() {
            assertThatThrownBy(() -> new OAuthScope(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("scope must not be null");
        }

        @Test
        void rejectsBlankScope() {
            assertThatThrownBy(() -> new OAuthScope("  "))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("scope must not be blank");
        }

        @Test
        void rejectsScopeWithWhitespace() {
            assertThatThrownBy(() -> new OAuthScope("user read"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not contain whitespace");
        }

        @Test
        void acceptsValidScope() {
            OAuthScope scope = new OAuthScope("user:read");
            assertThat(scope.value()).isEqualTo("user:read");
        }
    }

    @Nested
    @DisplayName("ClientCredentialsClient — collection-level validation")
    class CollectionValidationTests {

        @Test
        void rejectsEmptyScopes() {
            assertThatThrownBy(() -> client.acquire(Set.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not be empty");
        }
    }
}
