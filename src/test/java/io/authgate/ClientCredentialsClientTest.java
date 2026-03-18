package io.authgate;

import io.authgate.application.port.HttpTransport;
import io.authgate.credentials.ClientCredentialsClient;
import io.authgate.domain.model.OAuthScope;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("ClientCredentialsClient & OAuthScope — scope validation")
class ClientCredentialsClientTest {

    private final ClientCredentialsClient client = new ClientCredentialsClient(
            () -> { throw new UnsupportedOperationException(); },
            new HttpTransport() {
                @Override public TransportResponse postForm(String endpoint, Map<String, String> params) {
                    throw new UnsupportedOperationException();
                }
                @Override public TransportResponse fetchJson(String endpoint) {
                    throw new UnsupportedOperationException();
                }
            },
            "test-client",
            "test-secret"
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
        void rejectsScopeWithLeadingSpace() {
            assertThatThrownBy(() -> new OAuthScope(" read"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not contain whitespace");
        }

        @Test
        void rejectsScopeWithTab() {
            assertThatThrownBy(() -> new OAuthScope("user\tread"))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not contain whitespace");
        }

        @Test
        void acceptsValidScope() {
            var scope = new OAuthScope("user:read");
            org.assertj.core.api.Assertions.assertThat(scope.value()).isEqualTo("user:read");
        }
    }

    @Nested
    @DisplayName("ClientCredentialsClient — collection-level validation")
    class CollectionValidationTests {

        @Test
        void rejectsNullScopes() {
            assertThatThrownBy(() -> client.acquire(null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("scopes must not be null");
        }

        @Test
        void rejectsEmptyScopes() {
            assertThatThrownBy(() -> client.acquire(Set.of()))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("must not be empty");
        }
    }
}
