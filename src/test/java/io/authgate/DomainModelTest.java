package io.authgate;

import io.authgate.domain.model.*;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static org.assertj.core.api.Assertions.*;

class DomainModelTest {

    @Nested
    @DisplayName("ValidatedToken")
    class ValidatedTokenTests {

        private ValidatedToken createToken(Instant expiry) {
            return new ValidatedToken.Builder()
                    .subject("user-123")
                    .issuer("https://sso.example.com/")
                    .scopes(Set.of(new OAuthScope("openid"), new OAuthScope("profile"), new OAuthScope("admin")))
                    .audiences(Set.of("my-service"))
                    .expiration(expiry)
                    .build();
        }

        @Test
        void authorizationDecisions() {
            ValidatedToken token = createToken(Instant.now().plusSeconds(3600));

            assertThat(token.belongsTo("user-123")).isTrue();
            assertThat(token.belongsTo("other")).isFalse();
            assertThat(token.hasScope(new OAuthScope("admin"))).isTrue();
            assertThat(token.hasScope(new OAuthScope("delete"))).isFalse();
            assertThat(token.isIntendedFor("my-service")).isTrue();
            assertThat(token.isIntendedFor("other-service")).isFalse();
            assertThat(token.hasExpired()).isFalse();
        }

        @Test
        void detectsExpiredToken() {
            ValidatedToken token = createToken(Instant.now().minusSeconds(60));
            assertThat(token.hasExpired()).isTrue();
        }

        @Test
        void neverLeaksSubjectInToString() {
            ValidatedToken token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.toString()).doesNotContain("user-123");
        }
    }

    @Nested
    @DisplayName("AuthorizationChain")
    class AuthorizationChainTests {

        private ValidatedToken validToken() {
            return new ValidatedToken.Builder()
                    .subject("user-123")
                    .issuer("https://sso.example.com/")
                    .scopes(Set.of(new OAuthScope("openid"), new OAuthScope("admin")))
                    .audiences(Set.of("my-service"))
                    .expiration(Instant.now().plusSeconds(3600))
                    .build();
        }

        private ValidationOutcome validOutcome() {
            return new ValidationOutcome.Valid(validToken());
        }

        private ValidationOutcome rejectedOutcome() {
            return new ValidationOutcome.Rejected(RejectionReason.TOKEN_EXPIRED);
        }

        @Test
        void evaluateGrantedWhenAllMatch() {
            AuthorizationResult result = new AuthorizationChain(validOutcome())
                    .scope(new OAuthScope("admin")).audience("my-service").subject("user-123").evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void evaluateDeniedOnMissingScope() {
            AuthorizationResult result = new AuthorizationChain(validOutcome())
                    .scope(new OAuthScope("nonexistent")).evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Denied.class);
        }

        @Test
        void evaluateRejectedOnInvalidToken() {
            AuthorizationResult result = new AuthorizationChain(rejectedOutcome())
                    .scope(new OAuthScope("admin")).evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Rejected.class);
        }

        @Test
        void orThrowReturnsTokenWhenGranted() {
            ValidatedToken token = validToken();
            ValidatedToken result = new AuthorizationChain(new ValidationOutcome.Valid(token))
                    .scope(new OAuthScope("admin")).orThrow();
            assertThat(result).isSameAs(token);
        }

        @Test
        void orThrowThrowsAccessDeniedOnDenied() {
            assertThatThrownBy(() -> new AuthorizationChain(validOutcome()).scope(new OAuthScope("nonexistent")).orThrow())
                    .isInstanceOf(io.authgate.domain.exception.AccessDeniedException.class)
                    .hasMessageContaining("nonexistent");
        }

        @Test
        void orThrowThrowsTokenValidationOnRejected() {
            assertThatThrownBy(() -> new AuthorizationChain(rejectedOutcome()).orThrow())
                    .isInstanceOf(io.authgate.domain.exception.TokenValidationException.class);
        }
    }

    @Nested
    @DisplayName("ServiceToken")
    class ServiceTokenTests {

        @Test
        void freshTokenIsNotExpiringSoon() {
            ServiceToken token = new ServiceToken("acc", Instant.now().plusSeconds(3600));
            assertThat(token.isExpiringSoon()).isFalse();
        }

        @Test
        void almostExpiredTokenIsExpiringSoon() {
            ServiceToken token = new ServiceToken("acc", Instant.now().plusSeconds(10));
            assertThat(token.isExpiringSoon()).isTrue();
        }

        @Test
        void toStringDoesNotLeakAccessToken() {
            ServiceToken token = new ServiceToken("super-secret", Instant.now().plusSeconds(3600));
            assertThat(token.toString()).doesNotContain("super-secret");
        }
    }

    @Nested
    @DisplayName("RejectionReason")
    class RejectionReasonTests {

        @Test
        void allReasonsHaveDescriptions() {
            for (RejectionReason reason : RejectionReason.values()) {
                assertThat(reason.description()).isNotBlank();
                assertThat(reason.code()).isNotBlank();
            }
        }
    }

    @Nested
    @DisplayName("IssuerUri")
    class IssuerUriTests {

        @Test
        void normalizesTrailingSlash() {
            IssuerUri uri = new IssuerUri("https://sso.example.com");
            assertThat(uri.toString()).isEqualTo("https://sso.example.com/");
        }

        @Test
        void matchesWithNormalization() {
            IssuerUri uri = new IssuerUri("https://sso.example.com/app");
            assertThat(uri.matches("https://sso.example.com/app")).isTrue();
            assertThat(uri.matches("https://sso.example.com/app/")).isTrue();
            assertThat(uri.matches("https://other.example.com/app")).isFalse();
            assertThat(uri.matches(null)).isFalse();
        }

        @Test
        void rejectsNullAndBlank() {
            assertThatThrownBy(() -> new IssuerUri(null)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> new IssuerUri("  ")).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void requireHttpsRejectsHttp() {
            assertThatThrownBy(() -> new IssuerUri("http://sso.example.com", true))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("HTTPS");
        }
    }

    @Nested
    @DisplayName("UserInfo")
    class UserInfoTests {

        @Test
        void rejectsNullSubject() {
            assertThatThrownBy(() -> new UserInfo(null, null, null, null, null, null, null, null, null, null, null, null, null, null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("sub");
        }

        @Test
        void rejectsBlankSubject() {
            assertThatThrownBy(() -> new UserInfo("  ", null, null, null, null, null, null, null, null, null, null, null, null, null))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("sub");
        }

        @Test
        void customClaimsAreUnmodifiable() {
            Map<String, Object> mutable = new HashMap<>();
            mutable.put("org", "acme");
            UserInfo info = new UserInfo("user-1", null, null, null, null, null, null, null, null, null, null, null, null, mutable);

            assertThat(info.customClaims()).containsEntry("org", "acme");
            assertThatThrownBy(() -> info.customClaims().put("hack", "yes"))
                    .isInstanceOf(UnsupportedOperationException.class);
        }

        @Test
        void nullCustomClaimsBecomesEmptyMap() {
            UserInfo info = new UserInfo("user-1", null, null, null, null, null, null, null, null, null, null, null, null, null);
            assertThat(info.customClaims()).isEmpty();
        }

        @Test
        void toStringMasksPii() {
            UserInfo info = new UserInfo("user-123", "user@example.com", true, "John Doe", null, null, null, null, null, null, null, null, null, null);
            assertThat(info.toString()).isEqualTo("UserInfo[sub=***]");
            assertThat(info.toString()).doesNotContain("user-123");
            assertThat(info.toString()).doesNotContain("user@example.com");
        }
    }

    @Nested
    @DisplayName("ValidatedToken.validateAgainst")
    class TokenValidationTests {

        private final IssuerUri issuer = new IssuerUri("https://sso.example.com/");
        private final Clock utcClock = Clock.systemUTC();

        private ValidatedToken tokenWith(Instant expiry, String issuerStr, Set<String> audiences) {
            return new ValidatedToken.Builder()
                    .subject("sub")
                    .issuer(issuerStr)
                    .expiration(expiry)
                    .audiences(audiences)
                    .build();
        }

        @Test
        void acceptsValidToken() {
            ValidatedToken token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of("my-service"));

            switch (token.validateAgainst(issuer, "my-service", utcClock)) {
                case ValidationOutcome.Valid v -> assertThat(v.token()).isSameAs(token);
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }

        @Test
        void rejectsExpiredToken() {
            ValidatedToken token = tokenWith(Instant.now().minusSeconds(60), "https://sso.example.com/", Set.of());

            switch (token.validateAgainst(issuer, null, utcClock)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.TOKEN_EXPIRED);
            }
        }

        @Test
        void rejectsIssuerMismatch() {
            ValidatedToken token = tokenWith(Instant.now().plusSeconds(60), "https://other.example.com/", Set.of());

            switch (token.validateAgainst(issuer, null, utcClock)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.ISSUER_MISMATCH);
            }
        }

        @Test
        void rejectsAudienceMismatch() {
            ValidatedToken token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of("wrong-audience"));

            switch (token.validateAgainst(issuer, "expected-audience", utcClock)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.AUDIENCE_MISMATCH);
            }
        }

        @Test
        void skipsAudienceCheckWhenNull() {
            ValidatedToken token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of());

            switch (token.validateAgainst(issuer, null, utcClock)) {
                case ValidationOutcome.Valid v -> { /* pass */ }
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }
    }
}
