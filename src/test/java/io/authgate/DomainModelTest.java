package io.authgate;

import io.authgate.domain.model.*;
import io.authgate.domain.service.TokenValidationRules;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
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
                    .scopes(Set.of("openid", "profile", "admin"))
                    .audiences(Set.of("my-service"))
                    .expiration(expiry)
                    .build();
        }

        @Test
        void authorizationDecisions() {
            var token = createToken(Instant.now().plusSeconds(3600));

            assertThat(token.belongsTo("user-123")).isTrue();
            assertThat(token.belongsTo("other")).isFalse();
            assertThat(token.hasScope("admin")).isTrue();
            assertThat(token.hasScope("delete")).isFalse();
            assertThat(token.isIntendedFor("my-service")).isTrue();
            assertThat(token.isIntendedFor("other-service")).isFalse();
            assertThat(token.hasExpired()).isFalse();
        }

        @Test
        void detectsExpiredToken() {
            var token = createToken(Instant.now().minusSeconds(60));
            assertThat(token.hasExpired()).isTrue();
        }

        @Test
        void hasExpiredWithClockSkew() {
            // Token expired 10 seconds ago
            var token = createToken(Instant.now().minusSeconds(10));
            // But a clock offset of -30s means the clock "sees" 30s in the past → token still valid
            var skewedClock = Clock.offset(Clock.systemUTC(), Duration.ofSeconds(-30).negated().negated());
            // Actually: negated of 30s = -30s offset → clock is 30s behind → token appears not expired
            var behindClock = Clock.offset(Clock.systemUTC(), Duration.ofSeconds(30).negated());
            assertThat(token.hasExpired(behindClock)).isFalse();
            // With a forward clock, expired
            var aheadClock = Clock.offset(Clock.systemUTC(), Duration.ofSeconds(30));
            assertThat(token.hasExpired(aheadClock)).isTrue();
        }

        @Test
        void exposesSubject() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.subject()).isEqualTo("user-123");
        }

        @Test
        void neverLeaksSubjectInToString() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.toString()).doesNotContain("user-123");
        }

        @Test
        void requireGrantedWhenScopePresent() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().scope("admin").evaluate()).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void requireDeniedWhenScopeMissing() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().scope("nonexistent").evaluate()).isInstanceOf(AuthorizationResult.Denied.class);
        }

        @Test
        void requireGrantedWithAllConstraints() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require()
                    .scope("admin")
                    .audience("my-service")
                    .subject("user-123")
                    .evaluate()).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void requireDeniedOnSubjectMismatch() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().subject("wrong-user").evaluate()).isInstanceOf(AuthorizationResult.Denied.class);
        }

        @Test
        void requireGrantedWhenEmpty() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().evaluate()).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void denialReasonPresentWhenDenied() {
            var token = createToken(Instant.now().plusSeconds(3600));
            var result = token.require().scope("nonexistent").evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Denied.class);
            switch (result) {
                case AuthorizationResult.Denied d -> assertThat(d.reason()).contains("nonexistent");
                default -> fail("Expected Denied");
            }
        }

        @Test
        void denialReasonAbsentWhenGranted() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().scope("admin").evaluate()).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void requireDeniedOnAudienceMismatch() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.require().audience("wrong-audience").evaluate()).isInstanceOf(AuthorizationResult.Denied.class);
        }

        @Test
        void orThrowReturnsTokenWhenGranted() {
            var token = createToken(Instant.now().plusSeconds(3600));
            var result = token.require().scope("admin").subject("user-123").orThrow();
            assertThat(result).isSameAs(token);
        }

        @Test
        void orThrowThrowsWhenDenied() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThatThrownBy(() -> token.require().scope("nonexistent").orThrow())
                    .isInstanceOf(io.authgate.domain.exception.AccessDeniedException.class)
                    .hasMessageContaining("nonexistent");
        }

        @Test
        void isIssuedByMatchesWithNormalization() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.isIssuedBy(new IssuerUri("https://sso.example.com"))).isTrue();
            assertThat(token.isIssuedBy(new IssuerUri("https://sso.example.com/"))).isTrue();
            assertThat(token.isIssuedBy(new IssuerUri("https://other.example.com/"))).isFalse();
        }
    }

    @Nested
    @DisplayName("AuthorizationChain")
    class AuthorizationChainTests {

        private ValidatedToken validToken() {
            return new ValidatedToken.Builder()
                    .subject("user-123")
                    .issuer("https://sso.example.com/")
                    .scopes(Set.of("openid", "admin"))
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
            var result = new AuthorizationChain(validOutcome())
                    .scope("admin").audience("my-service").subject("user-123").evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void evaluateDeniedOnMissingScope() {
            var result = new AuthorizationChain(validOutcome())
                    .scope("nonexistent").evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Denied.class);
        }

        @Test
        void evaluateRejectedOnInvalidToken() {
            var result = new AuthorizationChain(rejectedOutcome())
                    .scope("admin").evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Rejected.class);
        }

        @Test
        void evaluateGrantedWithNoRequirements() {
            var result = new AuthorizationChain(validOutcome()).evaluate();
            assertThat(result).isInstanceOf(AuthorizationResult.Granted.class);
        }

        @Test
        void orThrowReturnsTokenWhenGranted() {
            var token = validToken();
            var result = new AuthorizationChain(new ValidationOutcome.Valid(token))
                    .scope("admin").orThrow();
            assertThat(result).isSameAs(token);
        }

        @Test
        void orThrowThrowsAccessDeniedOnDenied() {
            assertThatThrownBy(() -> new AuthorizationChain(validOutcome()).scope("nonexistent").orThrow())
                    .isInstanceOf(io.authgate.domain.exception.AccessDeniedException.class)
                    .hasMessageContaining("nonexistent");
        }

        @Test
        void orThrowThrowsTokenValidationOnRejected() {
            assertThatThrownBy(() -> new AuthorizationChain(rejectedOutcome()).orThrow())
                    .isInstanceOf(io.authgate.domain.exception.TokenValidationException.class);
        }

        @Test
        void deniedExposesReason() {
            var result = new AuthorizationChain(validOutcome()).subject("wrong").evaluate();
            switch (result) {
                case AuthorizationResult.Denied d -> assertThat(d.reason()).contains("wrong");
                default -> fail("Expected Denied");
            }
        }

        @Test
        void rejectedExposesReason() {
            var result = new AuthorizationChain(rejectedOutcome()).evaluate();
            switch (result) {
                case AuthorizationResult.Rejected r -> assertThat(r.reason().description()).contains("expired");
                default -> fail("Expected Rejected");
            }
        }
    }

    @Nested
    @DisplayName("ValidationOutcome (sealed)")
    class ValidationOutcomeTests {

        @Test
        void validOutcomeViaPatternMatching() {
            var token = new ValidatedToken.Builder()
                    .subject("sub").issuer("iss")
                    .expiration(Instant.now().plusSeconds(60))
                    .build();

            ValidationOutcome outcome = new ValidationOutcome.Valid(token);

            switch (outcome) {
                case ValidationOutcome.Valid v -> assertThat(v.token().belongsTo("sub")).isTrue();
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }

        @Test
        void rejectedOutcomeContainsReason() {
            ValidationOutcome outcome = new ValidationOutcome.Rejected(RejectionReason.TOKEN_EXPIRED);

            switch (outcome) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason().description()).contains("expired");
            }
        }

        @Test
        void exhaustivePatternMatching() {
            ValidationOutcome outcome = new ValidationOutcome.Rejected(RejectionReason.MALFORMED_TOKEN);

            String result = switch (outcome) {
                case ValidationOutcome.Valid v -> "valid";
                case ValidationOutcome.Rejected r -> "rejected";
            };

            assertThat(result).isEqualTo("rejected");
        }
    }

    @Nested
    @DisplayName("ServiceToken")
    class ServiceTokenTests {

        @Test
        void freshTokenIsNotExpiringSoon() {
            var token = new ServiceToken("acc", Instant.now().plusSeconds(3600));
            assertThat(token.isExpiringSoon()).isFalse();
        }

        @Test
        void almostExpiredTokenIsExpiringSoon() {
            var token = new ServiceToken("acc", Instant.now().plusSeconds(10));
            assertThat(token.isExpiringSoon()).isTrue();
        }

        @Test
        void exposesAccessToken() {
            var token = new ServiceToken("my-token", Instant.now().plusSeconds(3600));
            assertThat(token.accessToken()).isEqualTo("my-token");
        }

        @Test
        void rejectsNullAccessToken() {
            assertThatThrownBy(() -> new ServiceToken(null, Instant.now().plusSeconds(60)))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("accessToken");
        }

        @Test
        void rejectsBlankAccessToken() {
            assertThatThrownBy(() -> new ServiceToken("  ", Instant.now().plusSeconds(60)))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("accessToken");
        }

        @Test
        void rejectsNullExpiresAt() {
            assertThatThrownBy(() -> new ServiceToken("token", null))
                    .isInstanceOf(NullPointerException.class)
                    .hasMessageContaining("expiresAt");
        }

        @Test
        void toStringDoesNotLeakAccessToken() {
            var token = new ServiceToken("super-secret", Instant.now().plusSeconds(3600));
            assertThat(token.toString()).doesNotContain("super-secret");
        }
    }

    @Nested
    @DisplayName("RejectionReason")
    class RejectionReasonTests {

        @Test
        void allReasonsHaveDescriptions() {
            for (var reason : RejectionReason.values()) {
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
            var uri = new IssuerUri("https://sso.example.com");
            assertThat(uri.toString()).isEqualTo("https://sso.example.com/");
        }

        @Test
        void preservesTrailingSlash() {
            var uri = new IssuerUri("https://sso.example.com/");
            assertThat(uri.toString()).isEqualTo("https://sso.example.com/");
        }

        @Test
        void matchesWithNormalization() {
            var uri = new IssuerUri("https://sso.example.com/app");
            assertThat(uri.matches("https://sso.example.com/app")).isTrue();
            assertThat(uri.matches("https://sso.example.com/app/")).isTrue();
            assertThat(uri.matches("https://other.example.com/app")).isFalse();
            assertThat(uri.matches(null)).isFalse();
        }

        @Test
        void resolvesPath() {
            var uri = new IssuerUri("https://sso.example.com/app");
            assertThat(uri.resolvePath(".well-known/openid-configuration"))
                    .isEqualTo("https://sso.example.com/app/.well-known/openid-configuration");
        }

        @Test
        void rejectsNullAndBlank() {
            assertThatThrownBy(() -> new IssuerUri(null)).isInstanceOf(NullPointerException.class);
            assertThatThrownBy(() -> new IssuerUri("  ")).isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void equalityByNormalizedValue() {
            var a = new IssuerUri("https://sso.example.com");
            var b = new IssuerUri("https://sso.example.com/");
            assertThat(a).isEqualTo(b);
            assertThat(a.hashCode()).isEqualTo(b.hashCode());
        }

        @Test
        void requireHttpsRejectsHttp() {
            assertThatThrownBy(() -> new IssuerUri("http://sso.example.com", true))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("HTTPS");
        }

        @Test
        void requireHttpsAcceptsHttps() {
            var uri = new IssuerUri("https://sso.example.com", true);
            assertThat(uri.toString()).isEqualTo("https://sso.example.com/");
        }

        @Test
        void noHttpsEnforcementByDefault() {
            var uri = new IssuerUri("http://localhost:9000/app");
            assertThat(uri.toString()).isEqualTo("http://localhost:9000/app/");
        }
    }

    @Nested
    @DisplayName("DiscoveredEndpoints")
    class DiscoveredEndpointsTests {

        @Test
        void exposesAllEndpoints() {
            var issuer = new IssuerUri("https://sso.example.com/");
            var endpoints = new DiscoveredEndpoints(issuer, "https://sso.example.com/token", "https://sso.example.com/jwks");

            assertThat(endpoints.issuerUri()).isEqualTo(issuer);
            assertThat(endpoints.tokenEndpoint()).isEqualTo("https://sso.example.com/token");
            assertThat(endpoints.jwksUri()).isEqualTo("https://sso.example.com/jwks");
        }

        @Test
        void equalityCheck() {
            var issuer = new IssuerUri("https://sso.example.com/");
            var a = new DiscoveredEndpoints(issuer, "https://sso.example.com/token", "https://sso.example.com/jwks");
            var b = new DiscoveredEndpoints(issuer, "https://sso.example.com/token", "https://sso.example.com/jwks");
            assertThat(a).isEqualTo(b);
            assertThat(a.hashCode()).isEqualTo(b.hashCode());
        }
    }

    @Nested
    @DisplayName("TokenValidationRules")
    class TokenValidationRulesTests {

        private final IssuerUri issuer = new IssuerUri("https://sso.example.com/");

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
            var rules = new TokenValidationRules(issuer, "my-service");
            var token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of("my-service"));

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> assertThat(v.token()).isSameAs(token);
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }

        @Test
        void rejectsExpiredToken() {
            var rules = new TokenValidationRules(issuer, null);
            var token = tokenWith(Instant.now().minusSeconds(60), "https://sso.example.com/", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.TOKEN_EXPIRED);
            }
        }

        @Test
        void clockSkewToleranceAcceptsRecentlyExpiredToken() {
            var rules = new TokenValidationRules(issuer, null, Duration.ofSeconds(60));
            // Token expired 30 seconds ago, but 60s clock skew tolerance
            var token = tokenWith(Instant.now().minusSeconds(30), "https://sso.example.com/", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> { /* pass */ }
                case ValidationOutcome.Rejected r -> fail("Expected Valid with clock skew tolerance");
            }
        }

        @Test
        void clockSkewToleranceStillRejectsLongExpiredToken() {
            var rules = new TokenValidationRules(issuer, null, Duration.ofSeconds(30));
            // Token expired 60 seconds ago, 30s tolerance isn't enough
            var token = tokenWith(Instant.now().minusSeconds(60), "https://sso.example.com/", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.TOKEN_EXPIRED);
            }
        }

        @Test
        void rejectsIssuerMismatch() {
            var rules = new TokenValidationRules(issuer, null);
            var token = tokenWith(Instant.now().plusSeconds(60), "https://other.example.com/", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.ISSUER_MISMATCH);
            }
        }

        @Test
        void rejectsAudienceMismatch() {
            var rules = new TokenValidationRules(issuer, "expected-audience");
            var token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of("wrong-audience"));

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> fail("Expected Rejected");
                case ValidationOutcome.Rejected r -> assertThat(r.reason()).isEqualTo(RejectionReason.AUDIENCE_MISMATCH);
            }
        }

        @Test
        void skipsAudienceCheckWhenNull() {
            var rules = new TokenValidationRules(issuer, null);
            var token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com/", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> { /* pass */ }
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }

        @Test
        void issuerMatchesWithNormalization() {
            var rules = new TokenValidationRules(issuer, null);
            var token = tokenWith(Instant.now().plusSeconds(60), "https://sso.example.com", Set.of());

            switch (rules.validate(token)) {
                case ValidationOutcome.Valid v -> { /* pass */ }
                case ValidationOutcome.Rejected r -> fail("Expected Valid");
            }
        }
    }

    @Nested
    @DisplayName("TransportResponse")
    class TransportResponseTests {

        @Test
        void successfulForTwoHundredRange() {
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(200, java.util.Map.of()).isSuccessful()).isTrue();
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(201, java.util.Map.of()).isSuccessful()).isTrue();
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(299, java.util.Map.of()).isSuccessful()).isTrue();
        }

        @Test
        void notSuccessfulOutsideTwoHundredRange() {
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(199, java.util.Map.of()).isSuccessful()).isFalse();
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(300, java.util.Map.of()).isSuccessful()).isFalse();
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(401, java.util.Map.of()).isSuccessful()).isFalse();
            assertThat(new io.authgate.application.port.HttpTransport.TransportResponse(500, java.util.Map.of()).isSuccessful()).isFalse();
        }
    }
}
