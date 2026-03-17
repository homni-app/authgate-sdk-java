package io.authgate;

import io.authgate.domain.model.*;
import io.authgate.domain.service.DelegationPolicy;
import io.authgate.domain.service.TokenValidationRules;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.*;

class DomainModelTest {

    @Nested
    @DisplayName("BearerToken")
    class BearerTokenTests {

        @Test
        void rejectsBlankValue() {
            assertThatThrownBy(() -> new BearerToken(""))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void rejectsNull() {
            assertThatThrownBy(() -> new BearerToken(null))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        @Test
        void neverLeaksValueInToString() {
            var token = new BearerToken("super-secret-token");
            assertThat(token.toString()).doesNotContain("super-secret-token");
        }

        @Test
        void appliesAsHeader() {
            var token = new BearerToken("xyz");
            var captured = new String[1];
            token.applyAsHeader(h -> captured[0] = h);
            assertThat(captured[0]).isEqualTo("Bearer xyz");
        }

        @Test
        void describesValue() {
            var token = new BearerToken("abc123");
            var captured = new String[1];
            token.describeTo(v -> captured[0] = v);
            assertThat(captured[0]).isEqualTo("abc123");
        }

        @Test
        void equalityByValue() {
            var a = new BearerToken("same");
            var b = new BearerToken("same");
            assertThat(a).isEqualTo(b);
            assertThat(a.hashCode()).isEqualTo(b.hashCode());
        }
    }

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
                    .clientId("cli-client")
                    .build();
        }

        @Test
        void authorizationDecisions() {
            var token = createToken(Instant.now().plusSeconds(3600));

            assertThat(token.belongsTo("user-123")).isTrue();
            assertThat(token.belongsTo("other")).isFalse();
            assertThat(token.hasScope("admin")).isTrue();
            assertThat(token.hasScope("delete")).isFalse();
            assertThat(token.hasAllScopes(Set.of("openid", "admin"))).isTrue();
            assertThat(token.hasAllScopes(Set.of("openid", "delete"))).isFalse();
            assertThat(token.hasAnyScope(Set.of("delete", "admin"))).isTrue();
            assertThat(token.isIntendedFor("my-service")).isTrue();
            assertThat(token.isIntendedFor("other-service")).isFalse();
            assertThat(token.issuedByClient("cli-client")).isTrue();
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
        void describesStateThroughConsumers() {
            var token = createToken(Instant.now().plusSeconds(3600));

            var sub = new String[1];
            var iss = new String[1];
            token.describeSubjectTo(v -> sub[0] = v);
            token.describeIssuerTo(v -> iss[0] = v);

            assertThat(sub[0]).isEqualTo("user-123");
            assertThat(iss[0]).isEqualTo("https://sso.example.com/");
        }

        @Test
        void neverLeaksSubjectInToString() {
            var token = createToken(Instant.now().plusSeconds(3600));
            assertThat(token.toString()).doesNotContain("user-123");
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
                case ValidationOutcome.Rejected r -> {
                    var desc = new String[1];
                    r.describeReasonTo(d -> desc[0] = d);
                    assertThat(desc[0]).contains("expired");
                }
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
    @DisplayName("TokenInfo")
    class TokenInfoTests {

        @Test
        void lifecycleBehavior() {
            var token = new TokenInfo.Builder()
                    .accessToken("acc")
                    .refreshToken("ref")
                    .expiresInSeconds(3600)
                    .build();

            assertThat(token.isExpired()).isFalse();
            assertThat(token.canRefresh()).isTrue();
        }

        @Test
        void noRefreshToken() {
            var token = new TokenInfo.Builder()
                    .accessToken("acc")
                    .expiresInSeconds(3600)
                    .build();

            assertThat(token.canRefresh()).isFalse();
        }

        @Test
        void convertsToBearerToken() {
            var token = new TokenInfo.Builder()
                    .accessToken("my-jwt")
                    .expiresInSeconds(60)
                    .build();

            var bearer = token.toBearerToken();
            var captured = new String[1];
            bearer.describeTo(v -> captured[0] = v);
            assertThat(captured[0]).isEqualTo("my-jwt");
        }
    }

    @Nested
    @DisplayName("RejectionReason")
    class RejectionReasonTests {

        @Test
        void allReasonsHaveDescriptions() {
            for (var reason : RejectionReason.values()) {
                var desc = new String[1];
                var code = new String[1];
                reason.describeTo(d -> desc[0] = d);
                reason.describeCodeTo(c -> code[0] = c);

                assertThat(desc[0]).isNotBlank();
                assertThat(code[0]).isNotBlank();
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
        void describesAllEndpoints() {
            var issuer = new IssuerUri("https://sso.example.com/");
            var endpoints = new DiscoveredEndpoints(issuer, "https://sso.example.com/token", "https://sso.example.com/jwks");

            var issuerRef = new AtomicReference<IssuerUri>();
            var tokenEndpoint = new String[1];
            var jwksUri = new String[1];
            endpoints.describeIssuerUriTo(issuerRef::set);
            endpoints.describeTokenEndpointTo(v -> tokenEndpoint[0] = v);
            endpoints.describeJwksUriTo(v -> jwksUri[0] = v);

            assertThat(issuerRef.get()).isEqualTo(issuer);
            assertThat(tokenEndpoint[0]).isEqualTo("https://sso.example.com/token");
            assertThat(jwksUri[0]).isEqualTo("https://sso.example.com/jwks");
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
    @DisplayName("DelegationContext")
    class DelegationContextTests {

        @Test
        void describesSubjects() {
            var ctx = new DelegationContext("service-abc", "user-456");
            var acting = new String[1];
            var service = new String[1];
            ctx.describeActingSubjectTo(v -> acting[0] = v);
            ctx.describeServiceSubjectTo(v -> service[0] = v);
            assertThat(acting[0]).isEqualTo("user-456");
            assertThat(service[0]).isEqualTo("service-abc");
        }

        @Test
        void isActingFor() {
            var ctx = new DelegationContext("service-abc", "user-456");
            assertThat(ctx.isActingFor("user-456")).isTrue();
            assertThat(ctx.isActingFor("other")).isFalse();
        }

        @Test
        void neverLeaksSubjectsInToString() {
            var ctx = new DelegationContext("service-abc", "user-456");
            assertThat(ctx.toString()).doesNotContain("service-abc").doesNotContain("user-456");
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
    @DisplayName("DelegationPolicy")
    class DelegationPolicyTests {

        private final DelegationPolicy policy = new DelegationPolicy();

        private ValidatedToken serviceToken() {
            return new ValidatedToken.Builder()
                    .subject("service-abc")
                    .issuer("https://sso.example.com/")
                    .expiration(Instant.now().plusSeconds(3600))
                    .scopes(Set.of("openid", "service:delegate"))
                    .build();
        }

        private ValidatedToken userToken() {
            return new ValidatedToken.Builder()
                    .subject("user-123")
                    .issuer("https://sso.example.com/")
                    .expiration(Instant.now().plusSeconds(3600))
                    .scopes(Set.of("openid", "profile"))
                    .build();
        }

        @Test
        void createsDelegationContext() {
            var result = policy.evaluate(serviceToken(), "user-456");
            assertThat(result).isPresent();
            result.ifPresent(ctx -> {
                var acting = new String[1];
                var service = new String[1];
                ctx.describeActingSubjectTo(v -> acting[0] = v);
                ctx.describeServiceSubjectTo(v -> service[0] = v);
                assertThat(acting[0]).isEqualTo("user-456");
                assertThat(service[0]).isEqualTo("service-abc");
            });
        }

        @Test
        void emptyWhenNoDelegateScope() {
            var result = policy.evaluate(userToken(), "user-456");
            assertThat(result).isEmpty();
        }

        @Test
        void emptyWhenNoHeader() {
            var result = policy.evaluate(serviceToken(), null);
            assertThat(result).isEmpty();
        }

        @Test
        void emptyWhenBlankHeader() {
            var result = policy.evaluate(serviceToken(), "  ");
            assertThat(result).isEmpty();
        }

        @Test
        void customScopeAndHeader() {
            var customPolicy = new DelegationPolicy("custom:act-as", "X-Custom-Header");
            var token = new ValidatedToken.Builder()
                    .subject("svc")
                    .issuer("https://sso.example.com/")
                    .expiration(Instant.now().plusSeconds(3600))
                    .scopes(Set.of("custom:act-as"))
                    .build();

            var result = customPolicy.evaluate(token, "target-user");
            assertThat(result).isPresent();

            var headerName = new String[1];
            customPolicy.describeHeaderNameTo(v -> headerName[0] = v);
            assertThat(headerName[0]).isEqualTo("X-Custom-Header");
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
