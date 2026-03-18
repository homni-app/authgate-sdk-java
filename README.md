# AuthGate SDK

Provider-agnostic OIDC library for Java 21+. Handles JWT validation and client-credentials token acquisition — without framework dependencies.

## Installation

```xml
<dependency>
    <groupId>io.authgate</groupId>
    <artifactId>authgate-sdk</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Configuration

| Parameter | Required | Default | Description |
|---|---|---|---|
| `issuerUri` | **yes** | — | OIDC provider base URL |
| `clientId` | **yes** | — | OAuth 2.1 client identifier |
| `clientSecret` | no | `null` | Client secret for client-credentials grant |
| `audience` | no | `null` | Expected `aud` claim. When set, tokens without it are rejected |
| `requireHttps` | no | `true` | Reject non-HTTPS issuer URIs |
| `httpTimeout` | no | `10s` | HTTP call timeout for IdP requests |
| `discoveryTtl` | no | `1h` | OIDC discovery document cache TTL |
| `clockSkewTolerance` | no | `30s` | Allowed clock drift when verifying `exp` |
| `circuitBreakerFailureThreshold` | no | `5` | Failures before circuit breaker opens |
| `circuitBreakerResetTimeout` | no | `30s` | Time before a probe call after opening |
| `serviceTokenCacheSize` | no | `64` | Max cached service tokens |

## Usage

### Initialization

```java
var config = new AuthGateConfiguration.Builder()
        .issuerUri("https://idp.example.com/realms/my-realm/")
        .clientId("my-client")
        .clientSecret("secret")
        .build();

var sdk = AuthGate.builder(config).build();
```

Custom infrastructure:

```java
var sdk = AuthGate.builder(config)
        .cacheStore(redisCacheStore)
        .httpTransport(customTransport)
        .build();
```

### Authorization

`authorize()` validates the token and returns a fluent chain. Two styles:

**Exception-based** — `TokenValidationException` (401) / `AccessDeniedException` (403):

```java
sdk.authorizeFromHeader(authHeader).orThrow();
sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("email")).orThrow();
sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("email")).subject(userId).orThrow();
```

**Polymorphic** — `AuthorizationResult` sealed interface:

```java
switch (sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("profile")).evaluate()) {
    case AuthorizationResult.Granted g  -> handle(g.token());
    case AuthorizationResult.Denied d   -> log.warn(d.reason());
    case AuthorizationResult.Rejected r -> log.warn(r.reason().description());
}
```

**Rejection codes:**

| Code | Description |
|---|---|
| `TOKEN_EXPIRED` | Token has expired |
| `INVALID_SIGNATURE` | Signature verification failed |
| `ISSUER_MISMATCH` | Issuer does not match |
| `AUDIENCE_MISMATCH` | Audience does not match |
| `MALFORMED_TOKEN` | Invalid JWT structure |
| `UNKNOWN` | Unexpected error |

### Client Credentials

Service token acquisition for service-to-service communication. Tokens are cached per scope-set and refreshed automatically.

```java
ServiceToken token = sdk.acquireServiceToken(Set.of(new OAuthScope("openid"), new OAuthScope("profile")));
httpClient.header("Authorization", "Bearer " + token.accessToken());
```

Requires `clientSecret` in configuration.

### Custom CacheStore

Default — in-memory `ConcurrentHashMap`. For multi-instance deployments, implement `CacheStore`:

```java
var sdk = AuthGate.builder(config)
        .cacheStore(redisCacheStore)
        .build();
```

## Dependencies

| Library | Purpose |
|---|---|
| nimbus-jose-jwt | JWT validation, JWKS |
| jackson-databind | JSON parsing |
| slf4j-api | Logging facade |

**Requires:** Java 21+

## Roadmap

1. **Token Exchange (RFC 8693)** — delegation and impersonation flows
2. **Token Refresh** — automatic access token renewal via refresh tokens
3. **UserInfo endpoint** — `getUserInfo(accessToken)` to retrieve user details (sub, scopes, roles) without extra IdP calls
4. **Drop getters, use access modifiers** — expose fields via package-private access instead of getters (`token.accessToken` instead of `token.accessToken()`), reorganize packages as needed; avoid `public` fields
5. **Artifact optimization** — reduce SDK binary size and dependency footprint
