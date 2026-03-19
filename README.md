<div align="center">

# Java AuthGate SDK

<img src="assets/authgate-logo.jpeg" width="600" alt="AuthGate Logo">

**Provider-agnostic OIDC library for Java 21+**

Handles JWT validation, client-credentials token acquisition, and UserInfo retrieval — without framework dependencies.

[![GitHub Release](https://img.shields.io/github/v/release/homni-labs/authgate-sdk-java)](https://github.com/homni-labs/authgate-sdk-java/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/homni-labs/authgate-sdk-java/ci.yml?branch=master)](https://github.com/homni-labs/authgate-sdk-java/actions/workflows/ci.yml)
[![Javadoc](https://javadoc.io/badge2/io.github.homni-labs/authgate-sdk-java/javadoc.svg)](https://javadoc.io/doc/io.github.homni-labs/authgate-sdk-java)
[![Java 21+](https://img.shields.io/badge/Java-21%2B-blue)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[English](README.md) | [Русский](README_RU.md)

</div>

---

## Installation

**Maven** (from [Maven Central](https://repo1.maven.org/maven2/io/github/homni-labs/authgate-sdk-java/)):

```xml
<dependency>
    <groupId>io.github.homni-labs</groupId>
    <artifactId>authgate-sdk-java</artifactId>
    <version>0.0.1-alpha.1</version>
</dependency>
```

**Gradle (Kotlin DSL):**

```kotlin
implementation("io.github.homni-labs:authgate-sdk-java:0.0.1-alpha.1")
```

**Gradle (Groovy DSL):**

```groovy
implementation 'io.github.homni-labs:authgate-sdk-java:0.0.1-alpha.1'
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
| `userInfoCacheTtl` | no | `5m` | UserInfo response cache TTL |

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

<details>
<summary><b>Rejection codes</b></summary>

| Code | Description |
|---|---|
| `TOKEN_EXPIRED` | Token has expired |
| `INVALID_SIGNATURE` | Signature verification failed |
| `ISSUER_MISMATCH` | Issuer does not match |
| `AUDIENCE_MISMATCH` | Audience does not match |
| `MALFORMED_TOKEN` | Invalid JWT structure |
| `UNKNOWN` | Unexpected error |

</details>

### UserInfo

Fetch OIDC identity claims (email, name, etc.) from the Identity Provider's UserInfo endpoint. The endpoint URL is discovered automatically. Responses are cached.

```java
UserInfo info = sdk.fetchUserInfo(accessToken);
String email = info.email();
String name = info.name();
Map<String, Object> custom = info.customClaims();
```

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
| `nimbus-jose-jwt` | JWT validation, JWKS |
| `jackson-databind` | JSON parsing |
| `slf4j-api` | Logging facade |

**Requires:** Java 21+

## Roadmap

| Status | Feature | Issue |
|--------|---------|-------|
| 🔲 | Token Exchange (RFC 8693) — delegation and impersonation flows | [issue](https://github.com/homni-app/authgate-sdk-java/issues/1) |
| 🔲 | Token Refresh — automatic access token renewal via refresh tokens | [issue](https://github.com/homni-app/authgate-sdk-java/issues/2) |
| ✅ | UserInfo endpoint — retrieve user details without extra IdP calls | [issue](https://github.com/homni-app/authgate-sdk-java/issues/3) |
| ✅ | Drop getters, use access modifiers | [issue](https://github.com/homni-app/authgate-sdk-java/issues/4) |
| 🔲 | Artifact optimization — reduce binary size | [issue](https://github.com/homni-app/authgate-sdk-java/issues/5) |
| ✅ | Publish to Maven Central | [issue](https://github.com/homni-app/authgate-sdk-java/issues/6) |
| ✅ | Gradle dependency support | [issue](https://github.com/homni-app/authgate-sdk-java/issues/7) |
| ✅ | CI pipeline — run tests on push/PR | [issue](https://github.com/homni-labs/authgate-sdk-java/issues/9) |

## Contributing

1. Fork the repository
2. Create a branch from `master` (`feature/...`, `fix/...`, `refactor/...`)
3. Write code and tests
4. `mvn clean install`
5. Open a Pull Request — one feature or fix per PR, link related issue (`Closes #1`)

> **Code style** — follow existing conventions, write tests for every new feature, cover edge cases.

### Questions?

| Channel | Link |
|---------|------|
| GitHub Discussions | [discussions](https://github.com/homni-app/authgate-sdk-java/discussions) |
| Telegram | [@zaytsev_dv](https://t.me/zaytsev_dv) |
| Email | zaytsev.dmitry9228@gmail.com |

## License

This project is licensed under the [MIT License](LICENSE).
