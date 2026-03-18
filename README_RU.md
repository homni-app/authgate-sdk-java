# AuthGate SDK

Провайдер-независимая OIDC-библиотека для Java 21+. Валидация JWT и получение сервисных токенов через client-credentials — без привязки к фреймворку.

## Подключение

```xml
<dependency>
    <groupId>io.authgate</groupId>
    <artifactId>authgate-sdk</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

## Конфигурация

| Параметр | Обязательный | По умолчанию | Описание |
|---|---|---|---|
| `issuerUri` | **да** | — | Базовый URL OIDC-провайдера |
| `clientId` | **да** | — | OAuth 2.1 идентификатор клиента |
| `clientSecret` | нет | `null` | Секрет клиента для client-credentials grant |
| `audience` | нет | `null` | Ожидаемый `aud` claim. Если задан — токены без него отклоняются |
| `requireHttps` | нет | `true` | Отклонять `issuerUri` без HTTPS |
| `httpTimeout` | нет | `10s` | Таймаут HTTP-вызовов к IdP |
| `discoveryTtl` | нет | `1h` | TTL кэша OIDC discovery документа |
| `clockSkewTolerance` | нет | `30s` | Допустимое расхождение часов при проверке `exp` |
| `circuitBreakerFailureThreshold` | нет | `5` | Число ошибок до размыкания circuit breaker |
| `circuitBreakerResetTimeout` | нет | `30s` | Время до пробного вызова после размыкания |
| `serviceTokenCacheSize` | нет | `64` | Макс. количество кэшированных сервисных токенов |

## Использование

### Инициализация

```java
var config = new AuthGateConfiguration.Builder()
        .issuerUri("https://idp.example.com/realms/my-realm/")
        .clientId("my-client")
        .clientSecret("secret")
        .build();

var sdk = AuthGate.builder(config).build();
```

Custom инфраструктура:

```java
var sdk = AuthGate.builder(config)
        .cacheStore(redisCacheStore)
        .httpTransport(customTransport)
        .build();
```

### Авторизация

`authorize()` валидирует токен и возвращает fluent chain. Два стиля:

**Через исключения** — `TokenValidationException` (401) / `AccessDeniedException` (403):

```java
sdk.authorizeFromHeader(authHeader).orThrow();
sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("email")).orThrow();
sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("email")).subject(userId).orThrow();
```

**Полиморфный** — `AuthorizationResult` sealed interface:

```java
switch (sdk.authorizeFromHeader(authHeader).scope(new OAuthScope("profile")).evaluate()) {
    case AuthorizationResult.Granted g  -> handle(g.token());
    case AuthorizationResult.Denied d   -> log.warn(d.reason());
    case AuthorizationResult.Rejected r -> log.warn(r.reason().description());
}
```

**Коды отказа:**

| Код | Описание |
|---|---|
| `TOKEN_EXPIRED` | Токен просрочен |
| `INVALID_SIGNATURE` | Подпись не прошла верификацию |
| `ISSUER_MISMATCH` | Issuer не совпадает |
| `AUDIENCE_MISMATCH` | Audience не совпадает |
| `MALFORMED_TOKEN` | Невалидная структура JWT |
| `UNKNOWN` | Непредвиденная ошибка |

### Client Credentials

Получение сервисных токенов для межсервисного взаимодействия. Токены кэшируются по набору scopes и обновляются автоматически.

```java
ServiceToken token = sdk.acquireServiceToken(Set.of(new OAuthScope("openid"), new OAuthScope("profile")));
httpClient.header("Authorization", "Bearer " + token.accessToken());
```

Требует `clientSecret` в конфигурации.

### Кастомный CacheStore

По умолчанию — in-memory `ConcurrentHashMap`. Для multi-instance деплоев реализуйте `CacheStore`:

```java
var sdk = AuthGate.builder(config)
        .cacheStore(redisCacheStore)
        .build();
```

## Зависимости

| Библиотека | Назначение |
|---|---|
| nimbus-jose-jwt | Валидация JWT, JWKS |
| jackson-databind | Парсинг JSON |
| slf4j-api | Фасад логирования |

**Требования:** Java 21+
