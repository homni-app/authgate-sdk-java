# SSO SDK

Java-библиотека для интеграции сервисов с SSO-платформой (OAuth 2.1 / OpenID Connect).

## Для чего нужен SDK

SSO SDK решает задачу единой аутентификации и авторизации в микросервисной архитектуре Homni. Вместо того чтобы каждый сервис самостоятельно реализовывал работу с JWT, JWKS, OIDC Discovery и OAuth-токенами, SDK предоставляет готовое решение с одной точкой входа.

**Бизнес-задачи:**

- **Защита API** — автоматическая валидация JWT-токенов на входящих запросах, проверка подписи, срока действия, issuer и audience
- **Межсервисная авторизация** — получение токенов через Client Credentials для безопасного взаимодействия между backend-сервисами (например, telegram-backend -> media-service)
- **Делегирование действий** — механизм On-Behalf-Of позволяет сервису действовать от имени пользователя в downstream-вызовах
- **Zero-config для Spring Boot** — достаточно указать `sso.issuer-uri` в `application.yml`, все бины регистрируются автоматически

## Подключение

```xml
<dependency>
    <groupId>com.homni</groupId>
    <artifactId>sso-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

## Возможности

| Возможность | Описание |
|---|---|
| Валидация JWT | Проверка подписи (RS256/ES256+), expiration, issuer, audience |
| Client Credentials | Получение и кэширование сервисных токенов с автообновлением |
| OIDC Discovery | Автоматическое обнаружение эндпоинтов IdP с TTL-кэшированием |
| Servlet Filter | Защита эндпоинтов через `BearerTokenFilter` с исключением путей |
| On-Behalf-Of | Делегирование через scope `service:delegate` и заголовок `X-Homni-On-Behalf-Of` |
| Spring Boot Auto-Configuration | Автоматическая регистрация всех бинов |
| Standalone-режим | Работает без Spring — чистый Java 21+ |

## Быстрый старт

### Spring Boot

```yaml
# application.yml
sso:
  issuer-uri: https://sso.company.com/application/o/my-app/
  client-id: my-service
  client-secret: ${SSO_CLIENT_SECRET}
```

Все бины (`SsoSdk`, `TokenValidator`, `ClientCredentialsClient`) зарегистрируются автоматически.

```java
@RestController
public class MyController {

    private final TokenValidator tokenValidator;

    public MyController(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
    }

    @GetMapping("/api/data")
    public ResponseEntity<?> getData(@RequestHeader("Authorization") String auth) {
        return switch (tokenValidator.validateFromHeader(auth)) {
            case ValidationOutcome.Valid v -> {
                if (v.token().hasScope("read:data")) {
                    yield ResponseEntity.ok(loadData());
                }
                yield ResponseEntity.status(403).build();
            }
            case ValidationOutcome.Rejected r -> {
                yield ResponseEntity.status(401).build();
            }
        };
    }
}
```

### Standalone (без Spring)

```java
var sdk = SsoSdk.create(SsoSdkConfiguration.builder()
        .issuerUri("https://sso.company.com/application/o/my-app/")
        .clientId("my-service")
        .clientSecret("secret")
        .build());

// Валидация токена
var outcome = sdk.tokenValidator().validate(jwt);

// Получение сервисного токена
var token = sdk.clientCredentials().acquireToken(Set.of("service:delegate"));
token.describeAuthorizationHeaderTo(header ->
    httpClient.header("Authorization", header)
);
```

### Из переменных окружения

```bash
export SSO_ISSUER_URI=https://sso.company.com/application/o/my-app/
export SSO_CLIENT_ID=my-service
export SSO_CLIENT_SECRET=secret
```

```java
var sdk = SsoSdk.create(); // Читает из переменных окружения
```

## Архитектура

```
SsoSdk (фасад)
├── TokenValidator          — валидация JWT (подпись, claims, expiration)
├── ClientCredentialsClient — получение сервисных токенов (кэш, автообновление)
├── OidcDiscoveryClient     — обнаружение эндпоинтов IdP (кэш с TTL)
├── BearerTokenFilter       — Jakarta Servlet фильтр для защиты эндпоинтов
└── SsoHttpTransport        — HTTP-клиент (java.net.http, без внешних зависимостей)
```

## Компоненты

### Валидация токенов (`TokenValidator`)

Двухуровневая валидация JWT:

1. **Криптографический уровень** — проверка подписи через JWKS (поддержка RS256, RS384, RS512, ES256, ES384, ES512)
2. **Доменный уровень** — проверка expiration, issuer, audience, извлечение scopes и client_id

```java
ValidationOutcome outcome = sdk.tokenValidator().validate(rawJwt);

switch (outcome) {
    case ValidationOutcome.Valid v -> {
        v.token().hasScope("admin");           // проверка scope
        v.token().belongsTo("user-123");       // проверка subject
        v.token().isIntendedFor("my-service"); // проверка audience
        v.token().hasExpired();                // проверка срока
    }
    case ValidationOutcome.Rejected r -> {
        r.describeReasonTo(System.out::println);  // причина отказа
        r.describeCodeTo(System.out::println);     // OAuth error code
    }
}
```

**Коды отказа (`RejectionReason`):**

| Код | Описание |
|---|---|
| `TOKEN_EXPIRED` | Токен просрочен |
| `INVALID_SIGNATURE` | Подпись не прошла верификацию |
| `ISSUER_MISMATCH` | Issuer не совпадает с ожидаемым |
| `AUDIENCE_MISMATCH` | Audience не совпадает |
| `MALFORMED_TOKEN` | Невалидная структура JWT |
| `UNKNOWN` | Непредвиденная ошибка |

### Client Credentials (`ClientCredentialsClient`)

Получение и кэширование сервисных токенов для межсервисного взаимодействия:

```java
var token = sdk.clientCredentials().acquireToken(Set.of("service:delegate"));

// Токены кэшируются по набору scopes и автоматически обновляются за 30 секунд до истечения
token.describeAuthorizationHeaderTo(header ->
    httpClient.header("Authorization", header)
);
```

Потокобезопасный — использует `ReentrantReadWriteLock`.

### Bearer Token Filter (`BearerTokenFilter`)

Jakarta Servlet фильтр для автоматической защиты эндпоинтов:

```yaml
sso:
  filter:
    enabled: true
    url-patterns: /api/*,/v1/*
    excluded-paths: /health,/actuator,/public
```

- При успешной валидации — кладёт `ValidatedToken` в атрибут запроса `sso.validated.token`
- При ошибке — возвращает HTTP 401 с заголовком `WWW-Authenticate: Bearer error="..."` и JSON-телом

```java
// В контроллере — токен уже валидирован фильтром
var token = (ValidatedToken) request.getAttribute(BearerTokenFilter.VALIDATED_TOKEN_ATTRIBUTE);
if (token.hasScope("admin")) { ... }
```

### On-Behalf-Of (`OnBehalfOfContext`)

Механизм делегирования для сценариев, когда backend-сервис действует от имени пользователя:

```java
var context = OnBehalfOfContext.extract(validatedToken, request.getHeader("X-Homni-On-Behalf-Of"));

context.ifPresent(ctx -> {
    ctx.isActingFor("user-123");              // проверка делегирования
    ctx.describeActingSubjectTo(sub -> ...);  // ID пользователя
    ctx.describeServiceSubjectTo(sub -> ...); // ID сервиса
});
```

Контекст создаётся **только** при наличии scope `service:delegate` **и** заголовка `X-Homni-On-Behalf-Of`.

### OIDC Discovery (`OidcDiscoveryClient`)

Автоматическое обнаружение эндпоинтов Identity Provider по стандарту RFC 8414:

- Запрашивает `{issuerUri}/.well-known/openid-configuration`
- Кэширует результат с настраиваемым TTL (по умолчанию 1 час)
- Потокобезопасный с `ReentrantReadWriteLock`
- Извлекает: token_endpoint, jwks_uri, issuer, authorization_endpoint, userinfo_endpoint

## Доменная модель

### `BearerToken`

Непрозрачный контейнер для bearer-токена. **Никогда не раскрывает значение через toString()** — защита от случайного логирования.

```java
var token = BearerToken.fromAuthorizationHeader("Bearer abc123");
token.describeTo(raw -> ...);          // доступ к значению через callback
token.applyAsHeader(header -> ...);    // "Bearer abc123"
token.toString();                       // "BearerToken[***]"
```

### `ValidatedToken`

Иммутабельное представление проверенного JWT с методами авторизации:

```java
token.belongsTo("user-id")                    // совпадение subject
token.hasScope("admin")                        // одиночный scope
token.hasAllScopes(Set.of("read", "write"))    // AND-логика
token.hasAnyScope(Set.of("admin", "manager"))  // OR-логика
token.isIntendedFor("my-api")                  // проверка audience
token.issuedByClient("web-app")               // проверка client_id
token.hasExpired()                              // срок действия
```

### `TokenInfo`

Пара access + refresh токен с отслеживанием жизненного цикла:

```java
token.isExpired()     // проверка срока
token.canRefresh()    // есть ли refresh token
token.toBearerToken() // конвертация в BearerToken для валидации
```

### `ValidationOutcome` (sealed interface)

Алгебраический тип для результата валидации — исчерпывающий pattern matching через Java 21 sealed interfaces:

```java
switch (outcome) {
    case ValidationOutcome.Valid v   -> // успех
    case ValidationOutcome.Rejected r -> // отказ с причиной
}
```

## Конфигурация

### Spring Boot properties

| Property | Описание | По умолчанию |
|---|---|---|
| `sso.issuer-uri` | URL Identity Provider (обязательный) | — |
| `sso.client-id` | OAuth client ID | — |
| `sso.client-secret` | OAuth client secret | — |
| `sso.audience` | Ожидаемый audience токена | — |
| `sso.scopes` | Scopes через запятую | `openid,profile,email` |
| `sso.http-timeout-seconds` | Таймаут HTTP-запросов | `10` |
| `sso.discovery-ttl-minutes` | TTL кэша OIDC Discovery | `60` |
| `sso.filter.enabled` | Включить BearerTokenFilter | `false` |
| `sso.filter.url-patterns` | URL-паттерны фильтра | `/api/*` |
| `sso.filter.excluded-paths` | Исключённые пути | `/actuator,/health` |

### Переменные окружения

| Переменная | Описание |
|---|---|
| `SSO_ISSUER_URI` | URL Identity Provider |
| `SSO_CLIENT_ID` | OAuth client ID |
| `SSO_CLIENT_SECRET` | OAuth client secret |

### Приоритет конфигурации

1. Явные значения в builder
2. Переменные окружения
3. System properties (`sso.issuer-uri`)
4. Значение по умолчанию для разработки: `http://localhost:9000/application/o/sso-platform/`

## Исключения

Иерархия sealed — компилятор гарантирует обработку всех вариантов:

```
SsoSdkException (sealed)
├── TokenValidationException   — ошибки валидации JWT (содержит RejectionReason)
└── IdentityProviderException  — ошибки связи с IdP (discovery, JWKS, token endpoint)
```

## Структура проекта

```
sso-sdk/src/main/java/com/ssoplatform/sdk/
├── SsoSdk.java                          Фасад — единая точка входа
├── config/
│   ├── SsoSdkConfiguration.java         Иммутабельная конфигурация, builder
│   └── SsoSdkAutoConfiguration.java     Spring Boot auto-configuration
├── credentials/
│   └── ClientCredentialsClient.java     Межсервисная авторизация, кэш токенов
├── delegation/
│   └── OnBehalfOfContext.java           Scope-gated делегирование
├── discovery/
│   ├── OidcDiscoveryClient.java         RFC 8414 discovery, TTL-кэш
│   └── OidcDiscoveryDocument.java       Распарсенный OIDC-документ
├── domain/
│   ├── model/
│   │   ├── BearerToken.java             Непрозрачный контейнер токена
│   │   ├── ValidatedToken.java          Проверенный JWT, методы авторизации
│   │   ├── TokenInfo.java               Пара access/refresh токен
│   │   ├── ValidationOutcome.java       Sealed результат валидации
│   │   └── RejectionReason.java         Коды отказа (enum)
│   └── exception/
│       ├── SsoSdkException.java         Sealed базовое исключение
│       ├── TokenValidationException.java
│       └── IdentityProviderException.java
├── filter/
│   └── BearerTokenFilter.java           Servlet фильтр защиты эндпоинтов
├── http/
│   └── SsoHttpTransport.java            HTTP-клиент (java.net.http)
└── validation/
    └── TokenValidator.java              Движок валидации JWT
```

## Принципы проектирования

- **Tell, Don't Ask** — доменные объекты не раскрывают состояние через геттеры, а принимают `Consumer<T>` для контролируемого извлечения данных
- **Sealed типы** — `ValidationOutcome` и `SsoSdkException` используют sealed interfaces/classes для исчерпывающего pattern matching
- **Потокобезопасность** — все кэши и lazy-инициализация защищены `ReentrantReadWriteLock` или `volatile` + double-checked locking
- **Безопасность** — bearer-токены не раскрываются в `toString()`, claims не экспонируются напрямую
- **Zero external HTTP dependencies** — используется `java.net.http.HttpClient` из Java 21+

## Зависимости

| Библиотека | Назначение |
|---|---|
| Nimbus JOSE JWT | Валидация JWT, работа с JWKS, проверка подписей |
| Jackson | Парсинг JSON |
| Jakarta Servlet API | Servlet Filter |
| Spring Boot (опционально) | Auto-configuration |
| SLF4J | Логирование |

**Требования:** Java 21+
