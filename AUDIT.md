# ПОЛНЫЙ АРХИТЕКТУРНЫЙ АУДИТ — AuthGate SDK

**Scope:** 24 production files, ~1,540 LOC, 2 test files, 55 tests.

---

## БЛОК 1 — ЧИСТОТА АРХИТЕКТУРЫ И СЛОЁВ — 9/10

**Слои:**
| Слой | Пакеты | Оценка |
|------|--------|--------|
| Domain | `domain/model/`, `domain/service/`, `domain/exception/` | 10/10 |
| Application | `application/port/` | 9/10 |
| Infrastructure | `http/`, `discovery/`, `credentials/`, `validation/`, `filter/` | 8/10 |
| Config/Facade | `config/`, `AuthGate.java` | 8/10 |

**Dependency Rule — соблюдается строго.**
Domain-слой не импортирует ничего за пределами `java.*`. Проверено: ни один файл из `domain/` не содержит import-ов на `io.authgate.application`, `io.authgate.http`, `com.nimbusds`, `com.fasterxml`, `jakarta.*`.

🟡 **Medium** — `TokenValidator` (`validation/TokenValidator.java:16`) импортирует `domain.service.TokenValidationRules` напрямую вместо работы через порт. Это не нарушение dependency rule (infra зависит от domain), но создаёт жёсткую связку инфраструктуры с конкретным доменным сервисом:

```java
// Сейчас:
import io.authgate.domain.service.TokenValidationRules; // concrete class

// Альтернатива: можно принимать Function<ValidatedToken, ValidationOutcome>
// но это overengineering для SDK — текущий вариант оправдан.
```
**Вердикт: допустимо.** Для SDK уровня это нормально — порт для валидационных правил был бы избыточной абстракцией.

🟡 **Medium** — `AuthGate.java:46` хранит поле `DefaultHttpTransport transport` вместо интерфейса `HttpTransport`:
```java
// Плохо — AuthGate.java:46:
private final DefaultHttpTransport transport;

// Хорошо:
private final HttpTransport transport;
```
Это закрывает возможность подставить кастомный transport при создании facade.

---

## БЛОК 2 — ДОМЕННАЯ МОДЕЛЬ — 9/10

**Богатая модель — однозначно.** Это один из лучших аспектов проекта.

**Tell, Don't Ask** — последовательно применён во всех VO:
- `ValidatedToken` — 10 behavioral methods (`belongsTo`, `hasScope`, `hasAllScopes`, `hasAnyScope`, `isIntendedFor`, `issuedByClient`, `hasExpired`, `isIssuedBy`) + 4 describe-методов. Никаких геттеров.
- `BearerToken` — raw value доступен только через `describeTo` / `applyAsHeader`.
- `TokenInfo` — lifecycle behavior (`isExpired`, `canRefresh`) вместо геттеров.

**Value Objects — эталонные:**
- Иммутабельны (все `final` поля, `unmodifiableSet`)
- Самовалидирующиеся (`IssuerUri` проверяет null/blank/https, `BearerToken` проверяет blank)
- Equality по значению (`IssuerUri`, `BearerToken`, `DiscoveredEndpoints`, `DelegationContext`)

**Sealed ADT (`ValidationOutcome`)** — правильное использование Java 21 sealed interfaces для exhaustive pattern matching.

**Domain Services** — stateless (кроме `Clock` в `TokenValidationRules`, что корректно), чистая бизнес-логика.

🟢 **Low** — `ValidatedToken.Builder` не валидирует состояние полностью: `subject` проверяется на null, но не на blank. Пустая строка `""` — невалидный subject:
```java
// ValidatedToken.java:25:
this.subject = Objects.requireNonNull(builder.subject);
// → нужно:
if (builder.subject == null || builder.subject.isBlank())
    throw new IllegalArgumentException("subject must not be blank");
```

---

## БЛОК 3 — КАЧЕСТВО ООП — 8/10

### SOLID:

**S (SRP)** — 9/10. Каждый класс имеет одну ответственность. `TokenValidator` — на грани (JWKS initialization + claims mapping + validation orchestration), но для SDK это приемлемая гранулярность.

**O (OCP)** — 8/10. `ValidationOutcome` расширяем через sealed hierarchy. Но `RejectionReason` — enum, добавление нового reason требует модификации:
```java
// RejectionReason.java — закрытый для расширения enum.
// Для SDK это правильный выбор — пользователь не должен
// добавлять свои причины отклонения.
```

**L (LSP)** — 10/10. Sealed hierarchy `AuthGateException → TokenValidationException | IdentityProviderException` — корректна, контракт базового класса не нарушается.

**I (ISP)** — 9/10. Интерфейсы минимальны: `HttpTransport` — 2 метода, `EndpointDiscovery` — 1 метод.

**D (DIP)** — 8/10. Инфраструктурные адаптеры зависят от портов. Но:

🟠 **High** — `AuthGate.java:46,82` создаёт конкретные реализации напрямую, без возможности injection:
```java
// AuthGate.java:81-82:
this.transport = new DefaultHttpTransport(httpTimeout.get());
this.discoveryClient = new OidcDiscoveryClient(issuerUri, transport, discoveryTtl.get());

// Нет способа передать свой HttpTransport — facade жёстко привязан
// к DefaultHttpTransport. Пользователь, использующий OkHttp или Reactor,
// не может подставить свою реализацию.
```
**Рекомендация:** Добавить второй конструктор `AuthGate(AuthGateConfiguration, HttpTransport)`.

### Инкапсуляция — 10/10
Ни один доменный объект не утекает внутреннее состояние. `toString()` маскирует sensitive data (`BearerToken[***]`, `ValidatedToken[sub=***]`, `DelegationContext[service=***, actingFor=***]`).

### Полиморфизм — 9/10
`ValidationOutcome` — эталонное использование sealed + pattern matching. Нет ни одного `instanceof` chain.

---

## БЛОК 4 — РАСШИРЯЕМОСТЬ, ЗРЕЛОСТЬ, НАДЁЖНОСТЬ — 8/10

### Расширяемость — 7/10

🟠 **High** — Невозможность кастомизировать `HttpTransport` через facade (см. БЛОК 3, DIP).

🟡 **Medium** — `TokenValidator` нельзя расширить алгоритмами подписи. Набор `JWSAlgorithm` захардкожен в `initializeProcessor`:
```java
// TokenValidator.java:124-127:
JWSAlgorithm.RS256, JWSAlgorithm.RS384, JWSAlgorithm.RS512,
JWSAlgorithm.ES256, JWSAlgorithm.ES384, JWSAlgorithm.ES512
// EdDSA (Ed25519) не поддерживается — а это растущий стандарт
```

### Зрелость — 8/10
- Fail-fast валидация в конструкторах (все `Objects.requireNonNull`)
- `AuthGateConfiguration` — дефолты для всех необязательных полей
- `EnvironmentConfigurationResolver` — бросает `IllegalStateException` для обязательных полей

### Надёжность — 7/10

🟠 **High** — `DefaultHttpTransport.execute()` (`http/DefaultHttpTransport.java:71`) всегда парсит body как JSON. Если IdP вернёт HTML (502 от nginx), будет `JsonParseException`, обёрнутый в `IdentityProviderException` — пользователь не поймёт, что это сетевая ошибка:
```java
// DefaultHttpTransport.java:70-71:
var response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
Map<String, Object> body = objectMapper.readValue(response.body(), ...);
// Если response.body() = "<html>502 Bad Gateway</html>" → Jackson exception
```

### Поддерживаемость — 9/10
- Классы 40-166 строк — все компактны
- Методы 3-25 строк — ни одного god-метода
- Именование единообразно по всему проекту

---

## БЛОК 5 — FAANG PROXIMITY — 8/10

### Ясность намерений — 9/10
Код самодокументирующийся. `token.hasScope("admin")`, `token.belongsTo(userId)`, `token.isIssuedBy(issuer)` — читается как спецификация.

### Управление сложностью — 9/10
Hexagonal architecture для 1,540 LOC — идеальный баланс. Не underengineered, не overengineered.

### Консистентность — 9/10
Tell Don't Ask — везде. Builder pattern — везде. `Objects.requireNonNull` — везде. Sealed hierarchies — везде.

### Паттерны — уместны
- Builder (configuration, domain objects) — уместен
- Sealed + Records (ValidationOutcome) — уместен
- Port/Adapter (hexagonal) — уместен
- Double-checked locking (TokenValidator, AuthGate) — уместен

### Топ-5 что отделяет от FAANG:

1. **Нет инъекции HttpTransport в facade** — закрытая экосистема, нетестируемый facade
2. **Нет response-level error handling** — non-JSON responses вызовут cryptic errors
3. **Unbounded cache** в `ClientCredentialsClient.tokenCache` — potential memory leak
4. **Нет метрик/tracing hooks** — zero observability для production
5. **AtomicReference ceremony** — избыточная церемония извлечения значений из Tell Don't Ask

---

## БЛОК 6 — ПРОЦЕДУРНЫЙ КОД — 5%

🟡 **Medium** — `AuthGate` конструктор (`AuthGate.java:53-89`) — 36-строчный скрипт извлечения config через 11 `AtomicReference`:
```java
// AuthGate.java:56-66 — процедурный стиль:
var issuerUriStr = new AtomicReference<String>();
var clientIdStr = new AtomicReference<String>();
var clientSecretStr = new AtomicReference<String>();
// ... ещё 8 AtomicReference

// Рефакторинг: Config record с прямым доступом для internal use:
record ResolvedConfig(String issuerUri, String clientId, ...) {}
// AuthGateConfiguration.resolve() → ResolvedConfig
```

🟡 **Medium** — `ClientCredentialsClient.fetchToken()` (`credentials/ClientCredentialsClient.java:84-115`) — 31-строчная процедура: discover → extract endpoint → build params → post → check errors → parse → build:
```java
// Это допустимо для infrastructure adapter — процедурный стиль
// здесь оправдан, т.к. это действительно последовательная операция.
// Но AtomicReference на строке 86-87 — церемония:
var endpointRef = new AtomicReference<String>();
endpoints.describeTokenEndpointTo(endpointRef::set);
// Лучше: port мог бы возвращать endpoint напрямую
```

**Процент процедурного кода: ~5%.** Только конструктор `AuthGate` и `fetchToken` — всё остальное объектно-ориентированное.

---

## БЛОК 7 — ПОТЕНЦИАЛЬНЫЕ БАГИ И УЯЗВИМОСТИ

🟠 **High** — **Non-JSON response crash** (`DefaultHttpTransport.java:71`):
```java
Map<String, Object> body = objectMapper.readValue(response.body(), new TypeReference<>() {});
// 502/503 от reverse proxy → HTML body → JsonParseException
// Fix: проверять Content-Type и/или statusCode перед парсингом
```

🟠 **High** — **Unbounded token cache** (`ClientCredentialsClient.java:32`):
```java
private final Map<String, CachedToken> tokenCache = new HashMap<>();
// Если acquireToken вызывается с разными наборами scopes,
// cache растёт бесконечно. В long-running сервисе → memory leak.
// Fix: LRU cache (LinkedHashMap с removeEldestEntry) или ConcurrentHashMap с maxSize
```

🟡 **Medium** — **JWKS URI freeze** (`TokenValidator.java:103-113`):
```java
// Processor инициализируется один раз. Если IdP мигрирует и JWKS URI
// меняется в discovery document, TokenValidator продолжит использовать
// старый URI. Старая версия (SsoSdk) отслеживала currentJwksUri.
// Fix: добавить refresh hook или периодическую переинициализацию
```

🟡 **Medium** — **HttpClient не закрывается** (`DefaultHttpTransport.java:29`):
```java
this.httpClient = HttpClient.newBuilder()...build();
// HttpClient implements AutoCloseable в Java 21.
// При GC пул потоков executor закроется, но explicit close — best practice.
// DefaultHttpTransport should implement Closeable.
```

🟡 **Medium** — **Race in resolveRefreshAt** (`ClientCredentialsClient.java:136-138`):
```java
var result = new AtomicReference<>(Instant.now().plus(Duration.ofHours(1)));
token.describeExpiresInTo(exp -> result.set(Instant.now().plus(exp).minus(REFRESH_MARGIN)));
// Два вызова Instant.now() — race condition между default и actual значением.
// Не критично, но default 1h может "мигнуть" на наносекунды.
```

🟢 **Low** — **ParseException ignored** (`TokenValidator.java:158`):
```java
} catch (ParseException ignored) {}
// Если scope claim содержит невалидный JSON array, ошибка проглатывается.
// Лучше: log.trace("scope claim is not a string list", ignored)
```

🟢 **Low** — **Dead fields** (`OidcDiscoveryDocument.java:19-20`):
```java
private final String authorizationEndpoint;  // never read
private final String userinfoEndpoint;       // never read
```

---

## БЛОК 8 — МАСШТАБИРУЕМОСТЬ — 8/10

**Горизонтальная** — 9/10. SDK stateless по design (каждый инстанс независим). Кэши thread-safe, state in-memory — при масштабировании каждый инстанс будет иметь свой кэш (acceptable для OIDC discovery + client credentials).

**Вертикальная** — 8/10. Единственное узкое место — синхронный HTTP (`httpClient.send()`). Для SDK это нормально — async был бы overengineering.

**Доменная** — 9/10. Пакетная структура чётко модульна. Выделение `credentials/` или `filter/` в отдельный артефакт — trivial.

**Coupling** — 8/10. Facade `AuthGate` импортирует конкретные классы из всех пакетов — но это ожидаемо для facade.

🟡 **Medium** — **Stateful components:**
- `OidcDiscoveryClient.cached` — mutable state, но protected by RWLock
- `ClientCredentialsClient.tokenCache` — mutable, unbounded (см. БЛОК 7)
- `TokenValidator.jwtProcessor` — write-once, safe

---

## БЛОК 9 — ПРОИЗВОДИТЕЛЬНОСТЬ — 8/10

**Domain Layer** — 10/10. Все операции O(1): `Set.contains()`, `String.equals()`, `Clock.instant().isAfter()`.

**Infrastructure Layer:**

🟡 **Medium** — `BearerTokenFilter.isExcluded()` (`filter/BearerTokenFilter.java:81-83`):
```java
return excludedPaths.stream().anyMatch(path::startsWith);
// O(n) на каждый запрос. Для маленьких наборов OK,
// но Trie или HashSet с prefix matching был бы O(1).
// Для SDK с 3-5 excluded paths — acceptable.
```

🟢 **Low** — `OidcDiscoveryClient.discover()` (`discovery/OidcDiscoveryClient.java:47-48`) создаёт `new IssuerUri(doc.resolveIssuer())` на каждый вызов. IssuerUri.normalized вычисляется каждый раз:
```java
// discover() вызывается на каждую валидацию (через TokenValidator).
// При cache hit — дешёвая операция, но new IssuerUri() + String concat
// создают мусор. Можно кэшировать DiscoveredEndpoints вместе с doc.
```

**Hotspot:** `TokenValidator.validate()` — на горячем пути (каждый HTTP запрос). Профиль: `ensureProcessorInitialized()` (check volatile) → `jwtProcessor.process()` (Nimbus) → `mapToValidatedToken()` (allocation) → `validationRules.validate()` (comparisons). Nimbus — основной bottleneck (crypto verification). SDK overhead минимален.

---

## БЛОК 10 — ОБРАБОТКА ОШИБОК — 8/10

**Error Hierarchy** — 9/10. Sealed `AuthGateException` → `TokenValidationException | IdentityProviderException`. Exhaustive, типизированная.

**Result Pattern** — 10/10. `ValidationOutcome` — эталонная реализация Result-паттерна через sealed interface + records. Нет exception-driven control flow в валидации.

**Fail-Fast** — 9/10. Все конструкторы: `Objects.requireNonNull`, `isBlank()` checks. `EnvironmentConfigurationResolver` бросает `IllegalStateException` для обязательных полей.

**Error Propagation** — 8/10. Контекст сохраняется через chain: `new IdentityProviderException("message", cause)`.

🟡 **Medium** — Broad catch в `TokenValidator.validate()` (`validation/TokenValidator.java:62-64`):
```java
} catch (Exception e) {
    log.error("Unexpected error during JWT processing", e);
    return new ValidationOutcome.Rejected(RejectionReason.UNKNOWN);
}
// Ловит всё, включая NullPointerException и IllegalStateException.
// Лучше ловить JOSEException (base class Nimbus exceptions):
} catch (com.nimbusds.jose.JOSEException e) {
```

🟡 **Medium** — Broad catch в `OidcDiscoveryClient.fetchDiscoveryDocument()` (`discovery/OidcDiscoveryClient.java:110`):
```java
} catch (Exception e) {
    throw new IdentityProviderException("Failed to fetch...", e);
}
// Та же проблема — ловит RuntimeException (NPE, etc.)
```

**Проглоченных ошибок нет,** кроме `ParseException ignored` в `TokenValidator.java:158`.

---

## БЛОК 11 — БЕЗОПАСНОСТЬ — 8/10

**Sensitive data exposure** — 9/10. `toString()` маскирует subject, tokens. Логирование не содержит raw JWT или credentials.

🟡 **Medium** — `ClientCredentialsClient.fetchToken()` (`credentials/ClientCredentialsClient.java:92`) передаёт `client_secret` в POST form — это стандартный OAuth flow, но:
```java
params.put("client_secret", clientSecret);
// Если transport логирует request body на DEBUG — secret утечёт.
// DefaultHttpTransport не логирует body, но кастомные реализации могут.
```

🟡 **Medium** — `AuthGate.java:88` хранит `clientSecret` как `String`:
```java
this.clientSecret = clientSecretStr.get();
// String в JVM intern-ится, может оставаться в памяти после GC.
// Для SDK это acceptable, но char[] был бы безопаснее.
```

**BearerTokenFilter** — 8/10:
- Корректно проверяет `Authorization: Bearer` header
- Возвращает 401 с `WWW-Authenticate` (RFC 6750)
- `escapeJson()` (`filter/BearerTokenFilter.java:95-97`) — минималистичный, но достаточный для фиксированных enum-строк

🟡 **Medium** — `escapeJson()` не escapes `\n`, `\r`, `\t`, `\b`, `\f`:
```java
private String escapeJson(String v) {
    return v.replace("\\", "\\\\").replace("\"", "\\\"");
}
// RejectionReason descriptions — фиксированные строки без спецсимволов.
// Но если код эволюционирует, это может стать проблемой.
// Fix: использовать ObjectMapper.writeValueAsString()
```

**Input validation** — 9/10. На boundary layer: `IssuerUri` валидирует URI, `BearerToken` валидирует value, `AuthGateConfiguration.Builder` проверяет required fields.

---

## БЛОК 12 — УСТОЙЧИВОСТЬ (RESILIENCE) — 5/10

🔴 **Critical** — **Нет retry для HTTP вызовов.** `DefaultHttpTransport.execute()` — single attempt. Временный 503 от IdP → `IdentityProviderException` → сервис падает:
```java
// DefaultHttpTransport.java:68-78 — zero retry
private TransportResponse execute(HttpRequest request) {
    try {
        var response = httpClient.send(request, ...);
        // Single attempt. Transient failure = permanent failure.
```

🟠 **High** — **Нет Circuit Breaker.** Если IdP недоступен, каждый HTTP запрос будет блокировать поток на `connectTimeout` (10s default). При 100 req/s = 100 заблокированных потоков за 1 секунду.

🟡 **Medium** — **Timeout есть**, но только `connectTimeout`. Нет `request timeout`:
```java
// DefaultHttpTransport.java:29:
.connectTimeout(connectTimeout)
// Нет .timeout() на HttpRequest — если сервер принял соединение
// но не отвечает, запрос висит бесконечно.
// Fix: HttpRequest.newBuilder().timeout(requestTimeout)
```

🟡 **Medium** — **JWKS initialization failure — permanent.** Если `ensureProcessorInitialized()` бросает `IdentityProviderException`, processor остаётся `null`. Следующий вызов `validate()` повторит попытку (correct). Но нет backoff — при flood-е запросов каждый будет бить IdP.

**Nimbus retrying(true)** — единственный resilience mechanism. Nimbus сам retry-ит JWKS fetches при key rotation. Это покрывает только JWKS, не discovery и не token endpoint.

---

## БЛОК 13 — СОГЛАСОВАННОСТЬ ДАННЫХ — 8/10

SDK не работает с БД напрямую, но:

**Optimistic/Pessimistic locking:**
- `OidcDiscoveryClient` — RWLock: read lock для cache hit, write lock для refresh. Корректно.
- `ClientCredentialsClient` — RWLock: аналогично. Корректно.
- `TokenValidator` — double-checked locking с `volatile`. Корректно.

🟢 **Low** — `OidcDiscoveryClient.discover()` + `OidcDiscoveryClient.refresh()` — `refresh()` (`discovery/OidcDiscoveryClient.java:57-68`) не atomic с `discover()`. Между ними возможен stale read. Но для discovery document с TTL=1h это не проблема.

**Race conditions в бизнес-логике — нет.** Domain model stateless/immutable. Все mutable state — в infrastructure caches, protected by locks.

---

## БЛОК 14 — НАБЛЮДАЕМОСТЬ — 4/10

🟠 **High** — **Нет correlation/trace ID.** Ни один log message не содержит request context:
```java
// TokenValidator.java:144:
log.info("JWT processor initialized with JWKS from: {}", jwksUri);
// В production с 1000 req/s — бесполезно без trace ID.
```

**Log levels** — 7/10. В целом корректны:
- `debug` — JWT parse/signature errors (per-request, high volume)
- `info` — initialization, discovery loaded (lifecycle events)
- `error` — unexpected exceptions

Но:
```java
// OidcDiscoveryClient.java:106:
log.info("OIDC discovery loaded from: {}", discoveryUrl);
// При cacheTtl=1h это info каждый час. Лучше debug после первого раза.
```

🔴 **Critical** — **Нет hooks для метрик.** Нет способа отследить:
- Token validation latency
- Cache hit/miss ratio
- HTTP call duration/errors
- Discovery refresh frequency

Для FAANG-уровня SDK должен предоставлять callback-и или MeterRegistry integration point.

🟡 **Medium** — **Нет sensitive data в логах** — это плюс. `jwksUri` логируется, но это публичная информация.

---

## БЛОК 15 — DDD СТРАТЕГИЧЕСКИЙ УРОВЕНЬ — 7/10

**Bounded Context** — один: AuthGate SDK. Это правильно для SDK — один BC, чёткая граница.

**Ubiquitous Language** — 8/10:
- `ValidatedToken`, `BearerToken`, `DelegationContext`, `IssuerUri` — бизнес-термины OIDC
- `TokenValidationRules`, `DelegationPolicy` — domain service names отражают бизнес-намерение

🟡 **Medium** — `DiscoveredEndpoints` — технический термин, не бизнесовый. `IdentityProviderMetadata` был бы ближе к RFC 8414.

**Context Mapping** — ACL: `TokenValidator.mapToValidatedToken()` (`validation/TokenValidator.java:84-101`) — Anti-Corruption Layer, трансформирует Nimbus `JWTClaimsSet` в доменную модель `ValidatedToken`. Корректно.

**Aggregate boundaries** — N/A для SDK без persistence. Но:

🟢 **Low** — `DelegationPolicy` хранит `actingSubjectHeaderName` — это HTTP-specific knowledge в domain service:
```java
// domain/service/DelegationPolicy.java:20:
private final String actingSubjectHeaderName;
// Header name — инфраструктурное понятие. Domain service не должен знать
// о HTTP headers. Но DelegationPolicy использует его только для describe,
// а evaluate принимает уже готовый string value. Это borderline.
```

---

## БЛОК 16 — API DESIGN И КОНТРАКТЫ — 8/10

**Public API surface** (для пользователей SDK):
- `AuthGate` — 5 public methods: `validateToken`, `validateTokenFromHeader`, `evaluateDelegation`, `acquireClientToken`, `createFilter`
- `AuthGateConfiguration.Builder` — fluent API, 12 setters
- `ValidationOutcome` — sealed ADT с exhaustive switch
- `ValidatedToken` — behavioral API, 10 decision methods + 4 describe

**Контракт-ориентированность** — 9/10. Доменные объекты не утекают наружу. `JWTClaimsSet` (Nimbus) → `ValidatedToken` (domain) через ACL.

🟡 **Medium** — `AuthGate.evaluateDelegation()` принимает `String onBehalfOfHeader` — raw HTTP header value. Пользователю нужно знать, какой header читать:
```java
// AuthGate.java:111:
public Optional<DelegationContext> evaluateDelegation(
    ValidatedToken token, String onBehalfOfHeader)
// Пользователь должен сам прочитать request.getHeader("X-Acting-Subject")
// Но он может не знать имя header. SDK не expose-ит его.
// Fix: добавить метод getDelegationHeaderName() или describe метод.
```
Впрочем, `DelegationPolicy.describeHeaderNameTo()` существует, но не проброшен через facade.

---

## БЛОК 17 — ИММУТАБЕЛЬНОСТЬ И КОНКУРЕНТНОСТЬ — 8/10

**Immutable Value Objects** — 10/10. Все VO иммутабельны: `final` fields, `unmodifiableSet`, private constructor.

**Thread safety:**
- `TokenValidator.jwtProcessor` — `volatile` + double-checked locking ✓
- `OidcDiscoveryClient.cached` — `volatile` + RWLock ✓
- `ClientCredentialsClient.tokenCache` — RWLock ✓
- `AuthGate.clientCredentialsClient` — `volatile` + synchronized ✓

**Mutable shared state:**

🟡 **Medium** — `ClientCredentialsClient.tokenCache` (`credentials/ClientCredentialsClient.java:32`) — `HashMap` protected by RWLock, но unbounded growth. С RWLock корректно синхронизирован, но нет eviction.

🟢 **Low** — `DefaultHttpTransport.objectMapper` — immutable after construction, thread-safe by Jackson guarantees. ✓

**Нет async/await, нет deadlock risks.** Все операции синхронные. RWLock usage не допускает lock escalation (read → write atomically) — но этого и не делается: read lock release → write lock acquire.

---

## БЛОК 18 — ТЕХНИЧЕСКИЙ ДОЛГ — 7/10

**Cyclomatic Complexity** — 7/10:
| Метод | CC | Оценка |
|-------|-----|--------|
| `TokenValidator.validate()` | 4 (3 catch + normal) | OK |
| `BearerTokenFilter.doFilter()` | 5 | OK |
| `ClientCredentialsClient.fetchToken()` | 4 | OK |
| `AuthGate` constructor | 1 (linear) | OK, но long |

**Coupling** — 8/10. Afferent coupling на domain model — высокий (все зависят от `ValidatedToken`, `ValidationOutcome`). Это ожидаемо и правильно — domain core.

**Code Duplication:**

🟡 **Medium** — AtomicReference extraction pattern повторяется ~15 раз:
```java
// Повторяется в AuthGate, DelegationPolicy, ClientCredentialsClient, BearerTokenFilter:
var ref = new AtomicReference<String>();
something.describeXTo(ref::set);
var value = ref.get();
// Это ceremony tax от Tell Don't Ask. Можно вынести в utility:
// static <T> T extract(Consumer<Consumer<T>> describer)
```

**Dead Code:**

🟡 **Medium** — `OidcDiscoveryDocument.java:19-20`:
```java
private final String authorizationEndpoint;  // never accessed
private final String userinfoEndpoint;       // never accessed
```

🟡 **Medium** — `AuthGateConfiguration.isConfidentialClient()` (`config/AuthGateConfiguration.java:68-70`) — package-private, never called:
```java
boolean isConfidentialClient() {
    return clientSecret != null && !clientSecret.isBlank();
}
```

**Оценка техдолга: ~8-12 человеко-часов** (все Medium/Low issues).

---

## БЛОК 19 — КОНФИГУРАЦИЯ И ОКРУЖЕНИЕ — 8/10

**12-Factor App:**
- Factor III (Config in env) — ✓ `EnvironmentConfigurationResolver` reads `AUTHGATE_*`
- Factor XI (Logs as event streams) — ✓ SLF4J → stdout

🟡 **Medium** — `EnvironmentConfigurationResolver` резолвит только 3 из 12 полей:
```java
// resolve() → issuerUri, clientId, clientSecret
// Не резолвит: audience, clockSkew, requireHttps,
// delegationHeaderName, delegationScope, filterTokenAttribute
// Пользователь вынужден использовать Builder для полной настройки.
```

**Secrets Management** — 8/10. Нет хардкода credentials (removed default `sso-platform-device`). `clientSecret` приходит из env/config.

🟢 **Low** — Нет feature flags. Для SDK размером 1.5K LOC — не нужны.

---

## БЛОК 20 — СТИЛЬ И ЧИТАЕМОСТЬ — 9/10

### Именование — 9/10
- Переменные: `expectedIssuer`, `clockSkewTolerance`, `actingSubjectHeaderName` — intention-revealing ✓
- Методы: `hasScope()`, `belongsTo()`, `isIntendedFor()`, `hasExpired()` — boolean is/has prefix ✓
- Классы: нет `*Manager`, `*Helper`, `*Utils` ✓
- Магические числа: `Duration.ofSeconds(30)`, `Duration.ofHours(1)` — вынесены в `DEFAULT_TTL`, `REFRESH_MARGIN` ✓

🟢 **Low** — `v` в Builder setters — non-descriptive:
```java
// AuthGateConfiguration.Builder:
public Builder issuerUri(String v) { this.issuerUri = v; return this; }
// Допустимо для fluent builder — parameter name не видна в call site.
```

### Длина и сложность — 10/10
- Максимальный класс: `TokenValidator.java` — 166 строк ✓
- Максимальный метод: `AuthGate` constructor — 36 строк (церемония, не сложность)
- Вложенность: максимум 2 уровня (`if` inside `synchronized`) ✓
- Guard clauses используются: `BearerTokenFilter.doFilter()` ✓

### Выразительность — 9/10
```java
// Читается как спецификация:
if (token.hasExpired(clock)) return rejected(TOKEN_EXPIRED);
if (!token.isIssuedBy(expectedIssuer)) return rejected(ISSUER_MISMATCH);
```

### Консистентность — 9/10
- Builder pattern — одинаковый стиль везде
- Tell Don't Ask — `describeTo(Consumer<T>)` — единообразно
- Error wrapping — `new IdentityProviderException(msg, cause)` — везде

### Единственное смешение стилей:
🟡 **Medium** — `TokenValidator.validateFromHeader()` бросает `IllegalArgumentException`, а `BearerTokenFilter` проверяет тот же header и возвращает 401. Два разных подхода к одному невалидному input:
```java
// TokenValidator.java:75 — бросает exception:
throw new IllegalArgumentException("Invalid Authorization header...");
// BearerTokenFilter.java:59-61 — возвращает 401:
sendError(httpResp, "missing_token", "Authorization header...");
// Filter вызывает validateFromHeader, который бросит — но filter
// проверяет header раньше, поэтому exception не достигается.
// Потенциальная проблема: если кто-то вызовет validateFromHeader
// напрямую с null — получит IAE, а не ValidationOutcome.Rejected.
```

---

## БЛОК 21 — DDD ДОМЕННАЯ МОДЕЛЬ — 9/10

### Чеклист:
| Критерий | Статус |
|----------|--------|
| Невозможно создать невалидный объект домена | ✅ (конструкторы валидируют) |
| Все инварианты внутри агрегата | ✅ |
| Нет публичных сеттеров | ✅ |
| Value Objects иммутабельны и самовалидны | ✅ |
| Нет примитивной одержимости в домене | ✅ (`IssuerUri`, `BearerToken` вместо `String`) |
| Доменный слой не зависит от внешнего | ✅ |
| Каждый метод выражает бизнес-намерение | ✅ |
| Термины кода = термины бизнеса | ✅ (OIDC vocabulary) |

🟡 **Medium** — Примитивная одержимость на границе: `expectedAudience` в `TokenValidationRules` — `String`. Если бы аудиенций было несколько, это бы провалилось. Но OIDC audience — single string, так что допустимо.

🟢 **Low** — `ValidatedToken.Builder()` — публичный конструктор. Теоретически пользователь SDK может создать `ValidatedToken` с произвольными claims. Для SDK это необходимо (тестируемость), но стоит задокументировать "internal use only".

---

## ИТОГОВАЯ ТАБЛИЦА ОЦЕНОК

| Критерий | Оценка | Приоритет | Сложность фикса |
|----------|--------|-----------|-----------------|
| Чистота архитектуры | 9/10 | 🟢 Low | Low |
| Доменная модель (богатство) | 9/10 | 🟢 Low | Low |
| Качество ООП | 8/10 | 🟠 High | Med |
| Расширяемость и поддерживаемость | 8/10 | 🟠 High | Med |
| FAANG proximity | 8/10 | 🟡 Medium | Med |
| Процедурный код (~5%) | 9/10 | 🟢 Low | Low |
| Потенциальные баги | 7/10 | 🟠 High | Med |
| Масштабируемость | 8/10 | 🟡 Medium | Low |
| Производительность | 8/10 | 🟢 Low | Low |
| Обработка ошибок | 8/10 | 🟡 Medium | Med |
| Безопасность | 8/10 | 🟡 Medium | Low |
| Устойчивость (Resilience) | 5/10 | 🔴 Critical | High |
| Согласованность данных | 8/10 | 🟢 Low | Low |
| Наблюдаемость | 4/10 | 🔴 Critical | High |
| DDD стратегия | 7/10 | 🟡 Medium | Med |
| API Design | 8/10 | 🟡 Medium | Med |
| Иммутабельность / конкурентность | 8/10 | 🟡 Medium | Low |
| Технический долг | 7/10 | 🟡 Medium | Med |
| Конфигурация | 8/10 | 🟢 Low | Low |
| Стиль и читаемость | 9/10 | 🟢 Low | Low |
| DDD доменная модель | 9/10 | 🟢 Low | Low |
| **ИТОГО СРЕДНЯЯ** | **7.8/10** | | |

---

## ФИНАЛЬНЫЙ ВЕРДИКТ

### TOP-5 КРИТИЧЕСКИХ УЛУЧШЕНИЙ

**1. 🔴 Non-JSON response crash + отсутствие request timeout**
- `DefaultHttpTransport.java:70-71` — парсит любой response body как JSON
- `DefaultHttpTransport.java:29` — нет request timeout, только connect timeout
- Fix: проверить status code и content-type перед парсингом; добавить `.timeout()` на каждый `HttpRequest`
- ~2 часа

**2. 🔴 Нет retry/resilience для HTTP**
- Discovery fetch, token acquisition — single attempt
- 503 от IdP = полный отказ SDK
- Fix: retry с exponential backoff в `DefaultHttpTransport.execute()` (3 attempts, 100ms/500ms/2s)
- ~4 часа

**3. 🟠 Unbounded token cache**
- `ClientCredentialsClient.tokenCache` — grows forever
- Fix: `LinkedHashMap` с `removeEldestEntry(size > 64)` или Caffeine
- ~1 час

**4. 🟠 Facade не принимает кастомный HttpTransport**
- `AuthGate` жёстко создаёт `DefaultHttpTransport`
- Пользователь не может использовать OkHttp, interceptors, mTLS
- Fix: добавить `AuthGate(AuthGateConfiguration, HttpTransport)`; хранить `HttpTransport` вместо `DefaultHttpTransport`
- ~1 час

**5. 🟠 Zero observability hooks**
- Нет метрик, tracing, correlation ID
- Production debugging невозможен
- Fix: optional `EventListener` interface с callbacks `onTokenValidated`, `onDiscoveryRefreshed`, `onTokenAcquired` + MDC correlation ID support
- ~6 часов

---

### ROADMAP ДО FAANG-УРОВНЯ

#### 🔴 Фаза 1 — Стабилизация (0-2 недели) — ~12 часов
| Задача | Часы |
|--------|------|
| Request timeout на HttpRequest | 1 |
| Non-JSON response handling (check Content-Type before parse) | 2 |
| Retry с backoff в DefaultHttpTransport (3 attempts) | 4 |
| Bounded token cache (LRU, max 64 entries) | 1 |
| Remove dead fields в OidcDiscoveryDocument | 0.5 |
| Remove dead method `isConfidentialClient()` | 0.5 |
| Log ParseException instead of ignoring | 0.5 |
| Narrow catch(Exception) to specific types | 1 |
| Validate subject/issuer not blank in ValidatedToken | 0.5 |
| DefaultHttpTransport implements Closeable | 1 |

#### 🟠 Фаза 2 — Архитектурное усиление (2-6 недель) — ~20 часов
| Задача | Часы |
|--------|------|
| AuthGate accepts HttpTransport (DIP fix) | 2 |
| AuthGate field type → HttpTransport interface | 1 |
| Observability: EventListener interface + basic hooks | 6 |
| MDC correlation ID в log messages | 2 |
| EnvironmentConfigurationResolver: все 12 полей из env | 3 |
| Пробросить delegationHeaderName через AuthGate facade | 1 |
| Configurable JWS algorithms через AuthGateConfiguration | 2 |
| JWKS URI change detection (restore from old version) | 3 |

#### 🟡 Фаза 3 — Инженерное совершенство (6-12 недель) — ~16 часов
| Задача | Часы |
|--------|------|
| Extract `ConfigExtractor` utility для AtomicReference ceremony | 3 |
| `escapeJson()` → Jackson ObjectMapper | 1 |
| Circuit breaker для HTTP (optional, callback-based) | 6 |
| Benchmark: validate() latency profiling | 2 |
| Integration test с embedded OIDC server (WireMock) | 4 |

---

**Финальная оценка: 7.8/10 — Strong Junior Staff / Solid Senior level.**

Domain model и архитектура — на 9/10. Главные gaps: resilience (нет retry), observability (нет метрик), и minor flexibility issue (DIP в facade). Для SDK v1.0 это высокое качество. После Фазы 1 (12 часов) — это production-ready. После Фазы 2 — это FAANG-ready.
