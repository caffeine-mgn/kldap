# kldap — Kotlin Multiplatform LDAP client

## Цель

Kotlin Multiplatform-библиотека LDAP-клиента, позволяющая делать **LDAP-авторизацию**
из Kotlin-кода на любом поддерживаемом KMP-таргете.

Целевой сценарий использования:

```kotlin
LdapClient.connect(
    host = "ldap.corp.example.com",
    port = 636,
    ssl = true,
    trust = { cert -> /* custom verify */ true },
).use { ldap ->
    // Простой bind (по DN + пароль)
    ldap.bind(Dn("cn=admin,dc=corp,dc=local"), "secret".toCharArray())

    // Сценарий «логин по username, не по DN»:
    val user = ldap.searchOne(
        baseDn = Dn("dc=corp,dc=local"),
        filter = Filter { eq("sAMAccountName", username) }
    )
    ldap.bind(user.dn, password.toCharArray())
}
```

## Требования

### KMP-таргеты
- `jvm`
- `linuxX64`
- `mingwX64` (Windows native)
- `macosArm64`
- `iosArm64`, `iosSimulatorArm64`, `iosX64`

### Транспорты
- **LDAP** (TCP/389, plaintext) — сразу
- **LDAPS** (TLS/636) — сразу

### Операции (фаза 1)
- `bind` (simple bind, анонимный + по DN/паролю)
- `search` (поиск DN/атрибутов пользователя по фильтру)
- Полный набор (modify/add/delete) — **не входит** в первую фазу.

## Принятые архитектурные решения

### Модули vs пакеты
**Один gradle-модуль с пакетами внутри.** Не несколько gradle-модулей.

Причина: BER-кодер (ASN.1) — это 70–80% работы, и он нужен всем операциям.
Делить по операциям на уровне gradle = множить overhead конфигурации и KMP-компиляции
(7 таргетов × N модулей) без реальной выгоды. Если позже появится причина отделить —
выделить подмодуль из готовых пакетов тривиально.

### Пакетная структура

```
pw/binom/ldap/
├── asn1/        ← BER-кодер/декодер (INTEGER, OCTET STRING, SEQUENCE, ENUMERATED, BOOLEAN)
├── protocol/    ← LdapMessage, BindRequest/Result, SearchRequest/Result, LDAPResult
├── transport/   ← expect LdapTransport + actualTcp (jvm/native)
│                 expect LdapTlsTransport + actualTls
├── connection/  ← LdapConnection (messageId generator, in-flight tracking, ответы по messageId)
└── client/      ← высокоуровневый API: LdapClient, bind(...), search(...), authenticate(...)
```

`asn1` и `transport` — стабильное ядро.
`protocol` строится поверх `asn1`.
`client` — фасад для пользователя.

### Стек (зависимости)
- **kotlinx-io** (`org.jetbrains.kotlinx:kotlinx-io`) — байтовый фрейминг LDAP-сообщений,
  `ByteReadPacket` / `ByteWriteChannel`, чтение/запись с таймаутами.
- **kotlinx-serialization** (`org.jetbrains.kotlinx:kotlinx-serialization`) —
  `@Serializable`-аннотации для LDAP-структур (DN, атрибуты). Не замена BER — это для
  удобной работы с DTO-обёртками поверх ASN.1.
- **ktor-network + ktor-network-tls** (`io.ktor:ktor-network*`) — TCP/TLS транспорт.

### Версии — gradle version catalog
`gradle/libs.versions.toml`. Все плагины и зависимости только оттуда.

**Актуальные на 2026-10-05** (взяты из `kDNS`, обновляются при сборке если есть более новые):

| Компонент | Версия |
|---|---|
| Kotlin | 2.3.10 |
| Ktor | 3.4.1 |
| kotlinx-io | 0.9.0 |
| Dokka | 2.2.0 |
| vanniktech-maven-publish | 0.37.0 |

## Решения по API

_(полный список с обоснованиями — финальная версия формата API)_

### Сигнатура `connect`
```kotlin
suspend fun LdapClient.Companion.connect(
    host: String,
    port: Int = if (ssl) 636 else 389,
    ssl: Boolean = false,
    coroutineContext: CoroutineContext = Dispatchers.IO,
    trust: ((X509Certificate) -> Boolean)? = null,
    disableHostnameVerification: Boolean = false,
    connectTimeout: Duration = 30.seconds,
    readTimeout: Duration = 60.seconds,
    writeTimeout: Duration = 30.seconds,
): LdapClient
```

- `host` / `port` / `ssl` — отдельные аргументы, без URL-парсинга.
- `trust` — лямбда для кастомного trust manager. По умолчанию — системный trust store.
- `disableHostnameVerification` — default `false` (TLS hostname verification ВКЛ).
- `coroutineContext` — default `Dispatchers.IO`. Клиент создаёт свой `CoroutineScope(context + Job)`.

### Клиент — `AutoCloseable`
- `connect()` возвращает `LdapClient`.
- `close()` — без `suspend` (закрытие сокета — быстрая op).
- `suspend fun unbind()` — отправляет UnbindRequest + закрывает сокет.
- `use { }` — поддерживается. После `unbind()` клиент мёртв, повторный `close()` — no-op.

### Методы клиента
```kotlin
suspend fun bind(dn: Dn, password: CharArray): LdapBindResult
suspend fun bindAnonymous(): LdapBindResult
suspend fun search(
    baseDn: Dn,
    filter: LdapFilter,
    scope: SearchScope = SearchScope.Subtree,
    requestedAttributes: List<String> = emptyList(),
    sizeLimit: Int? = null,
    timeLimit: Duration? = null,
    controls: List<Control> = emptyList(),
): List<SearchEntry>

suspend fun searchOne(...): SearchEntry  // = search().first()
```

- **Re-bind** разрешён: можно вызывать `bind()` многократно на одном клиенте.
- **Cancellation**: при отмене корутины посылаем UnbindRequest, закрываем TCP, отменяем Job.

### Domain types
```kotlin
@JvmInline value class Dn(val raw: String) {
    val components: List<DnComponent>
    companion object { fun of(vararg pairs: Pair<String, String>): Dn }
}

@JvmInline value class LdapFilter(val raw: String) {
    companion object { fun build(block: FilterBuilder.() -> Unit): LdapFilter }
}

// Примеры Filter DSL:
Filter { eq("uid", "alice") }
Filter { and { eq("uid", "alice"); eq("ou", "users") } }
Filter { or { eq("cn", "Alice"); eq("cn", "Alicia") } }
Filter { not { eq("uid", "bob") } }

data class SearchEntry(
    val dn: Dn,
    val attrs: Map<String, List<String>>,
)

data class LdapBindResult(
    val resultCode: Int,           // 0 = success
    val matchedDn: String? = null,
    val message: String? = null,
) {
    val isSuccess: Boolean get() = resultCode == 0
}

enum class SearchScope { Base, SingleLevel, Subtree }

// Controls
data class Control(
    val oid: String,
    val value: ByteArray? = null,
    val criticality: Boolean = false,
)

// Из коробки реализованы:
object PagedResults {
    fun request(pageSize: Int): Control
    fun next(cookie: ByteArray): Control
    fun parseResponse(value: ByteArray): PagedResultsCookie?
}

object ServerSideSort {
    fun request(sortKeys: List<SortKey>): Control
    // parseResponse — не в фазе 1
}

object ManageDsaIT {
    val feature: Control  // без value
}
```

### Ошибки
`sealed class LdapException(message, resultCode: Int, matchedDn: String? = null)`:
- `InvalidCredentialsException` (49)
- `NoSuchObjectException` (32)
- `SizeLimitExceededException` (4)
- `TimeLimitExceededException` (3)
- `BusyException` (51)
- `UnavailableException` (52)
- `UnwillingToPerformException` (53)
- `ReferralException` (10) — если сервер вернул referral
- `ProtocolException` — сетевые/парсинговые проблемы, неизвестные коды

Все подклассы несут `resultCode: Int` и `matchedDn: String?`.

### Логирование
Без логгера. Тихо. Если пользователю нужно — оборачивает вызовы на своей стороне.

## Тестирование

### Прод-код
`commonMain`. Не платформенный — один раз пишется для всех таргетов.

### Тесты общего кода (`commonTest`)
- BER encoder/decoder — round-trip на известных LDAP-сообщениях
- Протокольные модели — сериализация/десериализация

### Интеграционные (`jvmTest` only)
- Testcontainers + `bitnami/openldap:latest`
- Тесты bind/search/rebind/controls
- **Podman** у пользователя. Testcontainers: `TESTCONTAINERS_RUNTIME=podman` через env или `~/.testcontainers.properties`.

## Публикация

### Каналы
- `mavenLocal()` (для разработки)
- Maven Central (для публичного использования)

### Плагин публикации
`com.vanniktech.maven.publish` v0.37.0.

### Подпись
- **На CI**: gpg CLI через `signingUseGpg=true` + `useGpgCmd()`.
- **Локально**: in-memory PGP через `useInMemoryPgpKeys(key, keyId, password)` (Bouncy Castle).
- Конкретный паттерн — копируем `kdns/core/build.gradle.kts:103-124`.

### CI/CD
- **Триггер**: push тега вида `[0-9]+.[0-9]+.[0-9]+`.
- **Workflow**: копируем `https://github.com/caffeine-mgn/kdns/blob/master/.github/workflows/release.yml`.
- **GitHub Secrets**:
  - `GPG_PRIVATE_KEY` — ASCII-armored приватный ключ (с реальными newline).
  - `GPG_PASSWORD` — пароль от ключа.
  - `GPG_KEY_ID` — 16 hex-символов (`gpg --list-secret-keys --keyid-format LONG`).
  - `MAVEN_CENTRAL_USERNAME` — Sonatype Central Portal.
  - `MAVEN_CENTRAL_PASSWORD` — Sonatype Central Portal.

### Локальная настройка
`~/.gradle/gradle.properties`:
```properties
signingInMemoryKey=-----BEGIN PGP PRIVATE KEY BLOCK-----\n\n...\n=xxxx\n-----END PGP PRIVATE KEY BLOCK-----\n
signingInMemoryKeyId=XXXXXXXX
signingInMemoryKeyPassword=passphrase
mavenCentralUsername=username
mavenCentralPassword=password
```

## Roadmap (план работ для реализующей сессии)

1. Каркас проекта: `settings.gradle.kts`, корневой `build.gradle.kts`, `gradle/libs.versions.toml`
   с KMP-плагином, таргетами, kotlinx-io, kotlinx-serialization, ktor-network,
   Detekt + KtLint, vanniktech-maven-publish.
2. `asn1/` — BER-кодер и декодер (INTEGER, OCTET STRING, SEQUENCE, ENUMERATED, BOOLEAN).
   + `commonTest` round-trip тесты.
3. `protocol/` — модели `LdapMessage`, `BindRequest`, `BindResponse`, `SearchRequest`,
   `SearchResultEntry`, `SearchResultDone`, `LDAPResult`, `Control`.
4. `transport/` — TCP (LDAP) + TLS (LDAPS) поверх ktor-network.
5. `connection/` — корреляция запрос-ответ по messageID, таймауты, in-flight tracking.
6. `client/` — `LdapClient`, `bind(...)`, `search(...)`, `searchOne(...)`, `unbind()`, `close()`.
7. Domain types: `Dn`, `LdapFilter`, `FilterBuilder` (DSL), `SearchEntry`, `SearchScope`, `Control`,
   `LdapBindResult`, готовые controls (PagedResults, ServerSideSort, ManageDsaIT).
8. Exceptions: sealed `LdapException` со всеми подклассами по resultCode.
9. Integration tests (`jvmTest`): testcontainers + Bitnami OpenLDAP.
10. CI/CD: `.github/workflows/release.yml` по образцу kDNS.
11. README (EN) + README.ru.md + Dokka.

## Заметки для следующих сессий

- Эта сессия — **«сборщик PLAN.md»**. Кода не пишет, только уточняет требования и фиксирует решения.
- Следующая сессия (новый чат, открытый **внутри** каталога `kldap/`) начнёт реализацию строго по этому PLAN.md.
- Если в реализации выяснится, что нужно отклониться от плана — сначала обновить PLAN.md, потом менять код.

## Лог решений (обратная хронология)

- 2026-10-05 — Re-bind разрешён.
- 2026-10-05 — Линтеры: Detekt + KtLint.
- 2026-10-05 — `coroutineContext` (не `scope`) — аргумент `connect`.
- 2026-10-05 — CI только release на tag, без push/PR workflows.
- 2026-10-05 — Connect: `LdapClient.Companion.connect(host, port, ssl, ...)` — отдельные аргументы.
- 2026-10-05 — CHANGELOG.md ведём.
- 2026-10-05 — README EN + RU.
- 2026-10-05 — Без `@Experimental` аннотаций.
- 2026-10-05 — Cancellation: UnbindRequest + закрытие TCP + отмена Job.
- 2026-10-05 — Password — `CharArray`. Без копий внутри.
- 2026-10-05 — Без логгера.
- 2026-10-05 — Integration tests — testcontainers + Bitnami OpenLDAP.
- 2026-10-05 — `companion fun connect()` — фабрика.
- 2026-10-05 — `unbind()` поддерживаем.
- 2026-10-05 — CoroutineScope от пользователя, default `Dispatchers.IO`.
- 2026-10-05 — sealed `LdapException` с подклассами по resultCode.
- 2026-10-05 — TLS hostname verification вкл по умолчанию.
- 2026-10-05 — Без отдельного Config-класса, всё аргументами `connect()`.
- 2026-10-05 — Target server: AD + OpenLDAP (тесты на Bitnami OpenLDAP).
- 2026-10-05 — Default timeouts: 30s connect, 60s read, 30s write.
- 2026-10-05 — Search limits: `sizeLimit: Int?`, `timeLimit: Duration?`.
- 2026-10-05 — Filter: `value class LdapFilter` + DSL builder.
- 2026-10-05 — Connection pool: нет.
- 2026-10-05 — Lifecycle: `AutoCloseable` + `use { }`, `suspend fun close()` / обычный `close()`.
- 2026-10-05 — Документация: README + Dokka (как у kDNS).
- 2026-10-05 — SASL: только SIMPLE в фазе 1.
- 2026-10-05 — Controls: расширяемый API + PagedResults + ServerSideSort + ManageDsaIT.
- 2026-10-05 — Search return: `SearchEntry(dn, attrs)`.
- 2026-10-05 — DN: `value class Dn(val raw: String)` + `Dn.of()` + components().
- 2026-10-05 — Anonymous bind поддерживаем.
- 2026-10-05 — artifactId = `kldap`, group = `pw.binom`, namespace = `pw.binom.ldap.*`.
- 2026-10-05 — JVM target 1.8, iOS 14.0.
- 2026-10-05 — Тесты: общие (commonTest) + integration (jvmTest, testcontainers Bitnami OpenLDAP). Podman поддержка.
- 2026-10-05 — Публикация: mavenLocal + Central. CI/CD скопирован с kDNS (vanniktech-maven-publish, GPG подпись).
- 2026-10-05 — TLS — хук для trust manager.
- 2026-10-05 — Referrals — игнорируем в фазе 1.
- 2026-10-05 — Ошибки — sealed `LdapException` с подклассами.
- 2026-10-05 — API стиль — `suspend fun`.
- 2026-10-05 — Версия Kotlin — «самая свежайшая стабильная».
- 2026-10-05 — Транспорт: `io.ktor:ktor-network` + `ktor-network-tls`.
- 2026-10-05 — Один gradle-модуль, пакеты внутри.
- 2026-10-05 — Подтверждены таргеты: jvm, linuxX64, mingwX64, macosArm64, iosArm64, iosSimulatorArm64, iosX64.
- 2026-10-05 — Подтверждены транспорты: LDAP (389) + LDAPS (636) сразу.