# kldap

**Kotlin Multiplatform LDAP-клиент** — компактная библиотека LDAPv3 (RFC 4511),
которая работает на любом поддерживаемом KMP-таргете: JVM, Linux, Windows,
macOS, iOS.

Поверх [Ktor Network](https://github.com/ktorio/ktor)-`ktor-network`/`ktor-network-tls`
для TCP/TLS и собственного ASN.1 BER-кодека. Никаких реактивных рантаймов,
никаких JVM-only зависимостей в ядре — всё в `commonMain`.

## Возможности

- **LDAP** (plaintext, порт 389) и **LDAPS** (TLS, порт 636).
- **Bind** — анонимный, простой (DN + пароль). SASL-каркас есть, но не
  оркестрируется в фазе 1.
- **Search** — base/single-level/subtree, произвольные фильтры,
  пагинация через controls.
- **Полный набор операций RFC 4511** — add, modify, delete, modify-DN,
  compare, abandon, unbind.
- **Мульти-таргет** — `jvm`, `linuxX64`, `mingwX64`, `macosArm64`,
  `iosArm64`, `iosSimulatorArm64`, `iosX64`.
- Без slf4j/log4j/логирования вообще — тишина by design.

## Использование

```kotlin
import pw.binom.ldap.client.LdapClient
import pw.binom.ldap.domain.*
import pw.binom.ldap.protocol.Authentication

// Проверка пароля против корпоративного LDAP/AD:
LdapClient.connect(
    host = "ldap.corp.example.com",
    port = 636,
    ssl = true,
).use { ldap ->
    val bind = ldap.bind("cn=admin,dc=corp,dc=local", Authentication.Simple("secret"))
    if (!bind.isSuccess) {
        // 49 = invalid credentials, 53 = locked, и т.д.
        throw InvalidCredentialsException(message = bind.message)
    }

    // Логин по username, не по DN: ищем пользователя, биндимся от его DN.
    val user = ldap.searchOne(
        baseDn = Dn.of("dc=corp,dc=local"),
        scope = SearchScope.Subtree,
        filter = Filter { eq("sAMAccountName", username) },
    )
    ldap.bind(Dn.of(user.dn.raw), Authentication.Simple(password))
}
```

То же самое работает на iOS/Android/Windows — меняется только подключение.

### Поиск

`search(...)` возвращает suspend-flow событий. Собирайте через
`searchAll(...)`/`searchOne(...)` или итерируйтесь:

```kotlin
val events = ldap.searchAll(
    baseDn = Dn.of("ou=people,dc=corp,dc=local"),
    scope = SearchScope.Subtree,
    filter = Filter {
        and {
            eq("objectClass", "person")
            present("mail")
        }
    },
    attributes = listOf("cn", "mail", "telephoneNumber"),
)
for (event in events) {
    when (event) {
        is LdapResponse.Entry ->
            println("найден: ${event.op.responseName} cn=${entry.firstString("cn")}")
        is LdapResponse.Done -> {} // поиск завершён
    }
}
```

### DSL фильтров

```kotlin
Filter { eq("uid", "alice") }
Filter { and { eq("uid", "alice"); eq("ou", "users") } }
Filter { or { eq("cn", "Алиса"); eq("cn", "Алисия") } }
Filter { not { eq("uid", "bob") } }
Filter { present("objectClass") }
Filter { substring("cn", initial = "А", any = listOf("лис"), final = "а") }
Filter { ge("age", "18") }
Filter { le("age", "65") }
```

### Controls

```kotlin
import pw.binom.ldap.domain.control.*

ldap.searchAll(
    baseDn = ...,
    scope = ...,
    filter = ...,
    controls = listOf(PagedResults.request(pageSize = 100)),
)
```

Готовые: `PagedResults`, `ServerSideSort`, `ManageDsaIT`. Тип `Control`
открытый — любой OID + значение проходит насквозь.

## Модель ошибок

Операции, которые могут быть отклонены сервером, кидают подкласс
`LdapException` с LDAP result code:

- `InvalidCredentialsException` (49)
- `NoSuchObjectException` (32)
- `SizeLimitExceededException` (4)
- `TimeLimitExceededException` (3)
- `BusyException` (51)
- `UnavailableException` (52)
- `UnwillingToPerformException` (53)
- `ReferralException` (10)
- `LdapProtocolException` — сетевые/парс-ошибки, неизвестные коды

Bind **не** кидает на «неверный пароль» — возвращает `LdapBindResult`
с `isSuccess == false`, чтобы можно было отличить «неверный пароль» от
«сервер недоступен».

## Сборка

```bash
./gradlew check            # jvm + linuxX64 тесты, ktlint, detekt
./gradlew dokkaGenerateHtml # API-документация
```

Интеграционные тесты против реального OpenLDAP (Testcontainers + образ
Bitnami) требуют Docker/Podman и опциональны:

```bash
./gradlew jvmTest -Dkldap.integration.enabled=true
```

## Структура

```
pw/binom/ldap/
├── asn1/       ← ASN.1 BER-кодек (tag/length/integer/octet-string/oid)
├── protocol/   ← RFC 4511 сообщения, операции, AST фильтров, controls
├── transport/  ← TCP + TLS сокеты (ktor-network)
├── connection/ ← корреляция по messageID, in-flight tracking, send/stream
├── client/     ← высокоуровневый LdapClient + события ответов
├── domain/     ← Dn, SearchEntry, SearchScope, Filter DSL, LdapBindResult
└── exception/  ← иерархия LdapException
```

## Лицензия

Apache License 2.0.