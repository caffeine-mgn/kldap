# kldap

**Kotlin Multiplatform LDAP client** — a small LDAPv3 (RFC 4511) client library
that works on any Kotlin Multiplatform target: JVM, Linux, Windows, macOS, and iOS.

Built on top of [Ktor Network](https://github.com/ktorio/ktor)-`ktor-network`/`ktor-network-tls`
for TCP/TLS and its own ASN.1 BER codec. No reactive runtime, no JVM-only
dependencies in the wire core — everything is `commonMain`.

## Features

- **LDAP** (plaintext, port 389) and **LDAPS** (TLS, port 636) transports.
- **Bind** — anonymous, simple (DN + password). SASL GSSAPI/EXTERNAL is
  encodable but not orchestrated in phase 1.
- **Search** — base/single-level/subtree, custom filters, paging via controls.
- **Complete RFC 4511 operation set** — add, modify, delete, modify-DN, compare,
  abandon, unbind.
- **Multi-target** — `jvm`, `linuxX64`, `mingwX64`, `macosArm64`, `iosArm64`,
  `iosSimulatorArm64`, `iosX64`.
- No slf4j/log4j/logging at all — silence by design.

## Usage

```kotlin
import pw.binom.ldap.client.LdapClient
import pw.binom.ldap.domain.*
import pw.binom.ldap.protocol.Authentication

// Check credentials against a corporate LDAP/AD server:
LdapClient.connect(
    host = "ldap.corp.example.com",
    port = 636,
    ssl = true,
).use { ldap ->
    val bind = ldap.bind("cn=admin,dc=corp,dc=local", Authentication.Simple("secret"))
    if (!bind.isSuccess) {
        // 49 = invalid credentials, 53 = locked, etc.
        throw InvalidCredentialsException(message = bind.message)
    }

    // Login-by-username flow: find the user by login, then bind as them.
    val user = ldap.searchOne(
        baseDn = Dn.of("dc=corp,dc=local"),
        scope = SearchScope.Subtree,
        filter = Filter { eq("sAMAccountName", username) },
    )
    ldap.bind(Dn.of(user.dn.raw), Authentication.Simple(password))
}
```

Works exactly the same on iOS/Android/Windows — only the wiring changes.

### Search stream

`search(...)` returns a suspend-flow of events. Collect it with
`searchAll(...)`/`searchOne(...)`, or iterate per entry:

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
            println("found: ${event.op.responseName} cn=${entry.firstString("cn")}")
        is LdapResponse.Done -> {} // search finished
    }
}
```

### Filter DSL

```kotlin
Filter { eq("uid", "alice") }
Filter { and { eq("uid", "alice"); eq("ou", "users") } }
Filter { or { eq("cn", "Alice"); eq("cn", "Alicia") } }
Filter { not { eq("uid", "bob") } }
Filter { present("objectClass") }
Filter { substring("cn", initial = "A", any = listOf("li"), final = "ce") }
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

Ready-made controls: `PagedResults`, `ServerSideSort`, `ManageDsaIT`.
The `Control` type is open — any OID + value passes through.

## Error model

Operations that can reject the request raise a subclass of `LdapException`
carrying the LDAP result code:

- `InvalidCredentialsException` (49)
- `NoSuchObjectException` (32)
- `SizeLimitExceededException` (4)
- `TimeLimitExceededException` (3)
- `BusyException` (51)
- `UnavailableException` (52)
- `UnwillingToPerformException` (53)
- `ReferralException` (10)
- `LdapProtocolException` — network/parse errors, unknown codes

Bind never raises for a rejected password — it returns `LdapBindResult`
where `isSuccess == false`, so you can distinguish "wrong password" from
"server unreachable".

## Build

```bash
./gradlew check            # jvm + linuxX64 tests, ktlint, detekt
./gradlew dokkaGenerateHtml # API docs
```

Integration tests against a real OpenLDAP (Testcontainers + Bitnami image)
require Docker/Podman and are opt-in:

```bash
./gradlew jvmTest -Dkldap.integration.enabled=true
```

## Repository layout

```
pw/binom/ldap/
├── asn1/       ← ASN.1 BER codec (tag/length/integer/octet-string/oid)
├── protocol/   ← RFC 4511 messages, ops, filter AST, controls
├── transport/  ← TCP + TLS sockets (ktor-network)
├── connection/ ← message-ID correlation, in-flight tracking, send/stream
├── client/     ← high-level LdapClient + response events
├── domain/     ← Dn, SearchEntry, SearchScope, Filter DSL, LdapBindResult
└── exception/  ← LdapException hierarchy
```

## License

Apache License 2.0.