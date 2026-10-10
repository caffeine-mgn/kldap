# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- `asn1/` package: ASN.1 BER encoder/decoder (`BerTag`, `BerReader`,
  `BerWriter`, `TagClass`).
- `protocol/` package: full RFC 4511 protocol model (LdapMessage envelope,
  Bind/Search/Modify/Add/Delete/ModifyDN/Compare/Abandon/Unbind,
  LdapFilter sealed class, LdapResult, Authentication, Control,
  SearchScope, DerefAliases, PartialAttribute, ResultCode).
- `transport/` package: TCP + TLS (LDAP/LDAPS) over `ktor-network` +
  `ktor-network-tls`. `LdapConnectionConfig`, `LdapTransport`,
  `ldapConnect()`.
- `connection/` package: `LdapConnection` with message-ID correlation,
  two in-flight registries (single-shot and streaming), `send` /
  `sendNoResponse` / `sendAndStream`. `LdapMessageChannel` for
  streaming BER framing. `LdapEndOfStreamException`.
- `client/` package: high-level `LdapClient` with `bind`, `unbind`,
  `search`, `searchOne`, `searchAll`, `add`, `modify`, `delete`,
  `modifyDn`, `compare`, `abandon`. `LdapResponse` sealed class
  (Ok/Entry/Reference/Done).
- `domain/` package: `Dn` value class, `SearchEntry`, `SearchScope`,
  `FilterBuilder` DSL building `pw.binom.ldap.protocol.LdapFilter`,
  `LdapBindResult`.
- `exception/` package: `LdapException` sealed class with subtypes
  for the most common LDAP result codes (InvalidCredentials,
  NoSuchObject, SizeLimitExceeded, TimeLimitExceeded, Busy,
  Unavailable, UnwillingToPerform, Referral, LdapProtocolException).
- KMP targets: `jvm`, `linuxX64`, `mingwX64`, `macosArm64`, `iosArm64`,
  `iosSimulatorArm64`, `iosX64`.
- Maven publishing via vanniktech-maven-publish (in-memory PGP +
  gpg CLI for CI).
- Detekt + ktlint + Dokka wired up.
- Integration tests via Testcontainers + Bitnami OpenLDAP image
  (opt-in via `-Dkldap.integration.enabled=true`).
- CI/CD: `.github/workflows/release.yml` triggered on tag push.
