package pw.binom.ldap.integration

import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.condition.EnabledIfSystemProperty
import pw.binom.ldap.client.LdapClient
import pw.binom.ldap.client.firstString
import pw.binom.ldap.protocol.Authentication
import pw.binom.ldap.protocol.PartialAttribute
import pw.binom.ldap.protocol.ResultCode
import pw.binom.ldap.protocol.SearchScope
import pw.binom.ldap.transport.LdapConnectionConfig
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * End-to-end tests against a real OpenLDAP server (Bitnami image).
 *
 * Skipped by default. To run locally:
 * - Docker or Podman must be running.
 * - Pass `-Dkldap.integration.enabled=true` to gradle.
 * - The first run will pull `bitnami/openldap:latest` (~100 MB).
 *
 * Usage:
 * ```
 * ./gradlew jvmTest -Dkldap.integration.enabled=true
 * ```
 */
@EnabledIfSystemProperty(named = "kldap.integration.enabled", matches = "true")
class OpenLdapIntegrationTest {

    @Test
    fun bindAsAdmin() = runBlocking {
        OpenLdapContainer().use { ldap ->
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = ldap.containerHost
                    port = ldap.ldapPort
                },
            )
            try {
                val result = client.bind(ldap.adminDn, Authentication.Simple(ldap.adminPassword))
                assertTrue(result.resultCode() == ResultCode.SUCCESS)
            } finally {
                client.close()
            }
        }
    }

    @Test
    fun bindInvalidCredentials() = runBlocking {
        OpenLdapContainer().use { ldap ->
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = ldap.containerHost
                    port = ldap.ldapPort
                },
            )
            try {
                val result = client.bind(ldap.adminDn, Authentication.Simple("wrong"))
                assertEquals(ResultCode.INVALID_CREDENTIALS, result.resultCode())
            } finally {
                client.close()
            }
        }
    }

    @Test
    fun addAndSearchUser() = runBlocking {
        OpenLdapContainer().use { ldap ->
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = ldap.containerHost
                    port = ldap.ldapPort
                },
            )
            try {
                client.bind(ldap.adminDn, Authentication.Simple(ldap.adminPassword))

                val addResult = client.add(
                    dn = ldap.testUserDn,
                    attributes = listOf(
                        PartialAttribute("objectClass", listOf(
                            "inetOrgPerson".encodeToByteArray(),
                            "organizationalPerson".encodeToByteArray(),
                            "person".encodeToByteArray(),
                            "top".encodeToByteArray(),
                        )),
                        PartialAttribute("cn", listOf("Test User".encodeToByteArray())),
                        PartialAttribute("sn", listOf("User".encodeToByteArray())),
                        PartialAttribute("uid", listOf(ldap.uniqueSuffix.encodeToByteArray())),
                    ),
                )
                assertEquals(ResultCode.SUCCESS, addResult.resultCode())

                val found = client.searchOne(
                    baseDn = ldap.usersBaseDn,
                    scope = SearchScope.WHOLE_SUBTREE,
                    filter = pw.binom.ldap.protocol.LdapFilter.EqualityMatch(
                        "uid",
                        ldap.uniqueSuffix.encodeToByteArray(),
                    ),
                )
                assertNotNull(found)
                assertEquals(ldap.testUserDn, found.op.objectName)
                assertEquals("Test User", found.op.firstString("cn"))
            } finally {
                client.close()
            }
        }
    }
}
