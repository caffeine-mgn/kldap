package pw.binom.ldap.integration

import org.testcontainers.containers.GenericContainer
import org.testcontainers.containers.wait.strategy.Wait
import org.testcontainers.junit.jupiter.Testcontainers
import java.util.UUID

/**
 * Bitnami OpenLDAP test container. Disabled by default — only runs
 * when an actual Docker/Podman daemon is available AND the developer
 * removes the @Disabled annotation (or sets
 * `kldap.integration.enabled=true` system property).
 *
 * Image: `bitnami/openldap:latest`
 * Default credentials:
 *   admin: admin
 *   password: adminpassword
 *   domain: example.org
 *   base DN: dc=example,dc=org
 */
@Testcontainers
class OpenLdapContainer : GenericContainer<OpenLdapContainer>(
    "bitnami/openldap:latest",
) {
    init {
        withEnv("LDAP_ADMIN_USERNAME", "admin")
        withEnv("LDAP_ADMIN_PASSWORD", "adminpassword")
        withEnv("LDAP_ROOT", "dc=example,dc=org")
        withEnv("LDAP_USERS", "users")
        withEnv("LDAP_PASSWORDS", "userpassword")
        withEnv("LDAP_USER_UID", "1000")
        withEnv("LDAP_USER_GID", "1000")
        withEnv("LDAP_USER_HOME", "/home/users")
        withEnv("LDAP_USER_SHELL", "/bin/bash")
        waitingFor(Wait.forLogMessage(".*slapd starting.*", 1))
        withExposedPorts(1389)
    }

    val ldapPort: Int get() = getMappedPort(1389)
    val containerHost: String get() = this.host
    val adminDn: String get() = "cn=admin,dc=example,dc=org"
    val adminPassword: String get() = "adminpassword"
    val userDn: String get() = "cn=users,dc=example,dc=org"
    val usersBaseDn: String get() = "ou=users,dc=example,dc=org"
    val uniqueSuffix: String = UUID.randomUUID().toString().take(8)
    val testUserDn: String get() = "uid=$uniqueSuffix,$usersBaseDn"
    val testUserPassword: String get() = "secret"
}
