package pw.binom.ldap.domain

/**
 * Result of an LDAP Bind operation. A bind can fail at the LDAP
 * protocol level (e.g. invalid credentials) without raising an
 * exception — check [isSuccess] / [resultCode] before continuing.
 *
 * @param resultCode LDAP [RFC 4511 result code](https://ldap.com/ldap-result-codes).
 *   `0` is success; any non-zero code means the bind was rejected.
 * @param matchedDn the closest matched DN the server reports (often empty).
 * @param message human-readable diagnostic from the server.
 * @param serverSaslCreds raw server SASL credentials (e.g. a bind
 *   challenge) if the server sent any. Most simple binds leave this empty.
 */
public class LdapBindResult(
    public val resultCode: Int,
    public val matchedDn: String? = null,
    public val message: String? = null,
    public val serverSaslCreds: ByteArray = EmptyByteArray,
) {
    public val isSuccess: Boolean get() = resultCode == 0

    override fun equals(other: Any?): Boolean = other is LdapBindResult &&
        resultCode == other.resultCode &&
        matchedDn == other.matchedDn &&
        message == other.message &&
        serverSaslCreds.contentEquals(other.serverSaslCreds)

    override fun hashCode(): Int = 31 * (31 * (31 * resultCode + (matchedDn?.hashCode() ?: 0)) +
        (message?.hashCode() ?: 0)) + serverSaslCreds.contentHashCode()

    override fun toString(): String =
        "LdapBindResult(resultCode=$resultCode, matchedDn=$matchedDn, message=$message)"

    public companion object {
        public const val SUCCESS: Int = 0
    }
}

private val EmptyByteArray = ByteArray(0)
