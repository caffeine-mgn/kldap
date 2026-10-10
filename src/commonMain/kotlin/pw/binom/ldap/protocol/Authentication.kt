package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * LDAP bind authentication (RFC 4511 §4.2 — `AuthenticationChoice`).
 *
 * Encoded with IMPLICIT TAGS:
 * - `[0] OCTET STRING` — `simple`
 * - `[3] SaslCredentials` — `sasl`
 */
public sealed class Authentication {
    /**
     * Simple username/password authentication. The password is sent in plaintext
     * over the wire (use TLS unless [isAnonymous] is `true`).
     *
     * Encoded as `[0] OCTET STRING` with UTF-8 password bytes.
     */
    public class Simple(
        public val password: String,
    ) : Authentication() {
        /** True if this is an anonymous bind (empty password). */
        public val isAnonymous: Boolean get() = password.isEmpty()

        override fun equals(other: Any?): Boolean = other is Simple && password == other.password

        override fun hashCode(): Int = password.hashCode()

        override fun toString(): String = if (isAnonymous) "Simple(anonymous)" else "Simple(***)"
    }

    /**
     * SASL authentication. The mechanism name is required; credentials are
     * optional (depending on the mechanism's exchange).
     *
     * Encoded as `[3] IMPLICIT SaslCredentials`:
     * `mechanism LDAPString (UTF8String), credentials OCTET STRING OPTIONAL`.
     */
    public class Sasl(
        public val mechanism: String,
        public val credentials: ByteArray? = null,
    ) : Authentication() {
        override fun equals(other: Any?): Boolean =
            other is Sasl &&
                mechanism == other.mechanism &&
                (credentials?.contentEquals(other.credentials) ?: (other.credentials == null))

        override fun hashCode(): Int =
            mechanism.hashCode() * 31 + (credentials?.contentHashCode() ?: 0)

        override fun toString(): String = "Sasl($mechanism)"
    }
}

internal fun BerWriter.writeAuthentication(auth: Authentication) {
    when (auth) {
        is Authentication.Simple ->
            writeTagged(BerTag.contextSpecific(0, constructed = false)) {
                writeRawBytes(auth.password.encodeToByteArray())
            }
        is Authentication.Sasl ->
            writeTagged(BerTag.contextSpecific(3, constructed = true)) {
                // [3] IMPLICIT SaslCredentials (RFC 4511 §4.2 + IMPLICIT TAGS §4.1):
                // the [3] tag replaces the underlying SEQUENCE tag, so the body contains
                // the SEQUENCE fields directly (no inner SEQUENCE wrapper).
                writeUtf8String(auth.mechanism)
                if (auth.credentials != null) writeOctetString(auth.credentials)
            }
    }
}

internal fun BerReader.readAuthentication(): Authentication {
    val tag = readTag()
    val length = readLength()
    val bodyBytes = source.readByteArray(length)
    val r = BerReader(Buffer().apply { write(bodyBytes) })
    return when (tag.number) {
        0 -> {
            require(!tag.constructed) { "Simple authentication must be primitive, got $tag" }
            // Body is raw UTF-8 bytes (no length prefix inside since the outer length was already read)
            val pwdBytes = r.source.readByteArray()
            Authentication.Simple(pwdBytes.decodeToString())
        }
        3 -> {
            require(tag.constructed) { "SASL authentication must be constructed, got $tag" }
            // Body contains mechanism (UTF8String) followed by optional credentials (OCTET STRING)
            val mechanism = r.readUtf8String()
            val credentials =
                if (r.source.exhausted()) null else r.readTypedBytes(BerTag.OCTET_STRING)
            Authentication.Sasl(mechanism, credentials)
        }
        else -> error("Unknown authentication tag: $tag")
    }
}
