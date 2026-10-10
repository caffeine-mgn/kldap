package pw.binom.ldap.domain.control

import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerWriter
import pw.binom.ldap.protocol.Control

/**
 * RFC 2696 — LDAP Control Extension for Simple Paged Results.
 *
 * The control value is a BER-encoded SEQUENCE:
 * ```
 * SEQUENCE {
 *     size            INTEGER (0..maxInt),
 *     cookie          OCTET STRING
 * }
 * ```
 *
 * Usage across pages:
 * ```kotlin
 * var cookie = ByteArray(0)
 * do {
 *     val page = ldap.searchAll(..., controls = listOf(PagedResults.request(100, cookie)))
 *     cookie = PagedResults.cookieFromResponse(done.responseControls) ?: ByteArray(0)
 * } while (cookie.isNotEmpty())
 * ```
 */
public object PagedResults {
    public const val OID: String = "1.2.840.113556.1.4.319"

    /** Builds a page request control. An empty [cookie] requests the first page. */
    public fun request(
        pageSize: Int,
        cookie: ByteArray = ByteArray(0),
        critical: Boolean = false,
    ): Control {
        require(pageSize > 0) { "pageSize must be positive, got $pageSize" }
        val (writer, buffer) = BerWriter.create()
        writer.writeSequence {
            writeInteger(pageSize.toLong())
            writeOctetString(cookie)
        }
        return Control(OID, critical, buffer.readByteArray())
    }

    /**
     * Parses a response control value into the server-supplied cookie.
     * Returns `null` for an empty cookie (end of pages) or missing control.
     */
    public fun parseResponse(value: ByteArray?): ByteArray? {
        if (value == null || value.isEmpty()) return null
        return BerReader.of(value).seq {
            readInteger() // size (not needed by the caller)
            readOctetString()
        }
    }

    /** Convenience: pull the paged-results cookie from a list of response controls. */
    public fun cookieFromResponse(controls: List<Control>): ByteArray? {
        val c = controls.firstOrNull { it.type == OID } ?: return null
        return parseResponse(c.value)
    }
}
