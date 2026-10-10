package pw.binom.ldap.domain.control

import kotlinx.io.readByteArray
import pw.binom.ldap.protocol.Control

/**
 * RFC 2891 — Server Side Sorting Control.
 *
 * The control value is the BER encoding of:
 * ```
 * SEQUENCE {
 *     sortKeyList SEQUENCE OF SEQUENCE {
 *         attributeType   LDAPOID,
 *         orderingRule    [0] MatchingRuleId OPTIONAL,
 *         reverseOrder    [1] BOOLEAN DEFAULT FALSE
 *     }
 * }
 * ```
 *
 * Only [attributeType] and [reverseOrder] are wired up in this convenience
 * builder. For an arbitrary control value, build a `Control(1.2.840.113556.1.4.473, ...)`
 * yourself and pass the raw bytes.
 *
 * Usage:
 * ```kotlin
 * ldap.searchAll(
 *     baseDn = ...,
 *     scope = ...,
 *     filter = ...,
 *     controls = listOf(ServerSideSort.sort("sn", reverse = false)),
 * )
 * ```
 */
public object ServerSideSort {
    public const val OID: String = "1.2.840.113556.1.4.473"

    public fun sort(
        attributeType: String,
        reverse: Boolean = false,
        critical: Boolean = false,
    ): Control {
        val (writer, buffer) = pw.binom.ldap.asn1.BerWriter
            .create()
        writer.writeSequence {
            writeSequence {
                writeOctetString(attributeType.encodeToByteArray())
                if (reverse) {
                    writeTagged(pw.binom.ldap.asn1.BerTag
                        .contextSpecific(1, constructed = false)) {
                        writeRawBytes(byteArrayOf(0xFF.toByte()))
                    }
                }
            }
        }
        return Control(OID, critical, buffer.readByteArray())
    }
}
