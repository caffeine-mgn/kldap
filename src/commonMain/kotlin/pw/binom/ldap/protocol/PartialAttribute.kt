package pw.binom.ldap.protocol

import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * A single LDAP attribute within an entry (RFC 4511 §4.5.1.7).
 *
 * Encoded as:
 * ```
 * PartialAttribute ::= SEQUENCE {
 *     type    AttributeDescription,
 *     vals    SET OF value AttributeValue
 * }
 * ```
 */
public class PartialAttribute(
    public val type: String,
    public val values: List<ByteArray>,
) {
    override fun equals(other: Any?): Boolean =
        other is PartialAttribute &&
            type == other.type &&
            values.size == other.values.size &&
            values.zip(other.values).all { (a, b) -> a.contentEquals(b) }

    override fun hashCode(): Int {
        var h = type.hashCode()
        for (v in values) h = h * 31 + v.contentHashCode()
        return h
    }

    override fun toString(): String = "$type=${values.map { it.decodeToString() }}"
}

internal fun BerWriter.writePartialAttribute(pa: PartialAttribute) {
    writeSequence {
        writeUtf8String(pa.type)
        writeSequence(BerTag.SET) {
            for (v in pa.values) writeOctetString(v)
        }
    }
}

internal fun BerReader.readPartialAttribute(): PartialAttribute =
    seq {
        val type = readUtf8String()
        val values = mutableListOf<ByteArray>()
        seq(BerTag.SET) {
            while (!source.exhausted()) {
                values.add(readOctetString())
            }
        }
        PartialAttribute(type, values)
    }
