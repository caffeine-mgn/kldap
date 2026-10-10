package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter
import pw.binom.ldap.asn1.TagClass

/**
 * LDAP search filter (RFC 4511 §4.5.1).
 *
 * Encoded with IMPLICIT TAGS (per RFC 4511 §4.1):
 * - `[0]` SET OF Filter — `AND`
 * - `[1]` SET OF Filter — `OR`
 * - `[2]` Filter — `NOT`
 * - `[3]` AttributeValueAssertion — `equalityMatch`
 * - `[4]` SubstringFilter — `substrings`
 * - `[5]` AttributeValueAssertion — `greaterOrEqual`
 * - `[6]` AttributeValueAssertion — `lessOrEqual`
 * - `[7]` AttributeDescription — `present`
 * - `[8]` AttributeValueAssertion — `approxMatch`
 *
 * Because RFC 4511 uses IMPLICIT TAGS, the choice tags replace the underlying
 * type tags rather than wrapping them: `[0] SET` has tag `0xA0` (no inner SET tag);
 * `[3] SEQUENCE` has tag `0xA3` (no inner SEQUENCE tag); `[7] OCTET STRING`
 * has tag `0x87` (no inner OCTET STRING tag).
 */
public sealed class LdapFilter {
    /** Conjunction: `(&(f1)(f2)...)`. */
    public class And(
        public val filters: List<LdapFilter>,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean = other is And && filters == other.filters

        override fun hashCode(): Int = filters.hashCode()

        override fun toString(): String = "(&${filters.joinToString("")})"
    }

    /** Disjunction: `(|(f1)(f2)...)`. */
    public class Or(
        public val filters: List<LdapFilter>,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean = other is Or && filters == other.filters

        override fun hashCode(): Int = filters.hashCode()

        override fun toString(): String = "(|${filters.joinToString("")})"
    }

    /** Negation: `(!(f))`. */
    public class Not(
        public val filter: LdapFilter,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean = other is Not && filter == other.filter

        override fun hashCode(): Int = filter.hashCode() xor 31

        override fun toString(): String = "(!$filter)"
    }

    /** Equality match: `(attr=value)`. */
    public class EqualityMatch(
        public val attribute: String,
        public val value: ByteArray,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean =
            other is EqualityMatch && attribute == other.attribute && value.contentEquals(other.value)

        override fun hashCode(): Int = attribute.hashCode() * 31 + value.contentHashCode()

        override fun toString(): String = "($attribute=${value.decodeToString()})"
    }

    /** Presence test: `(attr=*)`. */
    public data class Present(
        public val attribute: String,
    ) : LdapFilter() {
        override fun toString(): String = "($attribute=*)"
    }

    /** Substring match: `(attr=initial*any*...*final)`. */
    public class Substring(
        public val attribute: String,
        public val initial: String?,
        public val any: List<String>,
        public val final: String?,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean =
            other is Substring &&
                attribute == other.attribute &&
                initial == other.initial &&
                any == other.any &&
                final == other.final

        override fun hashCode(): Int =
            attribute.hashCode() * 31 + (initial?.hashCode() ?: 0) * 31 +
                any.hashCode() * 31 + (final?.hashCode() ?: 0)

        override fun toString(): String =
            buildString {
                append('(').append(attribute).append('=')
                append(initial.orEmpty())
                if (any.isNotEmpty()) {
                    for (a in any) append('*').append(a)
                    append('*')
                } else {
                    append('*')
                }
                append(final.orEmpty())
                append(')')
            }
    }

    /** Greater-or-equal: `(attr>=value)`. */
    public class GreaterOrEqual(
        public val attribute: String,
        public val value: ByteArray,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean =
            other is GreaterOrEqual && attribute == other.attribute && value.contentEquals(other.value)

        override fun hashCode(): Int = attribute.hashCode() * 31 + value.contentHashCode()

        override fun toString(): String = "($attribute>=${value.decodeToString()})"
    }

    /** Less-or-equal: `(attr<=value)`. */
    public class LessOrEqual(
        public val attribute: String,
        public val value: ByteArray,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean =
            other is LessOrEqual && attribute == other.attribute && value.contentEquals(other.value)

        override fun hashCode(): Int = attribute.hashCode() * 31 + value.contentHashCode()

        override fun toString(): String = "($attribute<=${value.decodeToString()})"
    }

    /** Approximate match: `(attr~=value)`. */
    public class ApproxMatch(
        public val attribute: String,
        public val value: ByteArray,
    ) : LdapFilter() {
        override fun equals(other: Any?): Boolean =
            other is ApproxMatch && attribute == other.attribute && value.contentEquals(other.value)

        override fun hashCode(): Int = attribute.hashCode() * 31 + value.contentHashCode()

        override fun toString(): String = "($attribute~=${value.decodeToString()})"
    }

    public companion object {
        /** Convenience: `(attribute = "value")` with UTF-8 bytes. */
        public fun eq(attribute: String, value: String): EqualityMatch =
            EqualityMatch(attribute, value.encodeToByteArray())

        /** Convenience: `(attribute = "value")` with arbitrary bytes. */
        public fun eq(attribute: String, value: ByteArray): EqualityMatch =
            EqualityMatch(attribute, value)

        /** Convenience: `(attribute = *)` presence filter. */
        public fun present(attribute: String): Present = Present(attribute)

        /** Convenience: `(&(f1)(f2)...)`. */
        public fun and(vararg filters: LdapFilter): And = And(filters.toList())

        /** Convenience: `(|(f1)(f2)...)`. */
        public fun or(vararg filters: LdapFilter): Or = Or(filters.toList())

        /** Convenience: `(!(f))`. */
        public fun not(filter: LdapFilter): Not = Not(filter)
    }
}

internal fun BerWriter.writeFilter(filter: LdapFilter) {
    when (filter) {
        is LdapFilter.And ->
            writeTagged(BerTag.contextSpecific(0, constructed = true)) {
                for (f in filter.filters) writeFilter(f)
            }
        is LdapFilter.Or ->
            writeTagged(BerTag.contextSpecific(1, constructed = true)) {
                for (f in filter.filters) writeFilter(f)
            }
        is LdapFilter.Not ->
            writeTagged(BerTag.contextSpecific(2, constructed = true)) {
                writeFilter(filter.filter)
            }
        is LdapFilter.EqualityMatch ->
            writeTagged(BerTag.contextSpecific(3, constructed = true)) {
                writeOctetString(filter.attribute.encodeToByteArray())
                writeOctetString(filter.value)
            }
        is LdapFilter.Present ->
            writeTagged(BerTag.contextSpecific(7, constructed = false)) {
                writeRawBytes(filter.attribute.encodeToByteArray())
            }
        is LdapFilter.Substring ->
            writeTagged(BerTag.contextSpecific(4, constructed = true)) {
                writeOctetString(filter.attribute.encodeToByteArray())
                writeSequence {
                    if (filter.initial != null) {
                        writeTagged(BerTag.contextSpecific(0, constructed = false)) {
                            writeRawBytes(filter.initial.encodeToByteArray())
                        }
                    }
                    for (a in filter.any) {
                        writeTagged(BerTag.contextSpecific(1, constructed = false)) {
                            writeRawBytes(a.encodeToByteArray())
                        }
                    }
                    if (filter.final != null) {
                        writeTagged(BerTag.contextSpecific(2, constructed = false)) {
                            writeRawBytes(filter.final.encodeToByteArray())
                        }
                    }
                }
            }
        is LdapFilter.GreaterOrEqual ->
            writeTagged(BerTag.contextSpecific(5, constructed = true)) {
                writeOctetString(filter.attribute.encodeToByteArray())
                writeOctetString(filter.value)
            }
        is LdapFilter.LessOrEqual ->
            writeTagged(BerTag.contextSpecific(6, constructed = true)) {
                writeOctetString(filter.attribute.encodeToByteArray())
                writeOctetString(filter.value)
            }
        is LdapFilter.ApproxMatch ->
            writeTagged(BerTag.contextSpecific(8, constructed = true)) {
                writeOctetString(filter.attribute.encodeToByteArray())
                writeOctetString(filter.value)
            }
    }
}

internal fun BerReader.readFilter(): LdapFilter {
    val tag = readTag()
    val length = readLength()
    val bodyBytes = source.readByteArray(length)
    val r = BerReader(Buffer().apply { write(bodyBytes) })
    val tagNumber = tag.number
    require(tag.clazz == TagClass.ContextSpecific) { "LDAP filter must be context-specific, got $tag" }
    return when (tagNumber) {
        0 -> {
            val filters = mutableListOf<LdapFilter>()
            while (!r.source.exhausted()) filters.add(r.readFilter())
            LdapFilter.And(filters)
        }
        1 -> {
            val filters = mutableListOf<LdapFilter>()
            while (!r.source.exhausted()) filters.add(r.readFilter())
            LdapFilter.Or(filters)
        }
        2 -> LdapFilter.Not(r.readFilter())
        3 -> {
            val typeBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            val valueBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            LdapFilter.EqualityMatch(typeBytes.decodeToString(), valueBytes)
        }
        4 -> {
            val typeBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            r.readTag()
            val seqLength = r.readLength()
            val seqBytes = r.source.readByteArray(seqLength)
            val subR = BerReader(Buffer().apply { write(seqBytes) })
            var initial: String? = null
            val any = mutableListOf<String>()
            var finalStr: String? = null
            while (!subR.source.exhausted()) {
                val subTag = subR.readTag()
                require(subTag.clazz == TagClass.ContextSpecific) {
                    "Substring component must be context-specific, got $subTag"
                }
                val subBytes = subR.readRawValue()
                when (subTag.number) {
                    0 -> initial = subBytes.decodeToString()
                    1 -> any.add(subBytes.decodeToString())
                    2 -> finalStr = subBytes.decodeToString()
                    else -> error("Unknown substring component tag: $subTag")
                }
            }
            LdapFilter.Substring(typeBytes.decodeToString(), initial, any, finalStr)
        }
        5 -> {
            val typeBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            val valueBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            LdapFilter.GreaterOrEqual(typeBytes.decodeToString(), valueBytes)
        }
        6 -> {
            val typeBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            val valueBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            LdapFilter.LessOrEqual(typeBytes.decodeToString(), valueBytes)
        }
        7 -> {
            val attrBytes = r.source.readByteArray()
            LdapFilter.Present(attrBytes.decodeToString())
        }
        8 -> {
            val typeBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            val valueBytes = r.readTypedBytes(BerTag.OCTET_STRING)
            LdapFilter.ApproxMatch(typeBytes.decodeToString(), valueBytes)
        }
        else -> error("Unknown LDAP filter tag: $tag")
    }
}
