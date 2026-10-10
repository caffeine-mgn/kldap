package pw.binom.ldap.domain

import pw.binom.ldap.protocol.LdapFilter
import pw.binom.ldap.protocol.PartialAttribute

/**
 * A single entry returned by an LDAP search.
 *
 * @param dn the entry's distinguished name
 * @param attributes all attributes and their values; the map key is the
 *   attribute type, the value is the list of values (UTF-8-decoded).
 *   Binary attributes (e.g. `userCertificate;binary`) are NOT decoded —
 *   use [binaryAttributes] for those.
 * @param binaryAttributes the binary-typed attributes (suffix `;binary`)
 *   preserved as raw bytes.
 */
public class SearchEntry internal constructor(
    public val dn: Dn,
    public val attributes: Map<String, List<String>>,
    public val binaryAttributes: Map<String, List<ByteArray>>,
) {
    override fun equals(other: Any?): Boolean = other is SearchEntry &&
        dn == other.dn &&
        attributes == other.attributes &&
        binaryAttributes == other.binaryAttributes

    override fun hashCode(): Int = 31 * (31 * dn.hashCode() + attributes.hashCode()) +
        binaryAttributes.hashCode()

    override fun toString(): String = "SearchEntry(dn=$dn, ${attributes.size}+${binaryAttributes.size} attrs)"

    public companion object {
        /** Builds a [SearchEntry] from a wire-level [LdapProtocolOp.SearchResultEntry]. */
        public fun fromOp(op: pw.binom.ldap.protocol.LdapProtocolOp.SearchResultEntry): SearchEntry {
            val text = mutableMapOf<String, MutableList<String>>()
            val binary = mutableMapOf<String, MutableList<ByteArray>>()
            for (attr in op.attributes) {
                if (attr.type.endsWith(";binary", ignoreCase = true)) {
                    binary.getOrPut(attr.type) { mutableListOf() } += attr.values
                } else {
                    text.getOrPut(attr.type) { mutableListOf() } += attr.values.map { it.decodeToString() }
                }
            }
            return SearchEntry(
                dn = Dn.of(op.objectName),
                attributes = text.mapValues { it.value.toList() },
                binaryAttributes = binary.mapValues { it.value.toList() },
            )
        }

        /** Builds the wire-level [PartialAttribute] list from a [SearchEntry] (reverse). */
        public fun toAttributes(entry: SearchEntry): List<PartialAttribute> {
            val out = mutableListOf<PartialAttribute>()
            for ((k, vs) in entry.attributes) {
                out += PartialAttribute(k, vs.map { it.encodeToByteArray() })
            }
            for ((k, vs) in entry.binaryAttributes) {
                out += PartialAttribute(k, vs.toList())
            }
            return out
        }

        /** Filter helper: convert a [LdapFilter] sealed-class to a debug string. */
        public fun debugFilter(filter: LdapFilter): String = filter.toString()
    }
}
