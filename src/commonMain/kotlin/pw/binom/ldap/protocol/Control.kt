package pw.binom.ldap.protocol

import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * An LDAP control (RFC 4511 §4.4 with semantics from RFC 4513 §6 and others).
 *
 * Encoded as a SEQUENCE inside the LdapMessage's `[0] Controls` field:
 * ```
 * Control ::= SEQUENCE {
 *     controlType    LDAPOID,
 *     criticality    BOOLEAN DEFAULT FALSE,
 *     controlValue   OCTET STRING OPTIONAL
 * }
 * ```
 *
 * When the [critical] flag is `false` and the [value] is `null`, the canonical
 * BER encoding omits both fields. The decoder handles all valid encodings
 * (criticality present, value present, value absent, both absent, etc.).
 */
public class Control(
    public val type: String,
    public val critical: Boolean = false,
    public val value: ByteArray? = null,
) {
    override fun equals(other: Any?): Boolean =
        other is Control &&
            type == other.type &&
            critical == other.critical &&
            (value?.contentEquals(other.value) ?: (other.value == null))

    override fun hashCode(): Int =
        type.hashCode() * 31 + critical.hashCode() * 31 + (value?.contentHashCode() ?: 0)

    override fun toString(): String =
        buildString {
            append(type)
            if (critical) append(" (critical)")
            if (value != null) append(" = ${value.size}B")
        }
}

internal fun BerWriter.writeControl(control: Control) {
    writeSequence {
        writeOid(control.type)
        // canonical BER: omit criticality when FALSE, omit value when null.
        if (control.critical) writeBoolean(true)
        if (control.value != null) writeOctetString(control.value)
    }
}

internal fun BerReader.readControl(): Control {
    if (source.exhausted()) error("Cannot read Control from exhausted reader")
    return seq {
        // Read type (always present).
        val oid = readOid()
        var critical = false
        var value: ByteArray? = null
        if (!source.exhausted()) {
            when (peekTag()) {
                BerTag.BOOLEAN -> {
                    critical = readBoolean()
                    if (!source.exhausted()) {
                        value = readOctetString()
                    }
                }
                BerTag.OCTET_STRING -> {
                    value = readOctetString()
                }
                else -> {
                    error("Expected BOOLEAN or OCTET STRING in Control after OID, got ${peekTag()}")
                }
            }
        }
        Control(oid, critical, value)
    }
}
