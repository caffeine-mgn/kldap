package pw.binom.ldap.asn1

/**
 * ASN.1 tag class (X.680 §8.6.1, X.690 §8.1.2.1).
 *
 * The two high bits of the first identifier byte determine the class:
 * - 00 → [Universal] (X.680-defined types like BOOLEAN, INTEGER, OCTET STRING, …)
 * - 01 → [Application] (protocol-specific types; LDAP protocol tags live here)
 * - 10 → [ContextSpecific] (tag applies only to the immediate enclosing constructor;
 *             LDAP uses these for CHOICE alternatives inside operations)
 * - 11 → [Private] (rarely used; reserved)
 */
public enum class TagClass(
    public val bit: Int,
) {
    Universal(0b00),
    Application(0b01),
    ContextSpecific(0b10),
    Private(0b11),
    ;

    internal companion object {
        fun fromBit(b: Int): TagClass =
            when (b) {
                0b00 -> Universal
                0b01 -> Application
                0b10 -> ContextSpecific
                0b11 -> Private
                else -> error("Invalid tag class bits: $b")
            }
    }
}
