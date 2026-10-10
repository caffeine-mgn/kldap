package pw.binom.ldap.domain

/**
 * A distinguished name (RFC 4514). Stored as the raw wire-format string;
 * component-level accessors are best-effort and don't validate against a
 * schema — LDAP servers accept arbitrary DN strings.
 *
 * Examples:
 * ```
 * Dn.of("cn=admin,dc=corp,dc=local")
 * Dn.of(
 *     "cn" to "admin",
 *     "dc" to "corp",
 *     "dc" to "local",
 * )
 * ```
 */
@kotlin.jvm.JvmInline
public value class Dn(public val raw: String) {
    override fun toString(): String = raw

    public companion object {
        /**
         * Parses a DN from raw wire-format. Whitespace after `,` or `;` and
         * around `=` is stripped, but the relative distinguished names are
         * kept verbatim otherwise (no attribute-value escaping is applied).
         */
        public fun of(raw: String): Dn = Dn(raw.trim())

        /**
         * Builds a DN from `attribute=value` pairs. Components are joined
         * left-to-right with `,`. Special characters in the value are not
         * escaped — escape them yourself if needed.
         */
        public fun of(vararg pairs: Pair<String, String>): Dn {
            require(pairs.isNotEmpty()) { "DN must have at least one component" }
            return Dn(pairs.joinToString(",") { (k, v) -> "$k=$v" })
        }
    }
}
