package pw.binom.ldap.protocol

/**
 * Scope of an LDAP search (RFC 4511 §4.5.1.1 — `scope`).
 *
 * Encoded as `ENUMERATED` in BER.
 */
public enum class SearchScope(
    public val code: Int,
) {
    /** Search the entry at the base DN only. */
    BASE_OBJECT(0),

    /** Search the entries immediately below the base DN. */
    SINGLE_LEVEL(1),

    /** Search the entire subtree rooted at the base DN. */
    WHOLE_SUBTREE(2),
    ;

    public companion object {
        /** Looks up a [SearchScope] by numeric value. */
        public fun fromCode(code: Int): SearchScope =
            entries.firstOrNull { it.code == code } ?: error("Unknown SearchScope code: $code")
    }
}
