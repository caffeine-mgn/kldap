package pw.binom.ldap.protocol

/**
 * How the server should dereference aliases during a search (RFC 4511 §4.5.1.2 — `derefAliases`).
 */
public enum class DerefAliases(
    public val code: Int,
) {
    NEVER_DEREF_ALIASES(0),
    DERE_FINDING_BASE_OBJ(1),
    DERE_IN_SEARCHING(2),
    DERE_ALWAYS(3),
    ;

    public companion object {
        public fun fromCode(code: Int): DerefAliases =
            entries.firstOrNull { it.code == code } ?: error("Unknown DerefAliases code: $code")
    }
}
