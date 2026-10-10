package pw.binom.ldap.domain

/**
 * High-level search scope, distinct from the protocol-level
 * [pw.binom.ldap.protocol.SearchScope] which carries wire codes.
 */
public enum class SearchScope {
    /** Search only the base object. */
    Base,

    /** Search one level below the base. */
    SingleLevel,

    /** Search the entire subtree below the base (default). */
    Subtree,
}
