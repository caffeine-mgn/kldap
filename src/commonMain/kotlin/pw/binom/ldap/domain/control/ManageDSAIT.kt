package pw.binom.ldap.domain.control

import pw.binom.ldap.protocol.Control

/**
 * RFC 3296 — ManageDsaIT Control.
 *
 * Tells the server to treat all referral responses as "in-place" so the
 * client can use LDAP entries for a smart referral as if they were
 * regular entries. The control has no value.
 *
 * Usage:
 * ```kotlin
 * ldap.searchAll(..., controls = listOf(ManageDSAIT))
 * ```
 */
public object ManageDSAIT {
    public const val OID: String = "2.16.840.1.113730.3.4.2"

    /** A pre-built critical ManageDsaIT control (no value). */
    public val CONTROL: Control = Control(OID, critical = true)
}

/** Convenience: read [ManageDSAIT.CONTROL] as a [Control]. */
public val manageDsaIt: Control get() = ManageDSAIT.CONTROL
