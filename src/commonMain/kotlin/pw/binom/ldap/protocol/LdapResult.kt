package pw.binom.ldap.protocol

import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * Common result component for LDAP responses (RFC 4511 §4.1.9).
 *
 * Encoded as:
 * ```
 * LDAPResult ::= SEQUENCE {
 *     resultCode    ENUMERATED { ... },
 *     matchedDN     LDAPDN,
 *     diagnosticMessage    LDAPString,
 *     referral      [3] Referral OPTIONAL
 * }
 * ```
 *
 * Referral (`referrals`) is included only when [referrals] is not empty
 * and is non-null in the encoded form.
 */
public data class LdapResult(
    val resultCode: ResultCode,
    val matchedDn: String,
    val diagnosticMessage: String,
    val referrals: List<String> = emptyList(),
)

internal fun BerWriter.writeLdapResult(result: LdapResult) {
    writeSequence {
        writeInteger(result.resultCode.code.toLong())
        writeUtf8String(result.matchedDn)
        writeUtf8String(result.diagnosticMessage)
        if (result.referrals.isNotEmpty()) {
            // [3] IMPLICIT SEQUENCE OF URI — the [3] tag replaces the SEQUENCE tag.
            writeTagged(BerTag.contextSpecific(3, constructed = true)) {
                for (r in result.referrals) writeUtf8String(r)
            }
        }
    }
}

internal fun BerReader.readLdapResult(): LdapResult =
    seq {
        LdapResult(
            resultCode = ResultCode.fromCode(readInteger().toInt()),
            matchedDn = readUtf8String(),
            diagnosticMessage = readUtf8String(),
            referrals =
                if (source.exhausted()) {
                    emptyList()
                } else {
                    // [3] IMPLICIT SEQUENCE OF URI — the [3] tag replaces the SEQUENCE tag,
                    // so the body is the URIs themselves (no inner SEQUENCE wrapper).
                    seq(BerTag.contextSpecific(3, constructed = true)) {
                        val list = mutableListOf<String>()
                        while (!source.exhausted()) list.add(readUtf8String())
                        list
                    }
                },
        )
    }
