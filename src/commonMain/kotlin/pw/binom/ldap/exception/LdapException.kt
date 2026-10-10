package pw.binom.ldap.exception

import pw.binom.ldap.protocol.LdapResult
import pw.binom.ldap.protocol.ResultCode

/**
 * Base class for all LDAP operation failures.
 *
 * Raised by [pw.binom.ldap.client.LdapClient] when the server returns a
 * non-success response for a single-shot operation. The `Bind` operation
 * is a special case: bind failures are returned as a successful
 * `LdapBindResult` with `isSuccess == false`, NOT as an exception,
 * because the wire protocol does not surface them as such.
 *
 * @param resultCode the LDAP result code from the server's response.
 * @param matchedDn the "matched DN" field from the server (often empty).
 * @param message the diagnostic message from the server.
 */
public abstract class LdapException(
    public val resultCode: ResultCode,
    public val matchedDn: String,
    public val diagnosticMessage: String?,
    cause: Throwable? = null,
) : RuntimeException(buildMessage(resultCode, matchedDn, diagnosticMessage), cause) {
    public companion object {
        private fun buildMessage(
            resultCode: ResultCode,
            matchedDn: String,
            message: String?,
        ): String = buildString {
            append("LDAP error ").append(resultCode.code).append(" (")
            append(resultCode.name).append(')')
            if (matchedDn.isNotEmpty()) {
                append(" matched=").append(matchedDn)
            }
            if (!message.isNullOrEmpty()) {
                append(": ").append(message)
            }
        }

        /**
         * Maps an LDAP [LdapResult] to a typed [LdapException] subclass.
         * For `SUCCESS` returns `null`; for unknown codes returns
         * [GenericLdapException].
         */
        public fun from(result: LdapResult): LdapException? {
            if (result.resultCode == ResultCode.SUCCESS) return null
            val code = result.resultCode
            val ex: LdapException = when (code) {
                ResultCode.INVALID_CREDENTIALS -> InvalidCredentialsException(result)
                ResultCode.NO_SUCH_OBJECT -> NoSuchObjectException(result)
                ResultCode.SIZE_LIMIT_EXCEEDED -> SizeLimitExceededException(result)
                ResultCode.TIME_LIMIT_EXCEEDED -> TimeLimitExceededException(result)
                ResultCode.BUSY -> BusyException(result)
                ResultCode.UNAVAILABLE -> UnavailableException(result)
                ResultCode.UNWILLING_TO_PERFORM -> UnwillingToPerformException(result)
                ResultCode.REFERRAL -> ReferralException(result)
                ResultCode.OTHER -> LdapProtocolException(result, "OTHER")
                else -> GenericLdapException(result)
            }
            return ex
        }
    }
}

/** Catch-all for LDAP errors that don't have a dedicated subclass. */
public class GenericLdapException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 32 — the target object does not exist. */
public class NoSuchObjectException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 49 — invalid credentials (wrong password, expired, locked). */
public class InvalidCredentialsException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 4 — the size limit was exceeded. */
public class SizeLimitExceededException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 3 — the time limit was exceeded. */
public class TimeLimitExceededException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 51 — the server is too busy. */
public class BusyException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 52 — the server is unavailable (down or unreachable). */
public class UnavailableException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 53 — the server is unwilling to perform the operation. */
public class UnwillingToPerformException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** LDAP code 10 — the server returned a referral. */
public class ReferralException(
    result: LdapResult,
) : LdapException(result.resultCode, result.matchedDn, result.diagnosticMessage)

/** Transport / parse error — the request never reached a coherent response. */
public class LdapProtocolException(
    result: LdapResult,
    detail: String,
) : LdapException(result.resultCode, result.matchedDn, "${result.diagnosticMessage ?: ""} [$detail]") {
    public constructor(message: String) : this(
        LdapResult(ResultCode.OTHER, "", message),
        "transport",
    )
}
