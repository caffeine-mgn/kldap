package pw.binom.ldap.client

import pw.binom.ldap.protocol.LdapMessage
import pw.binom.ldap.protocol.LdapProtocolOp
import pw.binom.ldap.protocol.PartialAttribute
import pw.binom.ldap.protocol.ResultCode

/**
 * The result of a single LDAP operation, as observed by the [LdapClient].
 *
 * Most operations return a "response" that carries an [ResultCode] and
 * optional diagnostic. [Entry] is the result of [LdapClient.search] /
 * [LdapClient.searchOne] for one matched entry, and [Done] is the
 * terminal marker of a search stream.
 *
 * The full [message] is included on every variant so callers can read
 * response [pw.binom.ldap.protocol.Control]s (e.g. paged-results cookies)
 * without losing them.
 */
public sealed class LdapResponse {
    /** Underlying [LdapMessage] (carries response [pw.binom.ldap.protocol.Control]s). */
    public abstract val message: LdapMessage

    /** A single LDAP response message (BindResponse, ModifyResponse, etc.). */
    public data class Ok(override val message: LdapMessage) : LdapResponse() {
        public val op: LdapProtocolOp get() = message.op
    }

    /** A search-stream result entry (RFC 4511 SearchResultEntry). */
    public data class Entry(override val message: LdapMessage) : LdapResponse() {
        public val op: LdapProtocolOp.SearchResultEntry get() = message.op as LdapProtocolOp.SearchResultEntry
    }

    /** A search-stream referral (RFC 4511 SearchResultReference). */
    public data class Reference(override val message: LdapMessage) : LdapResponse() {
        public val op: LdapProtocolOp.SearchResultReference get() = message.op as LdapProtocolOp.SearchResultReference
    }

    /** Terminal marker of a search stream. */
    public data class Done(override val message: LdapMessage) : LdapResponse() {
        public val op: LdapProtocolOp.SearchResultDone get() = message.op as LdapProtocolOp.SearchResultDone
    }

    /**
     * Returns the LDAP [ResultCode] of the underlying response if this
     * is an [Ok] or [Done]; throws otherwise.
     */
    public fun resultCode(): ResultCode = when (this) {
        is Ok -> resultCodeFromOp(op)
        is Done -> op.result.resultCode
        is Entry -> error("SearchResultEntry has no result code")
        is Reference -> error("SearchResultReference has no result code")
    }

    public companion object {
        /** Maps a wire-level [LdapMessage] to a client-level [LdapResponse] event. */
        public fun from(message: LdapMessage): LdapResponse? = when (val op = message.op) {
            is LdapProtocolOp.SearchResultEntry -> Entry(message)
            is LdapProtocolOp.SearchResultReference -> Reference(message)
            is LdapProtocolOp.SearchResultDone -> Done(message)
            else -> Ok(message)
        }
    }
}

internal fun resultCodeFromOp(op: LdapProtocolOp): ResultCode = when (op) {
    is LdapProtocolOp.BindResponse -> op.result.resultCode
    is LdapProtocolOp.SearchResultDone -> op.result.resultCode
    is LdapProtocolOp.ModifyResponse -> op.result.resultCode
    is LdapProtocolOp.AddResponse -> op.result.resultCode
    is LdapProtocolOp.DelResponse -> op.result.resultCode
    is LdapProtocolOp.ModifyDNResponse -> op.result.resultCode
    is LdapProtocolOp.CompareResponse -> op.result.resultCode
    is LdapProtocolOp.SearchResultEntry -> error("SearchResultEntry has no result code")
    is LdapProtocolOp.SearchResultReference -> error("SearchResultReference has no result code")
    is LdapProtocolOp.BindRequest -> error("BindRequest is a request, not a response")
    is LdapProtocolOp.UnbindRequest -> error("UnbindRequest is a request, not a response")
    is LdapProtocolOp.SearchRequest -> error("SearchRequest is a request, not a response")
    is LdapProtocolOp.ModifyRequest -> error("ModifyRequest is a request, not a response")
    is LdapProtocolOp.AddRequest -> error("AddRequest is a request, not a response")
    is LdapProtocolOp.DelRequest -> error("DelRequest is a request, not a response")
    is LdapProtocolOp.ModifyDNRequest -> error("ModifyDNRequest is a request, not a response")
    is LdapProtocolOp.CompareRequest -> error("CompareRequest is a request, not a response")
    is LdapProtocolOp.AbandonRequest -> error("AbandonRequest is a request, not a response")
}

/** Helper: extract attribute values from a search entry by name (case-insensitive). */
public fun LdapProtocolOp.SearchResultEntry.valuesOf(name: String): List<ByteArray> {
    val normalized = name.lowercase()
    return attributes
        .firstOrNull { it.type.equals(normalized, ignoreCase = true) }
        ?.values ?: emptyList()
}

/** Helper: get the first value of an attribute as a UTF-8 string. */
public fun LdapProtocolOp.SearchResultEntry.firstString(name: String): String? =
    valuesOf(name).firstOrNull()?.decodeToString()

/** Convenience: build a [PartialAttribute]. */
public fun attribute(type: String, vararg values: String): PartialAttribute =
    PartialAttribute(type, values.map { it.encodeToByteArray() })

public fun attribute(type: String, vararg values: ByteArray): PartialAttribute =
    PartialAttribute(type, values.toList())
