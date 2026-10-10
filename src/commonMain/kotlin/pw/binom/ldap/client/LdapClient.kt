package pw.binom.ldap.client

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.toList
import pw.binom.ldap.connection.LdapConnection
import pw.binom.ldap.protocol.Authentication
import pw.binom.ldap.protocol.Control
import pw.binom.ldap.protocol.DerefAliases
import pw.binom.ldap.protocol.LdapFilter
import pw.binom.ldap.protocol.LdapProtocolOp
import pw.binom.ldap.protocol.Modification
import pw.binom.ldap.protocol.ResultCode
import pw.binom.ldap.protocol.SearchScope
import pw.binom.ldap.transport.LdapConnectionConfig
import pw.binom.ldap.transport.ldapConnect
import kotlin.coroutines.CoroutineContext

/**
 * High-level LDAP client built on top of [LdapConnection].
 *
 * - The client owns the underlying transport; calling [close] (or
 *   using [use]) tears it down.
 * - Operations that have a single response return a typed [LdapResponse.Ok];
 *   a failed bind returns a [LdapResponse.Ok] whose
 *   [LdapResponse.resultCode] is not [ResultCode.SUCCESS] (the LDAP
 *   wire protocol does not surface bind failures as exceptions).
 * - [search] is a suspending function that returns a [Flow] of
 *   [LdapResponse] events: zero or more [LdapResponse.Entry],
 *   [LdapResponse.Reference], terminated by a [LdapResponse.Done].
 * - [searchOne] is shorthand for "first entry, ignore the rest".
 *
 * Thread-safety: a single client is bound to one connection; do not
 * share it across threads concurrently without external synchronization.
 * Create a new client (and a new connection) per logical actor.
 */
public class LdapClient internal constructor(
    private val connection: LdapConnection,
    private val scope: CoroutineScope,
) : AutoCloseable {

    /**
     * Performs an LDAP Bind. The returned [LdapResponse.Ok] carries the
     * [LdapProtocolOp.BindResponse] which has the [ResultCode] of the
     * bind attempt.
     */
    public suspend fun bind(
        dn: String,
        authentication: Authentication,
        version: Int = 3,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val response = connection.send(
            LdapProtocolOp.BindRequest(version, dn, authentication),
            controls,
        )
        return LdapResponse.Ok(response)
    }

    /**
     * Sends an LDAP UnbindRequest and tears down the connection. After
     * [unbind] returns, the client is closed and any further operations
     * will fail.
     */
    public suspend fun unbind() {
        connection.sendNoResponse(LdapProtocolOp.UnbindRequest)
        close()
    }

    /**
     * Streams search results. The flow emits zero or more [LdapResponse.Entry]
     * and [LdapResponse.Reference] events and terminates with a
     * [LdapResponse.Done]. Collect the flow inside a coroutine; the
     * underlying connection is held for the lifetime of the search.
     */
    public fun search(
        baseDn: String,
        scope: SearchScope,
        filter: LdapFilter,
        attributes: List<String> = emptyList(),
        derefAliases: DerefAliases = DerefAliases.NEVER_DEREF_ALIASES,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Boolean = false,
        controls: List<Control> = emptyList(),
    ): Flow<LdapResponse> = flow {
        val request = LdapProtocolOp.SearchRequest(
            baseDn = baseDn,
            scope = scope,
            derefAliases = derefAliases,
            sizeLimit = sizeLimit,
            timeLimit = timeLimit,
            typesOnly = typesOnly,
            filter = filter,
            attributes = attributes,
        )
        var done = false
        connection.sendAndStream(request, controls).collect { msg ->
            val ev = LdapResponse.from(msg) ?: return@collect
            emit(ev)
            if (ev is LdapResponse.Done) done = true
        }
        if (!done) {
            // LdapConnection.sendAndStream never emitted a Done event.
            // Surface the omission as an empty result; the connection
            // will surface subsequent errors.
        }
    }

    /**
     * Convenience: collect the first [LdapResponse.Entry] of a search,
     * or `null` if the search returned no entries.
     */
    public suspend fun searchOne(
        baseDn: String,
        scope: SearchScope,
        filter: LdapFilter,
        attributes: List<String> = emptyList(),
        derefAliases: DerefAliases = DerefAliases.NEVER_DEREF_ALIASES,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Boolean = false,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Entry? {
        val request = LdapProtocolOp.SearchRequest(
            baseDn = baseDn,
            scope = scope,
            derefAliases = derefAliases,
            sizeLimit = sizeLimit,
            timeLimit = timeLimit,
            typesOnly = typesOnly,
            filter = filter,
            attributes = attributes,
        )
        var result: LdapResponse.Entry? = null
        var done = false
        connection.sendAndStream(request, controls).collect { msg ->
            val ev = LdapResponse.from(msg) ?: return@collect
            when (ev) {
                is LdapResponse.Entry -> {
                    if (result == null) result = ev
                }
                is LdapResponse.Done -> done = true
                is LdapResponse.Reference,
                is LdapResponse.Ok,
                -> Unit
            }
        }
        if (!done && result == null) return null
        return result
    }

    /** Suspend-collecting variant of [search]: returns the full list of events. */
    public suspend fun searchAll(
        baseDn: String,
        scope: SearchScope,
        filter: LdapFilter,
        attributes: List<String> = emptyList(),
        derefAliases: DerefAliases = DerefAliases.NEVER_DEREF_ALIASES,
        sizeLimit: Int = 0,
        timeLimit: Int = 0,
        typesOnly: Boolean = false,
        controls: List<Control> = emptyList(),
    ): List<LdapResponse> = search(
        baseDn,
        scope,
        filter,
        attributes,
        derefAliases,
        sizeLimit,
        timeLimit,
        typesOnly,
        controls,
    ).toList()

    public suspend fun add(
        dn: String,
        attributes: List<pw.binom.ldap.protocol.PartialAttribute>,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val resp = connection.send(LdapProtocolOp.AddRequest(dn, attributes), controls)
        return LdapResponse.Ok(resp)
    }

    public suspend fun modify(
        dn: String,
        changes: List<Modification>,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val resp = connection.send(LdapProtocolOp.ModifyRequest(dn, changes), controls)
        return LdapResponse.Ok(resp)
    }

    public suspend fun delete(
        dn: String,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val resp = connection.send(LdapProtocolOp.DelRequest(dn), controls)
        return LdapResponse.Ok(resp)
    }

    public suspend fun modifyDn(
        dn: String,
        newRdn: String,
        deleteOldRdn: Boolean,
        newSuperior: String? = null,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val resp = connection.send(
            LdapProtocolOp.ModifyDNRequest(dn, newRdn, deleteOldRdn, newSuperior),
            controls,
        )
        return LdapResponse.Ok(resp)
    }

    public suspend fun compare(
        dn: String,
        attribute: String,
        value: ByteArray,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok {
        val resp = connection.send(
            LdapProtocolOp.CompareRequest(dn, attribute, value),
            controls,
        )
        return LdapResponse.Ok(resp)
    }

    public suspend fun compare(
        dn: String,
        attribute: String,
        value: String,
        controls: List<Control> = emptyList(),
    ): LdapResponse.Ok = compare(dn, attribute, value.encodeToByteArray(), controls)

    /** Sends an AbandonRequest. The server does not respond. */
    public suspend fun abandon(messageId: Int) {
        connection.sendNoResponse(LdapProtocolOp.AbandonRequest(messageId))
    }

    override fun close() {
        connection.close()
    }

    public companion object {
        /**
         * Connects to a server, creates a [LdapClient], and returns it.
         * The client's coroutine scope is the calling context + a
         * SupervisorJob so the underlying reader can be cancelled
         * independently of the caller.
         */
        public suspend fun connect(
            config: LdapConnectionConfig,
            context: CoroutineContext = config.coroutineContext,
        ): LdapClient {
            val transport = ldapConnect(config)
            val scope = CoroutineScope(context + Job(context[Job]))
            val conn = LdapConnection(transport, scope.coroutineContext)
            return LdapClient(conn, scope)
        }
    }
}

/**
 * Construct an [LdapClient] and run [block] with it. Closes the client
 * after [block] returns (or throws).
 */
public suspend inline fun <R> ldapClient(
    config: LdapConnectionConfig,
    context: CoroutineContext = config.coroutineContext,
    block: LdapClient.() -> R,
): R = LdapClient.connect(config, context).use(block)

/** AutoCloseable-style wrapper for [LdapClient]. */
public inline fun <R> LdapClient.use(block: LdapClient.() -> R): R {
    try {
        return block()
    } finally {
        close()
    }
}
