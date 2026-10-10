package pw.binom.ldap.connection

import io.ktor.utils.io.ByteReadChannel
import kotlinx.atomicfu.atomic
import kotlinx.atomicfu.locks.SynchronizedObject
import kotlinx.atomicfu.locks.synchronized
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import pw.binom.ldap.protocol.Control
import pw.binom.ldap.protocol.LdapMessage
import pw.binom.ldap.protocol.LdapProtocolOp
import pw.binom.ldap.transport.LdapTransport
import kotlin.coroutines.CoroutineContext

/**
 * A single LDAP connection over a [LdapTransport].
 *
 * Owns a background reader coroutine that demultiplexes incoming
 * [LdapMessage]s by `messageID` to the right in-flight caller. Writes are
 * serialized through a mutex; many callers can have [send] /
 * [sendNoResponse] / [sendAndStream] calls in flight simultaneously,
 * but only one wire write happens at a time.
 *
 * Two kinds of in-flight requests:
 * - Single-response: [send] returns the first matching message.
 * - Streaming: [sendAndStream] returns a [Flow] that emits every
 *   matching message (e.g. for a search that yields multiple
 *   SearchResultEntry / SearchResultReference / SearchResultDone
 *   messages).
 *
 * Lifecycle:
 * - [close] cancels the reader and tears down the transport.
 * - Calling [close] more than once is a no-op.
 * - Closing the transport from the outside surfaces as a failure on every
 *   pending [send] / [sendAndStream] call.
 */
public class LdapConnection internal constructor(
    private val transport: LdapTransport,
    parentContext: CoroutineContext,
) : AutoCloseable {

    private val scope: CoroutineScope =
        CoroutineScope(parentContext + Job(parentContext[Job]))
    private val inFlightLock = SynchronizedObject()

    /** Single-shot in-flight: one message per messageID. */
    private val inFlight = mutableMapOf<Int, CompletableDeferred<LdapMessage>>()

    /** Streaming in-flight: many messages per messageID. */
    private val inFlightStreams = mutableMapOf<Int, Channel<LdapMessage>>()

    private val writeMutex = Mutex()
    private val messageIdMutex = Mutex()
    private val nextMessageIdValue = atomic(0)
    private val closed = atomic(false)

    private val readerJob: Job = scope.launch {
        try {
            readerLoop(transport.input)
        } catch (ce: CancellationException) {
            // Connection is being closed; fail every pending send() so
            // callers don't hang on await() forever.
            failAllPendingSuspend(ce)
            throw ce
        } catch (t: Throwable) {
            failAllPendingSuspend(t)
        }
    }

    /**
     * Sends [op] (with [controls]) and suspends until the matching response
     * message arrives. The returned [LdapMessage] carries the same `messageID`.
     *
     * For operations that return multiple responses (e.g. search) use
     * [sendAndStream] instead.
     */
    public suspend fun send(
        op: LdapProtocolOp,
        controls: List<Control> = emptyList(),
    ): LdapMessage {
        val id = nextMessageId()
        val message = LdapMessage(id, op, controls)
        val deferred = CompletableDeferred<LdapMessage>()
        registerSingle(id, deferred)
        try {
            writeMutex.withLock { LdapMessageChannel.write(transport.output, message) }
            return deferred.await()
        } catch (ce: CancellationException) {
            deregisterSingle(id)
            throw ce
        } catch (t: Throwable) {
            deregisterSingle(id)
            throw t
        }
    }

    /**
     * Sends [op] (with [controls]) and returns a [Flow] that emits every
     * response message sharing the request's messageID. The flow closes
     * when the server sends a "terminal" response for that messageID —
     * in practice, anything other than [LdapProtocolOp.SearchResultEntry]
     * or [LdapProtocolOp.SearchResultReference] (i.e. a `*Response` or
     * `SearchResultDone`).
     */
    public fun sendAndStream(
        op: LdapProtocolOp,
        controls: List<Control> = emptyList(),
    ): Flow<LdapMessage> = flow {
        val id = nextMessageId()
        val message = LdapMessage(id, op, controls)
        val channel = Channel<LdapMessage>(capacity = Channel.UNLIMITED)
        registerStream(id, channel)
        try {
            writeMutex.withLock { LdapMessageChannel.write(transport.output, message) }
        } catch (t: Throwable) {
            deregisterStream(id)
            channel.close(t)
            throw t
        }
        try {
            for (msg in channel) {
                emit(msg)
                val isTerminal = when (val o = msg.op) {
                    is LdapProtocolOp.SearchResultEntry -> false
                    is LdapProtocolOp.SearchResultReference -> false
                    else -> true
                }
                if (isTerminal) break
            }
        } finally {
            deregisterStream(id)
            channel.close()
        }
    }

    /**
     * Fire-and-forget send. Used for [LdapProtocolOp.UnbindRequest] and
     * [LdapProtocolOp.AbandonRequest] which never receive a response.
     */
    public suspend fun sendNoResponse(
        op: LdapProtocolOp,
        controls: List<Control> = emptyList(),
    ) {
        val id = nextMessageId()
        val message = LdapMessage(id, op, controls)
        writeMutex.withLock { LdapMessageChannel.write(transport.output, message) }
    }

    override fun close() {
        if (!closed.compareAndSet(expect = false, update = true)) return
        // Synchronously fail every pending send so that callers do not
        // hang on `deferred.await()` after close(). The synchronized
        // block here is the same lock that send() and dispatch() acquire
        // for in-flight access, so a registration in progress will be
        // ordered either before (we'll fail it) or after (it'll see
        // `closed == true` and bail). Either way no await() blocks
        // forever.
        failAllPendingLocked(LdapEndOfStreamException("Connection closed"))
        scope.cancel("LdapConnection closed")
        transport.close()
    }

    private fun failAllPendingLocked(cause: Throwable) = synchronized(inFlightLock) {
        for ((_, deferred) in inFlight) {
            deferred.completeExceptionally(cause)
        }
        inFlight.clear()
        for ((_, channel) in inFlightStreams) {
            channel.close(cause)
        }
        inFlightStreams.clear()
    }

    private suspend fun readerLoop(input: ByteReadChannel) {
        while (currentCoroutineContext()[Job]?.isActive != false) {
            val message = LdapMessageChannel.read(input)
            dispatch(message)
        }
    }

    private fun dispatch(message: LdapMessage) {
        val id = message.messageId
        val (deferred, channel) = synchronized(inFlightLock) {
            val d = inFlight.remove(id)
            val c = inFlightStreams[id]
            d to c
        }
        when {
            channel != null -> {
                // Streaming request: forward the message. If the channel
                // was already closed (e.g. by a teardown), the send is a
                // no-op.
                val ok = channel.trySend(message).isSuccess
                if (!ok) {
                    // Channel was closed; ignore.
                }
            }
            deferred != null -> {
                deferred.complete(message)
            }
            // Untracked messageID (e.g. unsolicited notification from the
            // server) is dropped. LdapClient (step 6) will subscribe to
            // those through a separate channel if needed.
        }
    }

    private fun registerSingle(id: Int, deferred: CompletableDeferred<LdapMessage>) =
        synchronized(inFlightLock) { inFlight[id] = deferred }

    private fun deregisterSingle(id: Int) =
        synchronized(inFlightLock) { inFlight.remove(id) }

    private fun registerStream(id: Int, channel: Channel<LdapMessage>) =
        synchronized(inFlightLock) { inFlightStreams[id] = channel }

    private fun deregisterStream(id: Int) =
        synchronized(inFlightLock) { inFlightStreams.remove(id) }

    private fun failAllPendingSuspend(cause: Throwable) =
        failAllPendingLocked(cause)

    private suspend fun nextMessageId(): Int {
        // Atomic, monotonic, never zero. RFC 4511 messageID is any non-zero
        // positive integer; we skip 0 by wrapping from MAX_VALUE back to 1.
        return messageIdMutex.withLock {
            val cur = nextMessageIdValue.value
            val next = if (cur == Int.MAX_VALUE) 1 else cur + 1
            nextMessageIdValue.value = next
            next
        }
    }
}
