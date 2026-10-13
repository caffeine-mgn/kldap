package pw.binom.ldap.transport

import io.ktor.utils.io.ByteChannel
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.writeFully
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import pw.binom.tls.socket.SSLContext
import pw.binom.tls.socket.SSLSession

/**
 * Bridges a [SSLSession] to ktor-io [ByteReadChannel] / [ByteWriteChannel], so the
 * LDAP connection layer keeps its streaming coroutine model while TLS is provided by
 * `pw.binom.tls`.
 *
 * Why not `pw.binom.tls.socket.TlsConnection`: its `read`/`write` are blocking and
 * **single-flight** (read and write may not overlap; OpenSSL `SSL*` is not
 * thread-safe). kldap runs a continuous background reader while requests are being
 * written, so a blocking `TlsConnection` would deadlock the first write. This tunnel
 * instead drives the raw [SSLSession] state machine (`readNet`/`writeNet`/`readApp`/
 * `writeApp`) from a pair of coroutines that never block while holding the session:
 * all session calls are short, non-blocking and serialized through [sessionLock].
 */
internal class TlsTunnel(
    private val rawInput: ByteReadChannel,
    private val rawOutput: ByteWriteChannel,
    context: kotlin.coroutines.CoroutineContext,
    sslContext: SSLContext,
    serverName: String,
    port: Int,
) : AutoCloseable {

    private val scope = CoroutineScope(context + SupervisorJob())
    private val session: SSLSession = sslContext.clientSession(serverName, port)

    private val sessionLock = Mutex()
    private val progress = Channel<Unit>(Channel.CONFLATED)

    private val appIn = ByteChannel(autoFlush = true)
    private val appOut = ByteChannel(autoFlush = true)

    /** Decrypted application bytes coming from the peer. */
    val input: ByteReadChannel get() = appIn

    /** Application bytes to encrypt and send to the peer. */
    val output: ByteWriteChannel get() = appOut

    private val netIn = ByteArray(NET_BUF_SIZE)
    private val netOut = ByteArray(NET_BUF_SIZE)
    private val appBuf = ByteArray(NET_BUF_SIZE)

    init {
        scope.launch { pumpRead() }
        scope.launch { pumpWrite() }
    }

    override fun close() {
        scope.cancel("TlsTunnel closed")
        runCatching { session.shutdown() }
        runCatching { session.close() }
        runCatching { appIn.close() }
        runCatching { appOut.close() }
    }

    /**
     * Reads TLS records from the socket, feeds them to the session, and pushes the
     * decrypted output (and any session-generated records) onward.
     */
    private suspend fun pumpRead() {
        try {
            while (true) {
                val n = rawInput.readAvailable(netIn, 0, netIn.size)
                if (n < 0) break
                if (n == 0) continue
                var net: ByteArray? = null
                var app: ByteArray? = null
                sessionLock.withLock {
                    session.writeNet(netIn, 0, n)
                    net = drainNetLocked()
                    app = drainAppLocked()
                }
                net?.let { emit(rawOutput, it) }
                app?.let { emit(appIn, it) }
                progress.trySend(Unit)
            }
        } catch (_: Throwable) {
            fail()
        } finally {
            runCatching { appIn.close() }
        }
    }

    /** Reads plaintext from the application and encrypts it into the socket. */
    private suspend fun pumpWrite() {
        try {
            while (true) {
                val n = appOut.readAvailable(appBuf, 0, appBuf.size)
                if (n < 0) break
                if (n == 0) continue
                var offset = 0
                while (offset < n) {
                    var net: ByteArray? = null
                    var app: ByteArray? = null
                    var wantRead = false
                    sessionLock.withLock {
                        val status = session.writeApp(appBuf, offset, n - offset)
                        offset += status.bytes
                        net = drainNetLocked()
                        app = drainAppLocked()
                        when (status.state) {
                            SSLSession.State.OK, SSLSession.State.WANT_WRITE -> Unit
                            SSLSession.State.WANT_READ -> wantRead = true
                            SSLSession.State.CLOSED ->
                                throw LdapTlsException("TLS session closed during write")
                            SSLSession.State.ERROR ->
                                throw LdapTlsException("TLS write failed")
                        }
                    }
                    net?.let { emit(rawOutput, it) }
                    app?.let { emit(appIn, it) }
                    if (wantRead && offset < n) progress.receive()
                }
            }
        } catch (_: Throwable) {
            fail()
        }
    }

    private fun drainNetLocked(): ByteArray? = accumulate {
        session.readNet(netOut, 0, netOut.size)
    }

    private fun drainAppLocked(): ByteArray? {
        var out: ByteArray? = null
        while (true) {
            val status = session.readApp(appBuf, 0, appBuf.size)
            if (status.state != SSLSession.State.OK || status.bytes <= 0) break
            out = append(out, appBuf, status.bytes)
        }
        return out
    }

    private inline fun accumulate(read: () -> Int): ByteArray? {
        var out: ByteArray? = null
        while (true) {
            val n = read()
            if (n <= 0) break
            out = append(out, netOut, n)
        }
        return out
    }

    private fun append(acc: ByteArray?, src: ByteArray, length: Int): ByteArray {
        if (acc == null) return src.copyOf(length)
        val merged = ByteArray(acc.size + length)
        acc.copyInto(merged)
        src.copyInto(merged, acc.size, 0, length)
        return merged
    }

    private suspend fun emit(channel: ByteWriteChannel, data: ByteArray) {
        if (data.isEmpty()) return
        channel.writeFully(data, 0, data.size)
        channel.flush()
    }

    private fun fail() {
        runCatching { appIn.close() }
        runCatching { appOut.close() }
    }

    private companion object {
        private const val NET_BUF_SIZE = 16 * 1024
    }
}

/** Raised when the TLS layer fails to write/negotiate. */
public class LdapTlsException(message: String, cause: Throwable? = null) : RuntimeException(message, cause)
