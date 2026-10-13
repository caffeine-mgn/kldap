package pw.binom.ldap.transport

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.Socket
import io.ktor.network.sockets.awaitClosed
import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel

/**
 * Low-level LDAP transport: a connected TCP or TLS socket exposed as ktor-io channels.
 *
 * - TCP variant wraps a raw [Socket] from `aSocket(...).tcp().connect(host, port)`.
 * - TLS variant wraps the same socket with a [TlsTunnel] backed by `pw.binom.tls` — the
 *   [input]/[output] channels then carry decrypted/plaintext LDAP bytes.
 *
 * The ktor-io [ByteReadChannel] / [ByteWriteChannel] are the streaming primitives; the
 * LDAP message framing (read length, then read N bytes) lives one layer up in `connection/`.
 *
 * The transport owns its [SelectorManager] (and, for TLS, the tunnel) and closes them
 * together with the socket, so callers only need a single [close].
 */
public class LdapTransport internal constructor(
    public val input: ByteReadChannel,
    public val output: ByteWriteChannel,
    private val socket: Socket,
    private val selector: SelectorManager?,
    private val tls: TlsTunnel? = null,
) {
    /** Whether the underlying socket is closed. */
    public val closed: Boolean get() = socket.socketContext.isCompleted

    /** Closes the underlying socket. Safe to call multiple times. */
    public fun close() {
        tls?.close()
        socket.close()
        selector?.close()
    }

    /** Suspends until the underlying socket is fully closed. */
    public suspend fun awaitClosed() {
        socket.awaitClosed()
    }
}
