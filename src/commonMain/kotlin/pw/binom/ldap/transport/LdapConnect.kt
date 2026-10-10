package pw.binom.ldap.transport

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.network.tls.tls

/**
 * Connects to an LDAP/LDAPS server and returns a ready-to-use [LdapTransport].
 *
 * - [LdapConnectionConfig.ssl] = `false` → plain LDAP (default port 389).
 * - [LdapConnectionConfig.ssl] = `true`  → LDAPS (default port 636).
 *
 * The function performs a TCP connect, optionally upgrades to TLS via ktor's
 * `Socket.tls(...)` extension (which has expect/actual implementations for every
 * supported KMP target), and opens the read/write channels on the (possibly TLS-wrapped)
 * socket.
 *
 * The returned transport owns its [SelectorManager] — close it (or use `use { }`)
 * to release both the socket and the selector.
 */
public suspend fun ldapConnect(config: LdapConnectionConfig): LdapTransport {
    val effectivePort = when {
        config.port != 0 -> config.port
        config.ssl -> 636
        else -> 389
    }
    val selector = SelectorManager(config.coroutineContext)
    val rawSocket = aSocket(selector)
        .tcp()
        .connect(InetSocketAddress(config.host, effectivePort))
    val socket = if (config.ssl) {
        rawSocket.tls(config.coroutineContext) {
            serverName = config.serverName ?: config.host
        }
    } else {
        rawSocket
    }
    return LdapTransport(
        input = socket.openReadChannel(),
        output = socket.openWriteChannel(autoFlush = true),
        socket = socket,
        selector = selector,
    )
}
