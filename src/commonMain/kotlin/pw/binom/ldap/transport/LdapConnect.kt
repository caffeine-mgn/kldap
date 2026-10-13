package pw.binom.ldap.transport

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import pw.binom.tls.socket.SSLContext

/**
 * Connects to an LDAP/LDAPS server and returns a ready-to-use [LdapTransport].
 *
 * - [LdapConnectionConfig.ssl] = `false` → plain LDAP (default port 389).
 * - [LdapConnectionConfig.ssl] = `true`  → LDAPS (default port 636).
 *
 * The TCP connect is always done via ktor's socket API. For TLS the raw socket's
 * channels are wrapped by a [TlsTunnel] backed by `pw.binom.tls`, which exposes the
 * decrypted/plaintext bytes through the same ktor-io channels the TCP variant uses.
 *
 * The returned transport owns its [SelectorManager] (and, for TLS, the tunnel) — close
 * it (or use `use { }`) to release the socket, the selector and the TLS session.
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

    if (!config.ssl) {
        return LdapTransport(
            input = rawSocket.openReadChannel(),
            output = rawSocket.openWriteChannel(autoFlush = true),
            socket = rawSocket,
            selector = selector,
        )
    }

    val serverName = config.serverName ?: config.host
    val tunnel = TlsTunnel(
        rawInput = rawSocket.openReadChannel(),
        rawOutput = rawSocket.openWriteChannel(autoFlush = true),
        context = config.coroutineContext,
        sslContext = SSLContext.client(trustAll = config.trustAll),
        serverName = serverName,
        port = effectivePort,
    )
    return LdapTransport(
        input = tunnel.input,
        output = tunnel.output,
        socket = rawSocket,
        selector = selector,
        tls = tunnel,
    )
}
