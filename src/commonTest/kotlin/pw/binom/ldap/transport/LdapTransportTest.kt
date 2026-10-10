package pw.binom.ldap.transport

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LdapTransportTest {
    @Test
    fun tcpConnectReadAndClose() =
        runBlocking {
            val serverSelector = SelectorManager()
            val serverSocket = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
            val serverPort = (serverSocket.localAddress as InetSocketAddress).port

            val serverPayload = "Hello, LDAP!"
            val serverJob: Job = launch(serverSelector.coroutineContext) {
                val socket = serverSocket.accept()
                val output = socket.openWriteChannel(autoFlush = true)
                output.writeStringUtf8("$serverPayload\n")
                socket.close()
            }

            try {
                val client = withTimeout(5_000) {
                    ldapConnect(
                        LdapConnectionConfig().apply {
                            host = "127.0.0.1"
                            port = serverPort
                        },
                    )
                }

                val line = withTimeout(5_000) { client.input.readUTF8Line() }
                assertEquals(serverPayload, line) // readUTF8Line strips the trailing \n

                client.close()
                serverJob.join()
                withTimeout(5_000) { client.awaitClosed() }
                assertTrue(client.closed, "client transport should be closed after close()")
            } finally {
                serverJob.cancel()
                serverSocket.close()
                serverSelector.close()
            }
        }

    @Test
    fun closeIsIdempotent() =
        runBlocking {
            val serverSelector = SelectorManager()
            val serverSocket = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
            val port2 = (serverSocket.localAddress as InetSocketAddress).port

            val serverJob: Job = launch(serverSelector.coroutineContext) {
                val socket = serverSocket.accept()
                socket.openReadChannel().readUTF8Line()
            }

            try {
                val client = withTimeout(5_000) {
                    ldapConnect(
                        LdapConnectionConfig().apply {
                            host = "127.0.0.1"
                            port = port2
                        },
                    )
                }
                client.close()
                client.close()
                withTimeout(5_000) { client.awaitClosed() }
                assertTrue(client.closed)
            } finally {
                serverJob.cancel()
                serverSocket.close()
                serverSelector.close()
            }
        }

    @Test
    fun defaultPorts() {
        val tcpConfig = LdapConnectionConfig()
        assertFalse(tcpConfig.ssl)
        assertEquals(0, tcpConfig.port)

        val tlsConfig = LdapConnectionConfig().apply { ssl = true }
        assertTrue(tlsConfig.ssl)
        assertEquals(0, tlsConfig.port)
    }
}
