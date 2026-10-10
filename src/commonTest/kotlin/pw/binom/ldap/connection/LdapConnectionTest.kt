package pw.binom.ldap.connection

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import pw.binom.ldap.protocol.Authentication
import pw.binom.ldap.protocol.LdapProtocolOp
import pw.binom.ldap.protocol.ResultCode
import pw.binom.ldap.transport.LdapConnectionConfig
import pw.binom.ldap.transport.ldapConnect
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class LdapConnectionTest {

    @Test
    fun sendBindAndReceiveResponse() = runBlocking(Dispatchers.Default) {
        withServer { port ->
            val transport = ldapConnect(LdapConnectionConfig().apply {
                host = "127.0.0.1"
                this.port = port
                coroutineContext = Dispatchers.Default
            })
            val conn = LdapConnection(transport, Dispatchers.Default)
            try {
                val resp = conn.send(
                    LdapProtocolOp.BindRequest(
                        version = 3,
                        name = "cn=admin,dc=example,dc=com",
                        authentication = Authentication.Simple("secret"),
                    ),
                )
                assertEquals(1, resp.messageId)
                val bindResp = resp.op as LdapProtocolOp.BindResponse
                assertEquals(ResultCode.SUCCESS, bindResp.result.resultCode)
            } finally {
                conn.close()
            }
        }
    }

    @Test
    fun messageIdsAreMonotonicAndUnique() = runBlocking(Dispatchers.Default) {
        withServer(count = 3) { port ->
            val transport = ldapConnect(LdapConnectionConfig().apply {
                host = "127.0.0.1"
                this.port = port
                coroutineContext = Dispatchers.Default
            })
            val conn = LdapConnection(transport, Dispatchers.Default)
            try {
                val ids = (1..3).map { iter ->
                    val r = withTimeout(10_000) {
                        conn
                            .send(
                                LdapProtocolOp.BindRequest(
                                    version = 3,
                                    name = "cn=user",
                                    authentication = Authentication.Simple("pw"),
                                ),
                            ).messageId
                    }
                    r
                }
                assertEquals(3, ids.size)
                assertEquals(ids.toSet().size, ids.size, "message ids must be unique")
                for (i in 1 until ids.size) {
                    assertTrue(ids[i] > ids[i - 1], "ids must be strictly increasing")
                }
            } finally {
                conn.close()
            }
        }
    }

    @Test
    fun sendNoResponseDoesNotBlock() = runBlocking(Dispatchers.Default) {
        withServer { port ->
            val transport = ldapConnect(LdapConnectionConfig().apply {
                host = "127.0.0.1"
                this.port = port
                coroutineContext = Dispatchers.Default
            })
            val conn = LdapConnection(transport, Dispatchers.Default)
            try {
                withTimeout(5_000) {
                    conn.sendNoResponse(LdapProtocolOp.UnbindRequest)
                }
            } finally {
                conn.close()
            }
        }
    }

    @Test
    fun closeFailsPendingSend() = runBlocking(Dispatchers.Default) {
        withServer(blockServer = true) { port ->
            val transport = ldapConnect(LdapConnectionConfig().apply {
                host = "127.0.0.1"
                this.port = port
                coroutineContext = Dispatchers.Default
            })
            val conn = LdapConnection(transport, Dispatchers.Default)
            val result = kotlinx.coroutines.CompletableDeferred<Throwable?>()

            @OptIn(ExperimentalCoroutinesApi::class)
            val sendJob = launch(Dispatchers.Default.limitedParallelism(8)) {
                try {
                    conn.send(
                        LdapProtocolOp.BindRequest(
                            version = 3,
                            name = "cn=u",
                            authentication = Authentication.Simple("p"),
                        ),
                    )
                    result.complete(null)
                } catch (t: Throwable) {
                    result.complete(t)
                }
            }
            // Let the send actually register in inFlight and start awaiting.
            kotlinx.coroutines.yield()
            conn.close()
            sendJob.join()
            val failure = result.await()
            assertTrue(failure != null, "send() should have failed after close()")
        }
    }

    /**
     * Spins up a one-shot mock LDAP server on 127.0.0.1:<random>. The server
     * accepts a single connection, optionally reads a fixed number of
     * requests, sends back a SUCCESS BindResponse for each, and closes.
     */
    private suspend fun withServer(
        count: Int = 1,
        blockServer: Boolean = false,
        block: suspend (port: Int) -> Unit,
    ) = coroutineScope {
        val serverSelector = SelectorManager(coroutineContext)
        val serverSocket = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
        val port = (serverSocket.localAddress as InetSocketAddress).port

        val serverJob: Job = launch(serverSelector.coroutineContext) {
            val socket = serverSocket.accept()
            val input = socket.openReadChannel()
            val output = socket.openWriteChannel(autoFlush = true)
            try {
                repeat(count) {
                    val req = LdapMessageChannel.read(input)
                    val bindResp = LdapProtocolOp.BindResponse(
                        result = pw.binom.ldap.protocol.LdapResult(
                            resultCode = ResultCode.SUCCESS,
                            matchedDn = "",
                            diagnosticMessage = "",
                        ),
                    )
                    LdapMessageChannel.write(
                        output,
                        req.copy(op = bindResp),
                    )
                }
            } catch (ce: kotlinx.coroutines.CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Test ended; ignore.
            }
            if (blockServer) {
                try {
                    kotlinx.coroutines.suspendCancellableCoroutine<Unit> { }
                } catch (_: kotlinx.coroutines.CancellationException) {
                    // Expected when the test tears down.
                }
            }
            try {
                output.flush()
            } catch (_: Throwable) {
            }
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        }

        try {
            block(port)
        } finally {
            serverJob.cancelAndJoin()
            try {
                serverSocket.close()
            } catch (_: Throwable) {
            }
            try {
                serverSelector.close()
            } catch (_: Throwable) {
            }
        }
    }
}
