package pw.binom.ldap.client

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import pw.binom.ldap.connection.LdapMessageChannel
import pw.binom.ldap.protocol.Authentication
import pw.binom.ldap.protocol.LdapFilter
import pw.binom.ldap.protocol.LdapProtocolOp
import pw.binom.ldap.protocol.LdapResult
import pw.binom.ldap.protocol.PartialAttribute
import pw.binom.ldap.protocol.ResultCode
import pw.binom.ldap.protocol.SearchScope
import pw.binom.ldap.transport.LdapConnectionConfig
import kotlin.coroutines.coroutineContext
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

class LdapClientTest {

    @Test
    fun bindSuccess() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port ->
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            val resp = withTimeout(5_000) {
                client.bind("cn=admin", Authentication.Simple("secret"))
            }
            assertEquals(ResultCode.SUCCESS, resp.resultCode())
            assertIs<LdapProtocolOp.BindResponse>(resp.op)
            client.close()
        }
    }

    @Test
    fun bindFailure() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port, responder ->
            responder.sendResult = LdapProtocolOp.BindResponse(
                result = LdapResult(
                    resultCode = ResultCode.INVALID_CREDENTIALS,
                    matchedDn = "",
                    diagnosticMessage = "wrong password",
                ),
            )
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            val resp = withTimeout(5_000) {
                client.bind("cn=admin", Authentication.Simple("wrong"))
            }
            assertEquals(ResultCode.INVALID_CREDENTIALS, resp.resultCode())
            client.close()
        }
    }

    @Test
    fun addReturnsResponse() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port, responder ->
            responder.sendResult = LdapProtocolOp.AddResponse(
                result = LdapResult(ResultCode.SUCCESS, "", ""),
            )
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            val resp = withTimeout(5_000) {
                client.add(
                    dn = "dc=example,dc=com",
                    attributes = listOf(
                        PartialAttribute("objectClass", listOf("top".encodeToByteArray())),
                        PartialAttribute("dc", listOf("example".encodeToByteArray())),
                    ),
                )
            }
            assertEquals(ResultCode.SUCCESS, resp.resultCode())
            client.close()
        }
    }

    @Test
    fun searchOneReturnsFirstEntry() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port, responder ->
            responder.streamResponses = listOf(
                LdapProtocolOp.SearchResultEntry(
                    objectName = "dc=example,dc=com",
                    attributes = listOf(
                        PartialAttribute(
                            "objectClass",
                            listOf("top".encodeToByteArray()),
                        ),
                    ),
                ),
                LdapProtocolOp.SearchResultEntry(
                    objectName = "ou=users,dc=example,dc=com",
                    attributes = listOf(
                        PartialAttribute(
                            "objectClass",
                            listOf("organizationalUnit".encodeToByteArray()),
                        ),
                    ),
                ),
                LdapProtocolOp.SearchResultDone(
                    result = LdapResult(ResultCode.SUCCESS, "", ""),
                ),
            )
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            val entry = withTimeout(5_000) {
                client.searchOne(
                    baseDn = "dc=example,dc=com",
                    scope = SearchScope.WHOLE_SUBTREE,
                    filter = LdapFilter.Present("objectClass"),
                )
            }
            assertNotNull(entry)
            assertEquals("dc=example,dc=com", entry.op.objectName)
            assertEquals("top", entry.op.firstString("objectClass"))
            client.close()
        }
    }

    @Test
    fun searchAllStreamsEntriesAndDone() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port, responder ->
            responder.streamResponses = listOf(
                LdapProtocolOp.SearchResultEntry(
                    objectName = "uid=alice",
                    attributes = listOf(
                        PartialAttribute("cn", listOf("Alice".encodeToByteArray())),
                    ),
                ),
                LdapProtocolOp.SearchResultEntry(
                    objectName = "uid=bob",
                    attributes = listOf(
                        PartialAttribute("cn", listOf("Bob".encodeToByteArray())),
                    ),
                ),
                LdapProtocolOp.SearchResultDone(
                    result = LdapResult(ResultCode.SUCCESS, "", ""),
                ),
            )
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            val events = withTimeout(5_000) {
                client.searchAll(
                    baseDn = "ou=users",
                    scope = SearchScope.WHOLE_SUBTREE,
                    filter = LdapFilter.Present("objectClass"),
                )
            }
            assertEquals(3, events.size)
            assertIs<LdapResponse.Entry>(events[0])
            assertIs<LdapResponse.Entry>(events[1])
            assertIs<LdapResponse.Done>(events[2])
            assertEquals("Alice", (events[0] as LdapResponse.Entry).op.firstString("cn"))
            assertEquals("Bob", (events[1] as LdapResponse.Entry).op.firstString("cn"))
            client.close()
        }
    }

    @Test
    fun unbindTearsDown() = kotlinx.coroutines.runBlocking(Dispatchers.Default) {
        withMockServer { port, responder ->
            val client = LdapClient.connect(
                LdapConnectionConfig().apply {
                    host = "127.0.0.1"
                    this.port = port
                    coroutineContext = Dispatchers.Default
                },
            )
            withTimeout(5_000) { client.unbind() }
            // A second call to a closed client should fail.
            val ex = runCatching {
                withTimeout(2_000) {
                    client.bind("cn=u", Authentication.Simple("p"))
                }
            }.exceptionOrNull()
            assertNotNull(ex, "second bind should fail after unbind")
            // server stays open until scope ends
        }
    }
}

/** A responder template used by [withMockServer] to decide what to send. */
private class MockResponder {
    /** Single-result response to send for one-shot operations. */
    var sendResult: LdapProtocolOp = LdapProtocolOp.BindResponse(
        result = LdapResult(ResultCode.SUCCESS, "", ""),
    )

    /** Stream of responses to send for a search request (consumed per request). */
    var streamResponses: List<LdapProtocolOp> = emptyList()
}

/**
 * Spins up a one-shot mock LDAP server on 127.0.0.1:<random>. The server
 * accepts a single connection, reads a request, and either echoes
 * [MockResponder.sendResult] (one-shot) or replays
 * [MockResponder.streamResponses] (for search).
 */
private suspend fun withMockServer(
    block: suspend (port: Int, responder: MockResponder) -> Unit,
) = kotlinx.coroutines.coroutineScope {
    val serverSelector = SelectorManager(coroutineContext)
    val serverSocket = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
    val port = (serverSocket.localAddress as InetSocketAddress).port
    val responder = MockResponder()
    val quit = Channel<Unit>(1)
    val serverJob: Job = launch(serverSelector.coroutineContext) {
        try {
            val socket = serverSocket.accept()
            val input = socket.openReadChannel()
            val output = socket.openWriteChannel(autoFlush = true)
            try {
                while (true) {
                    val req = LdapMessageChannel.read(input)
                    val op = req.op
                    if (op is LdapProtocolOp.UnbindRequest) break
                    if (op is LdapProtocolOp.AbandonRequest) continue
                    if (op is LdapProtocolOp.SearchRequest && responder.streamResponses.isNotEmpty()) {
                        for (resp in responder.streamResponses) {
                            LdapMessageChannel.write(output, req.copy(op = resp))
                        }
                    } else {
                        LdapMessageChannel.write(output, req.copy(op = responder.sendResult))
                    }
                }
            } catch (ce: CancellationException) {
                throw ce
            } catch (_: Throwable) {
                // Test ended; ignore.
            }
            try {
                socket.close()
            } catch (_: Throwable) {
            }
        } finally {
            quit.trySend(Unit)
        }
    }
    try {
        block(port, responder)
    } finally {
        try {
            withTimeout(1_000) { quit.receive() }
        } catch (_: Throwable) {
        }
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

private suspend fun withMockServer(
    block: suspend (port: Int) -> Unit,
) = withMockServer { port, _ -> block(port) }

@Suppress("unused")
private val unused: Unit = Unit
