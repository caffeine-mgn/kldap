package pw.binom.ldap.transport

import io.ktor.network.selector.SelectorManager
import io.ktor.network.sockets.InetSocketAddress
import io.ktor.network.sockets.aSocket
import io.ktor.network.sockets.openReadChannel
import io.ktor.network.sockets.openWriteChannel
import io.ktor.utils.io.asSink
import io.ktor.utils.io.asSource
import io.ktor.utils.io.readUTF8Line
import io.ktor.utils.io.writeStringUtf8
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.io.buffered
import pw.binom.tls.socket.SSLContext
import pw.binom.tls.socket.tlsServer
import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Verifies the TLS path end to end: a mock LDAPS server is wrapped with
 * `pw.binom.tls` (server side), and [ldapConnect] with `ssl = true` drives the
 * client side through [TlsTunnel]. The self-signed test certificate is embedded
 * as DER (base64) so the test runs on every platform without extra tooling.
 */
class TlsTransportTest {

    @Test
    fun ldapsRoundTrip() =
        runBlocking(Dispatchers.Default) {
            val serverSelector = SelectorManager(Dispatchers.Default)
            val serverSocket = aSocket(serverSelector).tcp().bind("127.0.0.1", 0)
            val serverPort = (serverSocket.localAddress as InetSocketAddress).port

            val serverJob: Job = launch(Dispatchers.Default) {
                val socket = serverSocket.accept()
                try {
                    val source = socket.openReadChannel().asSource().buffered()
                    val sink = socket.openWriteChannel(autoFlush = true).asSink().buffered()
                    val tls = tlsServer(source, sink, SSLContext.server(listOf(TEST_CERT_DER), TEST_KEY_DER))
                    val buf = ByteArray(64)
                    val n = tls.read(buf)
                    if (n > 0) tls.write(buf, 0, n)
                    tls.close()
                } finally {
                    socket.close()
                }
            }

            try {
                val client = withTimeout(10_000) {
                    ldapConnect(
                        LdapConnectionConfig().apply {
                            host = "127.0.0.1"
                            port = serverPort
                            ssl = true
                            trustAll = true
                            serverName = "test"
                            coroutineContext = Dispatchers.Default
                        },
                    )
                }

                client.output.writeStringUtf8("secure-ping\n")
                client.output.flush()
                val line = withTimeout(10_000) { client.input.readUTF8Line() }
                assertEquals("secure-ping", line)

                client.close()
                serverJob.join()
                withTimeout(5_000) { client.awaitClosed() }
                assertTrue(client.closed, "TLS transport should be closed after close()")
            } finally {
                serverJob.cancel()
                serverSocket.close()
                serverSelector.close()
            }
        }

    private companion object {
        @OptIn(ExperimentalEncodingApi::class)
        val TEST_CERT_DER: ByteArray = Base64.decode(
            "MIIDATCCAemgAwIBAgIUcCH2NxbPwMbHY6kaD/njAU5bZWwwDQYJKoZIhvcNAQELBQAwDzENMAsGA1UE" +
                "AwwEdGVzdDAgFw0yNjEwMTMxMTI5MzlaGA8yMTI2MDkxOTExMjkzOVowDzENMAsGA1UEAwwEdGVzdDCC" +
                "ASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKwEa2VtqvqaT3Oulr1BkyrN9WBI7OIMXBLiHQgb" +
                "NeV7SA3Cl2xvv3Ysimy4JuCa1qhZ1TOKJtf2nXqnUfWegm8K4LV3TvQpBk0IqZ7p2/XyPdjr6icVCY9s" +
                "xTmPvIoP8zDeRYL0hTma4I8gP2R4JQhWp8PE2xHjlji9gUTnYR4HpGHFhsmuwYU0ynIx8FvYgp5l73xs" +
                "tcKxaWJC28ZQlTtFaFfoCg2BIUMllgYu0thPmkhjCzUM0Qgy4QdrclBw3GGSNzAqGMsPqpCXrOdGUheZ" +
                "j7gsyIikjglPgz0jn/ODJwJMSDgflMEEJgDemW6KCGTCDIihkFQ/YtUX4gQOpFECAwEAAaNTMFEwHQYD" +
                "VR0OBBYEFBpx3GucyvMzTUb6Rj7rupG6h7VOMB8GA1UdIwQYMBaAFBpx3GucyvMzTUb6Rj7rupG6h7VO" +
                "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABiJ0AkvFekyOSL4akt1ZOfkeKuzupnd" +
                "tb3CIIUy0Ee5vaIUirbI0Pz13VuS0qJZIYvRaZsQt+G/VTibQI6inK1LHVaGn5uLl0e9XjlJoyocCPFm" +
                "pcpHQ2oOZDUv6l7ZSLMPgaNGumLjZrzSej8nckcPZxXTZ6V0oVtTh5SdTFoBh8mgcr9OgjuSqgh3z7ec" +
                "7eROQlDWm8DJhGK6mIqsn28Hhc+OVZDPlMOUIcgkA72R+hro+lyaK+zQks1Xys+YR4L5FgpGiLVdqpPNr" +
                "rYFU0uil2WzCkenE6Yfsh7mvmF34uoQ1dS94EcU7p4v6IYpoeSjyHzOzyI/HoDkLPSlfIg=",
        )

        @OptIn(ExperimentalEncodingApi::class)
        val TEST_KEY_DER: ByteArray = Base64.decode(
            "MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCsBGtlbar6mk9zrpa9QZMqzfVgSOzi" +
                "DFwS4h0IGzXle0gNwpdsb792LIpsuCbgmtaoWdUziibX9p16p1H1noJvCuC1d070KQZNCKme6dv18j3Y" +
                "6+onFQmPbMU5j7yKD/Mw3kWC9IU5muCPID9keCUIVqfDxNsR45Y4vYFE52EeB6RhxYbJrsGFNMpyMfBb" +
                "2IKeZe98bLXCsWliQtvGUJU7RWhX6AoNgSFDJZYGLtLYT5pIYws1DNEIMuEHa3JQcNxhkjcwKhjLD6qQ" +
                "l6znRlIXmY+4LMiIpI4JT4M9I5/zgycCTEg4H5TBBCYA3pluighkwgyIoZBUP2LVF+IEDqRRAgMBAAEC" +
                "ggEAFcphiHHCDQjrM65ULhlWeT+p686RI3mJWGMIZnR7+VwKnqOd5wCo8mFmD6usURuMQbtPhL3lecol3" +
                "NnBSioQP9zS5mn8uHVR9QQ56IWbdaaAKzCHcvf5RA/1U/tfWOX4WqJtj89F6Swzci4VmbaWil3f1q7jS" +
                "XrZFsr6yy28Yb9E6JuZsLvTnYEzRNetJ1ULEtw/32JO31Fevh0LWPoFqJHNo7ibQqjSZ5MPkNee5O72+" +
                "R+C9xshvsKLQwWf7RFmI04QbdRQ8m9CnutpHM8KLOaUHDewvTsuHYGrtRPKE7YjovTWKIomtYQCOy5vd" +
                "7PNhAgI0tCMAZlTvk7aaOFqeQKBgQDVxKTiNBkI+omXw6Wk6IgcULaba7qdFe/GLTeuRInCllKfiCdv" +
                "QriI0kbY9RRcCJEFh3HFYz9PtX1Mvd0m/pwFWkwWZ2GPJQXVueANY76NzDiX2CX2iM3vx2pukGYIUseo" +
                "VCbEUoaeiUPbfwHhZShaQgpantAQQa89xYugfCWanwKBgQDOADfyGHetB5dBDNCwYFAj8o4Awf8tp6FR" +
                "0PTuSuh54Vd8+ENhZfKPq9hKHQf4fYpJQ7vM7HEn9r9iaHzfnoKn467a6dEGQ6pUrdPt9CN1O6ETavrD" +
                "yVKpFymvI8hpNE56o0cXjwApejYXl114Q3+9ELkmE7aGPDZPIdiVabJLDwKBgD0I4GsVpPBDWHXUjr7/" +
                "BZ3QDdNidu3TDZrv3i4Ls6mzcfPK1DeYPUgTgdcAYsfESmPhwEIzjCgeEaCPtU0k9TcyCPd8nQZZ88iK" +
                "QcaQ7B9gZ+gy9uPlO6dysJjQ8dD+kbMmE8uKJJWva4iIQukwEM10fbBSF+YMWxSwCqXPzIzRAoGAQh5p" +
                "1oep6dyU3KkrVmEjd9ZDY9TgfZvfOG50HwPmCDCerxrULa/WIe0LOAaHZ2eL+iYGYijFzQjytrhI1FGB" +
                "KDf5CIShtXwEcLd2XVrOArPH6H6ezDaTFHi9xVwb2ECUq+I6UEJyz91M/Vd1BcPMfTef5avQGte6qr13" +
                "UcWiF1sCgYADQEvI2fVkPxD4N/qRY6EZlnWdB1vUyQpenFEsySEgRa6aWYRombhUiiOXb1FisAEw44kn" +
                "VTC7sawh8Jn2BXz8K+0DNBxL2WOfUqE+XT5DRK479Luvu3zFy628Q/hM1Ebg/9VDl66SD7eBiTREqRSS" +
                "FArRueDj1kZLSQjylh5b9g==",
        )
    }
}
