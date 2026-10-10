package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerWriter
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class AuthenticationTest {
    private fun roundTrip(auth: Authentication): Authentication {
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeAuthentication(auth)
        val bytes = buffer.readByteArray()
        val reader = BerReader.of(bytes)
        return reader.readAuthentication()
    }

    @Test
    fun anonymousRoundTrip() {
        val original = Authentication.Simple("")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertTrue((decoded as Authentication.Simple).isAnonymous)
    }

    @Test
    fun simpleRoundTrip() {
        val original = Authentication.Simple("p@ssw0rd")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun saslRoundTrip() {
        val original =
            Authentication.Sasl(
                mechanism = "PLAIN",
                credentials =
                    byteArrayOf(
                        0,
                        'a'.code.toByte(),
                        'l'.code.toByte(),
                        'i'.code.toByte(),
                        'c'.code.toByte(),
                        'e'.code.toByte(),
                        0,
                        's'.code.toByte(),
                        'e'.code.toByte(),
                        'c'.code.toByte(),
                        'r'.code.toByte(),
                        'e'.code.toByte(),
                        't'.code.toByte(),
                    ),
            )
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun saslNoCredentialsRoundTrip() {
        val original = Authentication.Sasl(mechanism = "PLAIN")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun simpleWireEncoding() {
        // [0] OCTET STRING, 6 bytes: "secret"
        //   0x80 0x06 'secret'
        val auth = Authentication.Simple("secret")
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeAuthentication(auth)
        val bytes = buffer.readByteArray()
        assertContentEquals(
            byteArrayOf(
                0x80.toByte(),
                0x06,
                's'.code.toByte(),
                'e'.code.toByte(),
                'c'.code.toByte(),
                'r'.code.toByte(),
                'e'.code.toByte(),
                't'.code.toByte(),
            ),
            bytes,
        )
    }
}
