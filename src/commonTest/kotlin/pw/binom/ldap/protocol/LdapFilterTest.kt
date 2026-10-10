package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerWriter
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class LdapFilterTest {
    private fun roundTrip(filter: LdapFilter): LdapFilter {
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeFilter(filter)
        val bytes = buffer.readByteArray()
        val reader = BerReader.of(bytes)
        return reader.readFilter()
    }

    @Test
    fun equalityMatchRoundTrip() {
        val original = LdapFilter.eq("objectClass", "inetOrgPerson")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(objectClass=inetOrgPerson)", decoded.toString())
    }

    @Test
    fun equalityMatchByteArrayRoundTrip() {
        val original = LdapFilter.EqualityMatch("mail", byteArrayOf(0x00, 0xFF.toByte(), 0x7F))
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun presentRoundTrip() {
        val original = LdapFilter.present("objectClass")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(objectClass=*)", decoded.toString())
    }

    @Test
    fun andRoundTrip() {
        val original =
            LdapFilter.and(
                LdapFilter.eq("objectClass", "person"),
                LdapFilter.eq("uid", "alice"),
            )
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(&(objectClass=person)(uid=alice))", decoded.toString())
    }

    @Test
    fun orRoundTrip() {
        val original =
            LdapFilter.or(
                LdapFilter.eq("uid", "alice"),
                LdapFilter.eq("uid", "bob"),
            )
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(|(uid=alice)(uid=bob))", decoded.toString())
    }

    @Test
    fun notRoundTrip() {
        val original = LdapFilter.not(LdapFilter.present("objectClass"))
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(!(objectClass=*))", decoded.toString())
    }

    @Test
    fun substringInitialOnly() {
        val original = LdapFilter.Substring("cn", initial = "ali", any = emptyList(), final = null)
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(cn=ali*)", decoded.toString())
    }

    @Test
    fun substringInitialAny() {
        val original =
            LdapFilter.Substring(
                attribute = "cn",
                initial = "ali",
                any = listOf("c", "e"),
                final = null,
            )
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(cn=ali*c*e*)", decoded.toString())
    }

    @Test
    fun substringFinalOnly() {
        val original = LdapFilter.Substring("cn", initial = null, any = emptyList(), final = "son")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(cn=*son)", decoded.toString())
    }

    @Test
    fun greaterOrEqualRoundTrip() {
        val original = LdapFilter.GreaterOrEqual("age", "X".encodeToByteArray())
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertEquals("(age>=X)", decoded.toString())
    }

    @Test
    fun lessOrEqualRoundTrip() {
        val original = LdapFilter.LessOrEqual("age", "100".encodeToByteArray())
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun approxMatchRoundTrip() {
        val original = LdapFilter.ApproxMatch("cn", "Janssen".encodeToByteArray())
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun nestedOperatorsRoundTrip() {
        val original =
            LdapFilter.and(
                LdapFilter.eq("objectClass", "groupOfNames"),
                LdapFilter.or(
                    LdapFilter.eq("member", "uid=alice,ou=People,dc=example,dc=com"),
                    LdapFilter.eq("member", "uid=bob,ou=People,dc=example,dc=com"),
                ),
                LdapFilter.not(LdapFilter.eq("cn", "admins")),
            )
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }

    @Test
    fun equalityMatchWireEncoding() {
        // RFC 4511 §4.5.1 reference wire bytes for (objectClass = person):
        //   0xA3 0x15  -- [3] tag, length 21
        //   0x04 0x0B 'objectClass'        -- type (11 bytes: 1+1+11 = 13)
        //   0x04 0x06 'person'              -- value (6 bytes: 1+1+6 = 8)
        //   total body: 13+8 = 21 bytes
        val filter = LdapFilter.eq("objectClass", "person")
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeFilter(filter)
        val bytes = buffer.readByteArray()
        assertContentEquals(
            byteArrayOf(
                0xA3.toByte(),
                21,
                0x04,
                0x0B,
                'o'.code.toByte(),
                'b'.code.toByte(),
                'j'.code.toByte(),
                'e'.code.toByte(),
                'c'.code.toByte(),
                't'.code.toByte(),
                'C'.code.toByte(),
                'l'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                's'.code.toByte(),
                0x04,
                0x06,
                'p'.code.toByte(),
                'e'.code.toByte(),
                'r'.code.toByte(),
                's'.code.toByte(),
                'o'.code.toByte(),
                'n'.code.toByte(),
            ),
            bytes,
        )
    }

    @Test
    fun presentWireEncoding() {
        // [7] AttributeDescription (primitive)
        //   0x87 0x0B 'objectClass'  (length 11)
        val filter = LdapFilter.present("objectClass")
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeFilter(filter)
        val bytes = buffer.readByteArray()
        assertContentEquals(
            byteArrayOf(
                0x87.toByte(),
                0x0B,
                'o'.code.toByte(),
                'b'.code.toByte(),
                'j'.code.toByte(),
                'e'.code.toByte(),
                'c'.code.toByte(),
                't'.code.toByte(),
                'C'.code.toByte(),
                'l'.code.toByte(),
                'a'.code.toByte(),
                's'.code.toByte(),
                's'.code.toByte(),
            ),
            bytes,
        )
    }

    @Test
    fun readOidSanityCheck() {
        // Sanity check that our OID codec handles dot-decimal correctly inside filter logic.
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeOid("1.2.840.113556.1.4.803")
        val bytes = buffer.readByteArray()
        val reader = BerReader.of(bytes)
        assertEquals("1.2.840.113556.1.4.803", reader.readOid())
    }
}
