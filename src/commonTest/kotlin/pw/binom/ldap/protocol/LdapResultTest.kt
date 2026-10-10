package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerWriter
import kotlin.test.Test
import kotlin.test.assertEquals

class LdapResultTest {
    @Test
    fun simpleResultRoundTrip() {
        val original =
            LdapResult(
                resultCode = ResultCode.SUCCESS,
                matchedDn = "",
                diagnosticMessage = "",
            )
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeLdapResult(original)
        val bytes = buffer.readByteArray()
        val reader = BerReader.of(bytes)
        val decoded = reader.readLdapResult()
        assertEquals(original, decoded)
        assertEquals(emptyList(), decoded.referrals)
    }

    @Test
    fun resultWithReferralsRoundTrip() {
        val original =
            LdapResult(
                resultCode = ResultCode.REFERRAL,
                matchedDn = "",
                diagnosticMessage = "",
                referrals =
                    listOf(
                        "ldap://other.example.com/dc=example,dc=com",
                    ),
            )
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeLdapResult(original)
        val bytes = buffer.readByteArray()
        val reader = BerReader.of(bytes)
        val decoded = reader.readLdapResult()
        assertEquals(original, decoded)
    }
}
