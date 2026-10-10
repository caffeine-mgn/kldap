package pw.binom.ldap.asn1

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BerTagTest {
    @Test
    fun shortFormEncodeRoundtrip() {
        val tag = BerTag(TagClass.Universal, constructed = true, number = 0x10)
        assertEquals(BerTag.SEQUENCE, tag)
        val encoded = tag.encode()
        assertEquals(1, encoded.size)
        assertEquals(0x30.toByte(), encoded[0]) // constructed (1) | universal (00) | low5 = 0x10
    }

    @Test
    fun shortFormDecodeRoundtrip() {
        val tag = BerTag.contextSpecific(3)
        val decoded = BerTag.decode(tag.encode())
        assertEquals(tag, decoded)
    }

    @Test
    fun longFormEncode() {
        // LDAP doesn't usually hit long form, but the encoder must still work.
        val tag = BerTag(TagClass.Application, constructed = true, number = 200)
        val encoded = tag.encode()
        // First byte: 01 (application) | 1 (constructed) | 11111 (long form) = 0x7F
        assertEquals(0x7F.toByte(), encoded[0])
        // 200 in base-128: 200 = 0xC8 -> 0x81 0x48
        assertEquals(0x81.toByte(), encoded[1])
        assertEquals(0x48.toByte(), encoded[2])
    }

    @Test
    fun longFormDecode() {
        val tag = BerTag(TagClass.Application, constructed = true, number = 200)
        val decoded = BerTag.decode(byteArrayOf(0x7F.toByte(), 0x81.toByte(), 0x48.toByte()))
        assertEquals(tag, decoded)
    }

    @Test
    fun applicationHelpers() {
        assertEquals(
            BerTag(TagClass.Application, constructed = true, number = 0),
            BerTag.application(0),
        )
        assertEquals(
            BerTag(TagClass.Application, constructed = true, number = 4),
            BerTag.application(4),
        )
    }

    @Test
    fun universalConstantsAreStable() {
        assertEquals(0x01, BerTag.BOOLEAN.number)
        assertEquals(0x02, BerTag.INTEGER.number)
        assertEquals(0x04, BerTag.OCTET_STRING.number)
        assertEquals(0x05, BerTag.NULL.number)
        assertEquals(0x06, BerTag.OBJECT_IDENTIFIER.number)
        assertEquals(0x0C, BerTag.UTF8_STRING.number)
        assertEquals(0x10, BerTag.SEQUENCE.number)
        assertEquals(0x11, BerTag.SET.number)
    }

    @Test
    fun negativeNumberRejected() {
        assertFailsWith<IllegalArgumentException> {
            BerTag(TagClass.Universal, false, -1)
        }
    }
}
