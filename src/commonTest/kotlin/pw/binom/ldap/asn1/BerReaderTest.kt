package pw.binom.ldap.asn1

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BerReaderTest {
    @Test
    fun readBoolean() {
        val reader = BerReader.of(byteArrayOf(0x01, 0x01, 0xFF.toByte()))
        assertEquals(true, reader.readBoolean())

        val reader2 = BerReader.of(byteArrayOf(0x01, 0x01, 0x00))
        assertEquals(false, reader2.readBoolean())
    }

    @Test
    fun readIntegerShortForm() {
        // INTEGER 0 — BER requires encoding as 0x00
        assertEquals(0L, BerReader.of(byteArrayOf(0x02, 0x01, 0x00)).readInteger())
        // INTEGER 127
        assertEquals(127L, BerReader.of(byteArrayOf(0x02, 0x01, 0x7F)).readInteger())
        // INTEGER 128 — minimal encoding requires leading 0x00 because high bit is set
        assertEquals(128L, BerReader.of(byteArrayOf(0x02, 0x02, 0x00, 0x80.toByte())).readInteger())
        // INTEGER 256
        assertEquals(256L, BerReader.of(byteArrayOf(0x02, 0x02, 0x01, 0x00)).readInteger())
        // INTEGER 258 (LDAP result code "success")
        assertEquals(258L, BerReader.of(byteArrayOf(0x02, 0x02, 0x01, 0x02)).readInteger())
    }

    @Test
    fun readIntegerMultiByte() {
        // INTEGER 65536 = 0x01 0x00 0x00
        val bytes = byteArrayOf(0x02, 0x03, 0x01, 0x00, 0x00)
        assertEquals(65536L, BerReader.of(bytes).readInteger())
    }

    @Test
    fun readOctetString() {
        val payload = "hello".encodeToByteArray()
        val bytes = byteArrayOf(0x04, payload.size.toByte()) + payload
        assertContentEquals(payload, BerReader.of(bytes).readOctetString())
    }

    @Test
    fun readEmptyOctetString() {
        assertContentEquals(ByteArray(0), BerReader.of(byteArrayOf(0x04, 0x00)).readOctetString())
    }

    @Test
    fun readUtf8String() {
        val text = "Привет, LDAP! 🚀"
        val payload = text.encodeToByteArray()
        val bytes = byteArrayOf(0x0C, payload.size.toByte()) + payload
        assertEquals(text, BerReader.of(bytes).readUtf8String())
    }

    @Test
    fun readNull() {
        BerReader.of(byteArrayOf(0x05, 0x00)).readNull()
    }

    @Test
    fun readOidRfcExample() {
        // OID 1.2.840.113556.1.4.805
        // 1.2 -> 0x2A  (= 40*1 + 2)
        // 840 -> 0x86 0x48  (base-128 of 840: 6*128+72)
        // 113556 -> 0x86 0xF7 0x14
        //   113556 mod 128 = 20 (0x14); 113556 / 128 = 887
        //   887 mod 128 = 119 (0x77); 887 / 128 = 6
        //   → bytes 6, 119, 20 = 0x86 0xF7 0x14
        // 1 -> 0x01
        // 4 -> 0x04
        // 805 -> 0x86 0x25  (805 = 6*128 + 37; first byte = 6 with MSB continuation, second = 37)
        val oidBytes =
            byteArrayOf(
                0x06,
                0x0A, // OID, length 10
                0x2A, // 1.2
                0x86.toByte(),
                0x48.toByte(), // 840
                0x86.toByte(),
                0xF7.toByte(),
                0x14, // 113556
                0x01,
                0x04, // 1.4
                0x86.toByte(),
                0x25.toByte(), // 805
            )
        assertEquals("1.2.840.113556.1.4.805", BerReader.of(oidBytes).readOid())
    }

    @Test
    fun readSequenceScopesReader() {
        // SEQUENCE { INTEGER 42 }
        val bytes = byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x2A)
        BerReader.of(bytes).seq {
            // Inside seq() the sub-reader starts at the first inner element.
            assertEquals(42L, readInteger())
        }
    }

    @Test
    fun readSequenceExhaustsOnBoundary() {
        // SEQUENCE { OCTET STRING "ab" }  — total bytes 6 (0x30 0x04 0x04 0x02 0x61 0x62)
        val bytes = byteArrayOf(0x30, 0x04, 0x04, 0x02, 0x61, 0x62)
        BerReader.of(bytes).seq {
            assertContentEquals("ab".encodeToByteArray(), readOctetString())
            // After reading the octet string, the inner reader should be exhausted.
            assertTrue(exhausted())
        }
    }

    @Test
    fun readLengthShortForm() {
        val reader = BerReader.of(byteArrayOf(0x00))
        // Calling readLength here would consume just the 0x00 byte.
        assertEquals(0L, reader.readLength().toLong())
    }

    @Test
    fun readLengthLongForm() {
        // length = 200 -> 0x81 0xC8
        val reader = BerReader.of(byteArrayOf(0x81.toByte(), 0xC8.toByte()))
        assertEquals(200L, reader.readLength().toLong())
    }

    @Test
    fun indefiniteLengthRejected() {
        // 0x05 0x80 — tag NULL with indefinite length, then 0x00 0x00 EOC
        assertFailsWith<IllegalArgumentException> {
            BerReader.of(byteArrayOf(0x05, 0x80.toByte(), 0x00, 0x00)).readNull()
        }
    }

    @Test
    fun wrongTagRejected() {
        // Try to read INTEGER but element is OCTET STRING
        val bytes = byteArrayOf(0x04, 0x01, 0x00)
        assertFailsWith<IllegalArgumentException> {
            BerReader.of(bytes).readInteger()
        }
    }

    @Test
    fun skipElement() {
        // SEQUENCE { OCTET STRING "x", INTEGER 7 } -> bytes 0x30 0x06 0x04 0x01 0x78 0x02 0x01 0x07
        val bytes = byteArrayOf(0x30, 0x06, 0x04, 0x01, 0x78, 0x02, 0x01, 0x07)
        BerReader.of(bytes).seq {
            skipElement()
            assertEquals(7L, readInteger())
        }
    }
}
