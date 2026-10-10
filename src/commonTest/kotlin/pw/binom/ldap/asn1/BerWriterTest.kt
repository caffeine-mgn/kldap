package pw.binom.ldap.asn1

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class BerWriterTest {
    private fun writer(): Pair<BerWriter, Buffer> {
        val (w, b) = BerWriter.create()
        return w to b
    }

    private fun bytes(buffer: Buffer): ByteArray {
        val n = buffer.size.toInt()
        return buffer.readByteArray(n)
    }

    @Test
    fun writeBoolean() {
        val (w, b) = writer()
        w.writeBoolean(true)
        assertContentEquals(byteArrayOf(0x01, 0x01, 0xFF.toByte()), bytes(b))

        val (w2, b2) = writer()
        w2.writeBoolean(false)
        assertContentEquals(byteArrayOf(0x01, 0x01, 0x00), bytes(b2))
    }

    @Test
    fun writeIntegerZeroUsesMinimalEncoding() {
        val (w, b) = writer()
        w.writeInteger(0L)
        // BER requires INTEGER 0 to be encoded as 0x00 (not as empty).
        assertContentEquals(byteArrayOf(0x02, 0x01, 0x00), bytes(b))
    }

    @Test
    fun writeIntegerStripsLeadingZeros() {
        // 1 should be 0x02 0x01 0x01 (single byte, no leading 0x00)
        val (w1, b1) = writer()
        w1.writeInteger(1L)
        assertContentEquals(byteArrayOf(0x02, 0x01, 0x01), bytes(b1))

        // 127 should be 0x02 0x01 0x7F
        val (w2, b2) = writer()
        w2.writeInteger(127L)
        assertContentEquals(byteArrayOf(0x02, 0x01, 0x7F), bytes(b2))

        // 128 needs leading 0x00 because 0x80 alone would be interpreted as -128.
        val (w3, b3) = writer()
        w3.writeInteger(128L)
        assertContentEquals(byteArrayOf(0x02, 0x02, 0x00, 0x80.toByte()), bytes(b3))

        // 258 = 0x01 0x02 → 0x02 0x02 0x01 0x02
        val (w4, b4) = writer()
        w4.writeInteger(258L)
        assertContentEquals(byteArrayOf(0x02, 0x02, 0x01, 0x02), bytes(b4))
    }

    @Test
    fun writeIntegerMultiByte() {
        // 65536 = 0x01 0x00 0x00
        val (w, b) = writer()
        w.writeInteger(65536L)
        assertContentEquals(byteArrayOf(0x02, 0x03, 0x01, 0x00, 0x00), bytes(b))
    }

    @Test
    fun writeOctetString() {
        val payload = "hello".encodeToByteArray()
        val (w, b) = writer()
        w.writeOctetString(payload)
        assertContentEquals(byteArrayOf(0x04, 0x05) + payload, bytes(b))
    }

    @Test
    fun writeEmptyOctetString() {
        val (w, b) = writer()
        w.writeOctetString(ByteArray(0))
        assertContentEquals(byteArrayOf(0x04, 0x00), bytes(b))
    }

    @Test
    fun writeUtf8String() {
        val (w, b) = writer()
        val text = "Привет"
        w.writeUtf8String(text)
        val payload = text.encodeToByteArray()
        assertContentEquals(byteArrayOf(0x0C, payload.size.toByte()) + payload, bytes(b))
    }

    @Test
    fun writeNull() {
        val (w, b) = writer()
        w.writeNull()
        assertContentEquals(byteArrayOf(0x05, 0x00), bytes(b))
    }

    @Test
    fun writeOidSimple() {
        // 1.2 -> 0x2A
        val (w, b) = writer()
        w.writeOid("1.2")
        assertContentEquals(byteArrayOf(0x06, 0x01, 0x2A), bytes(b))
    }

    @Test
    fun writeOidWithLongArcs() {
        // 1.3.6.1.4.1.4203.1.11.3
        // 1*40+3 = 43 = 0x2B
        // 6 -> 0x06
        // 1 -> 0x01
        // 4 -> 0x04
        // 1 -> 0x01
        // 4203 (2 bytes): 4203 mod 128 = 107 (0x6B); 4203 / 128 = 32 (0x20);
        //   MSB continuation: 0xA0, 0x6B
        // 1 -> 0x01
        // 11 -> 0x0B
        // 3 -> 0x03
        // total content bytes = 10
        val expected =
            byteArrayOf(
                0x06,
                0x0A,
                0x2B,
                0x06,
                0x01,
                0x04,
                0x01,
                0xA0.toByte(),
                0x6B,
                0x01,
                0x0B,
                0x03,
            )
        val (w, b) = writer()
        w.writeOid("1.3.6.1.4.1.4203.1.11.3")
        assertContentEquals(expected, bytes(b))
    }

    @Test
    fun writeOidRejectsBadFirstArc() {
        val (w, _) = writer()
        assertFailsWith<IllegalArgumentException> {
            w.writeOid("3.1")
        }
    }

    @Test
    fun writeSequenceBackfillsLength() {
        val (w, b) = writer()
        w.writeSequence {
            writeInteger(42L)
        }
        // SEQUENCE { INTEGER 42 } = 0x30 0x03 0x02 0x01 0x2A
        assertContentEquals(byteArrayOf(0x30, 0x03, 0x02, 0x01, 0x2A), bytes(b))
    }

    @Test
    fun writeNestedSequences() {
        val (w, b) = writer()
        w.writeSequence {
            writeInteger(1L) // messageID
            writeSequence(BerTag.application(3)) {
                // SearchRequest tag
                writeUtf8String("dc=example,dc=com") // base DN
                writeInteger(2L) // scope
                writeInteger(0L) // derefAliases
                writeInteger(0L) // sizeLimit
                writeInteger(0L) // timeLimit
                writeBoolean(false) // typesOnly
            }
        }
        val out = bytes(b)
        // Outer: 0x30 (tag) + length
        assertEquals(0x30.toByte(), out[0])
        // We don't pin every byte, but we can verify round-trip via BerReader.
        val reader = BerReader.of(out)
        reader.seq {
            assertEquals(1L, readInteger())
            seq(BerTag.application(3)) {
                assertEquals("dc=example,dc=com", readUtf8String())
                assertEquals(2L, readInteger())
                assertEquals(0L, readInteger())
                assertEquals(0L, readInteger())
                assertEquals(0L, readInteger())
                assertEquals(false, readBoolean())
            }
        }
    }

    @Test
    fun writeApplicationTag() {
        val (w, b) = writer()
        w.writeTag(BerTag.application(0, constructed = true))
        // BindRequest tag (APPLICATION 0, constructed) = 0x60
        assertContentEquals(byteArrayOf(0x60), bytes(b))
    }

    @Test
    fun writeLengthLongForm() {
        val (w, b) = writer()
        w.writeLength(200)
        assertContentEquals(byteArrayOf(0x81.toByte(), 0xC8.toByte()), bytes(b))

        val (w2, b2) = writer()
        w2.writeLength(300)
        // 300 = 0x012C -> 0x82 0x01 0x2C
        assertContentEquals(byteArrayOf(0x82.toByte(), 0x01, 0x2C), bytes(b2))

        val (w3, b3) = writer()
        w3.writeLength(0x10000)
        // 0x10000 = 0x010000 -> 0x83 0x01 0x00 0x00
        assertContentEquals(byteArrayOf(0x83.toByte(), 0x01, 0x00, 0x00), bytes(b3))
    }

    @Test
    fun negativeLengthRejected() {
        val (w, _) = writer()
        assertFailsWith<IllegalArgumentException> {
            w.writeLength(-1)
        }
    }
}
