package pw.binom.ldap.asn1

import kotlinx.io.Buffer
import kotlinx.io.Source

/**
 * ASN.1 tag (X.680 §8.6, X.690 §8.1.2).
 *
 * A tag consists of three logical parts:
 * - [clazz] — universal / application / context-specific / private
 * - [constructed] — whether the value is itself a structured (constructed) BER element;
 *            for LDAP almost every operation uses constructed tags
 * - [number] — the tag number within the class (e.g. 16 for SEQUENCE, 0 for
 *            APPLICATION 0 = LDAP BindRequest, 4 for APPLICATION 4 = SearchResultEntry, …)
 *
 * Encoded form (X.690 §8.1.2.3):
 * ```
 *   first byte:  c c 1 P  n n n n
 *                 │ │   │
 *                 │ │   └── low 5 bits of tag number (0..30)
 *                 │ └────── primitive (0) / constructed (1)
 *                 └──────── class bits
 *
 *   if low5 == 11111 (i.e. number >= 31): subsequent bytes encode the
 *   full tag number with base-128, MSB continuation bit. This is rare in LDAP.
 * ```
 */
public class BerTag(
    public val clazz: TagClass,
    public val constructed: Boolean,
    public val number: Int,
) {
    init {
        require(number >= 0) { "Tag number must be non-negative, got $number" }
        require(number <= 0xFFFFFF) { "Tag number too large for BER: $number" }
    }

    public val isPrimitive: Boolean get() = !constructed

    /** Encodes this tag to bytes (X.690 §8.1.2.3). */
    public fun encode(): ByteArray {
        val firstByte =
            (clazz.bit shl 6) or (if (constructed) 0x20 else 0) or
                if (number < 0x1F) number else 0x1F
        if (number < 0x1F) {
            return byteArrayOf(firstByte.toByte())
        }
        // Long form: base-128 encoding of the tag number, MSB=1 means "continue".
        var n = number
        val tail = ArrayDeque<Byte>()
        tail.addFirst((n and 0x7F).toByte())
        n = n shr 7
        while (n > 0) {
            tail.addFirst(((n and 0x7F) or 0x80).toByte())
            n = n shr 7
        }
        val out = ByteArray(1 + tail.size)
        out[0] = firstByte.toByte()
        var i = 1
        for (b in tail) {
            out[i++] = b
        }
        return out
    }

    override fun equals(other: Any?): Boolean =
        other is BerTag &&
            other.clazz == clazz &&
            other.constructed == constructed &&
            other.number == number

    override fun hashCode(): Int {
        var result = clazz.hashCode()
        result = 31 * result + constructed.hashCode()
        result = 31 * result + number
        return result
    }

    override fun toString(): String {
        val kind = if (constructed) "constructed" else "primitive"
        return "BerTag(${clazz.name.lowercase()}, $kind, #$number)"
    }

    public companion object {
        public val BOOLEAN: BerTag = BerTag(TagClass.Universal, false, 0x01)
        public val INTEGER: BerTag = BerTag(TagClass.Universal, false, 0x02)
        public val BIT_STRING: BerTag = BerTag(TagClass.Universal, false, 0x03)
        public val OCTET_STRING: BerTag = BerTag(TagClass.Universal, false, 0x04)
        public val NULL: BerTag = BerTag(TagClass.Universal, false, 0x05)
        public val OBJECT_IDENTIFIER: BerTag = BerTag(TagClass.Universal, false, 0x06)
        public val UTF8_STRING: BerTag = BerTag(TagClass.Universal, false, 0x0C)
        public val SEQUENCE: BerTag = BerTag(TagClass.Universal, true, 0x10)
        public val SET: BerTag = BerTag(TagClass.Universal, true, 0x11)

        /** LDAP message-type tags (APPLICATION, constructed, 0..N) — RFC 4511 §4.2. */
        public fun application(
            number: Int,
            constructed: Boolean = true,
        ): BerTag = BerTag(TagClass.Application, constructed, number)

        /** Convenience for LDAP CHOICE alternatives (e.g. attribute selection in SearchRequest). */
        public fun contextSpecific(
            number: Int,
            constructed: Boolean = false,
        ): BerTag = BerTag(TagClass.ContextSpecific, constructed, number)

        /** Decodes the leading identifier byte(s) from [source]. */
        public fun decode(source: Source): BerTag {
            val firstByte = source.readByte().toInt() and 0xFF
            val clazz = TagClass.fromBit((firstByte shr 6) and 0b11)
            val constructed = (firstByte and 0x20) != 0
            val low = firstByte and 0x1F
            if (low < 0x1F) {
                return BerTag(clazz, constructed, low)
            }
            var number = 0
            while (true) {
                val b = source.readByte().toInt() and 0xFF
                if (number > (Int.MAX_VALUE ushr 7)) {
                    throw IllegalStateException("BER tag number overflow")
                }
                number = (number shl 7) or (b and 0x7F)
                if ((b and 0x80) == 0) break
            }
            return BerTag(clazz, constructed, number)
        }

        /** Decodes the leading identifier byte(s) from the given [bytes]. */
        public fun decode(bytes: ByteArray): BerTag {
            val buffer = Buffer().apply { write(bytes) }
            return decode(buffer)
        }
    }
}
