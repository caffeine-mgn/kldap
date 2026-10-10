package pw.binom.ldap.asn1

import kotlinx.io.Buffer
import kotlinx.io.Sink

/**
 * Streaming encoder for BER (Basic Encoding Rules) elements (X.690 §8).
 *
 * Wraps a [kotlinx.io.Sink] (typically a [Buffer] for in-memory encoding).
 * Every typed write emits a TLV triple (tag, length, value); constructed
 * elements like [writeSequence] defer the length encoding by writing into a
 * sub-buffer first.
 *
 * Typical usage:
 * ```
 * val buffer = Buffer()
 * val w = BerWriter(buffer)
 * w.writeSequence(BerTag.application(0)) {  // BindRequest tag
 *     writeInteger(1)              // messageID
 *     writeInteger(0)              // version
 *     writeOctetString(...)
 *     ...
 * }
 * ```
 *
 * Limitations: same as [BerReader] — indefinite lengths and arbitrary-precision
 * INTEGER are not supported because they don't appear in LDAP.
 */
public class BerWriter(
    @PublishedApi internal val sink: Sink,
) {
    /** Writes the raw identifier octets for [tag]. */
    public fun writeTag(tag: BerTag) {
        sink.write(tag.encode())
    }

    /**
     * Writes a BER length (X.690 §8.1.3).
     *
     * - `0..127` → short form (one byte).
     * - `>=128` → long form: `0x8N` followed by `N` big-endian bytes (N = 1..4 here;
     *   LDAP messages are far below 4 GiB).
     */
    public fun writeLength(length: Int) {
        require(length >= 0) { "Negative BER length: $length" }
        if (length < 0x80) {
            sink.writeByte(length.toByte())
            return
        }
        val numBytes =
            when {
                length <= 0xFF -> 1
                length <= 0xFFFF -> 2
                length <= 0xFFFFFF -> 3
                else -> 4
            }
        sink.writeByte((0x80 or numBytes).toByte())
        for (i in (numBytes - 1) downTo 0) {
            sink.writeByte(((length ushr (i * 8)) and 0xFF).toByte())
        }
    }

    /** Writes `BOOLEAN` (X.690 §11.1); uses 0xFF for `true` per the BER convention. */
    public fun writeBoolean(value: Boolean) {
        writeTag(BerTag.BOOLEAN)
        writeLength(1)
        sink.writeByte(if (value) 0xFF.toByte() else 0x00)
    }

    /**
     * Writes `INTEGER` (X.690 §12.1).
     *
     * Encodes using the minimum number of bytes and strips leading zero/sign-
     * extension octets, per §10.1 — so `0` is encoded as a single `0x00`, `1` as
     * a single `0x01`, `255` as `0x00 0xFF`, etc.
     */
    public fun writeInteger(value: Long) {
        writeTag(BerTag.INTEGER)
        if (value == 0L) {
            writeLength(1)
            sink.writeByte(0)
            return
        }
        // Render as 8 big-endian bytes, then strip leading 0x00 (or 0xFF if negative).
        val bytes = ByteArray(8)
        var v = value
        for (i in 7 downTo 0) {
            bytes[i] = (v and 0xFF).toByte()
            v = v ushr 8
        }
        var start = 0
        if (value > 0) {
            while (start < 7 &&
                bytes[start].toInt() == 0 &&
                (bytes[start + 1].toInt() and 0x80) == 0
            ) {
                start++
            }
        } else {
            while (start < 7 &&
                bytes[start].toInt() and 0xFF == 0xFF &&
                (bytes[start + 1].toInt() and 0x80) != 0
            ) {
                start++
            }
        }
        val out = bytes.copyOfRange(start, 8)
        writeLength(out.size)
        sink.write(out)
    }

    /** Writes `OCTET STRING` (X.690 §11.4) with the given raw payload. */
    public fun writeOctetString(bytes: ByteArray) {
        writeTag(BerTag.OCTET_STRING)
        writeLength(bytes.size)
        sink.write(bytes)
    }

    /** Writes `UTF8String` (X.690 §11.7) from a Kotlin [String]. */
    public fun writeUtf8String(value: String) {
        writeTag(BerTag.UTF8_STRING)
        writeLength(value.encodeToByteArray().size)
        sink.write(value.encodeToByteArray())
    }

    /** Writes `NULL` (X.690 §11.2). */
    public fun writeNull() {
        writeTag(BerTag.NULL)
        writeLength(0)
    }

    /** Writes raw bytes without any tag or length prefix. */
    public fun writeRawBytes(bytes: ByteArray) {
        sink.write(bytes)
    }

    /**
     * Writes `OBJECT IDENTIFIER` (X.690 §11.4 / §8.4).
     * Accepts the dotted-decimal form (e.g. `"1.3.6.1.4.1.4203.1.11.3"`).
     * The first two arcs are encoded into the first content byte per the rule
     * `first_byte = 40 * first_arc + second_arc`; this breaks for first_arc >= 2
     * but LDAP never uses such OIDs.
     */
    public fun writeOid(oid: String) {
        val parts = oid.split('.').map { it.toInt() }
        require(parts.size >= 2) { "OID must have at least two arcs, got '$oid'" }
        val firstArc = parts[0]
        val secondArc = parts[1]
        require(firstArc in 0..2) {
            "OID first arc must be 0, 1 or 2 (LDAP doesn't use larger); got $firstArc"
        }
        require(secondArc >= 0) { "OID second arc must be non-negative; got $secondArc" }
        val firstByte = 40 * firstArc + secondArc
        val tailBytes = ArrayList<Byte>(parts.size * 2)
        tailBytes.add(firstByte.toByte())
        for (i in 2 until parts.size) {
            encodeBase128(parts[i], tailBytes)
        }
        writeTag(BerTag.OBJECT_IDENTIFIER)
        writeLength(tailBytes.size)
        for (b in tailBytes) {
            sink.writeByte(b)
        }
    }

    private fun encodeBase128(
        value: Int,
        out: MutableList<Byte>,
    ) {
        require(value >= 0) { "OID arc must be non-negative, got $value" }
        if (value == 0) {
            out.add(0)
            return
        }
        val stack = ArrayDeque<Byte>()
        var n = value
        while (n > 0) {
            stack.addFirst((n and 0x7F).toByte())
            n = n ushr 7
        }
        // MSB=1 on all but the last byte to mark continuation.
        for (i in 0 until stack.size - 1) {
            out.add((stack[i].toInt() or 0x80).toByte())
        }
        out.add(stack.last())
    }

    /**
     * Writes a constructed element (e.g. [BerTag.SEQUENCE], LDAP application tags)
     * with a properly encoded length.
     *
     * The implementation runs [block] into a sub-buffer first, so the length
     * field can be back-filled once we know how many bytes were produced. This
     * means nested [writeSequence] calls allocate a Buffer per nesting level —
     * acceptable for LDAP traffic, which rarely goes deeper than 3-4 levels.
     */
    public inline fun writeSequence(
        tag: BerTag = BerTag.SEQUENCE,
        block: BerWriter.() -> Unit,
    ) {
        writeTag(tag)
        val sub = Buffer()
        val subWriter = BerWriter(sub)
        subWriter.block()
        val size = sub.size.toInt()
        writeLength(size)
        sink.write(sub, sub.size)
    }

    /**
     * Writes a constructed or primitive tag with a length and value body
     * (for non-SEQUENCE cases, e.g. `[APPLICATION 3]` SearchRequest, `[0] Controls`).
     *
     * The body is produced by running [block] into a sub-buffer first so the length
     * can be back-filled. Use [BerTag.SEQUENCE] explicitly when the inner tag must
     * remain a SEQUENCE; this helper writes [tag] as the only tag for the body.
     */
    public inline fun writeTagged(tag: BerTag, block: BerWriter.() -> Unit) {
        writeTag(tag)
        val sub = Buffer()
        val subWriter = BerWriter(sub)
        subWriter.block()
        val size = sub.size.toInt()
        writeLength(size)
        sink.write(sub, sub.size)
    }

    public companion object {
        /** Convenience: builds a writer over a new empty buffer; use [Buffer.readByteArray] to extract. */
        public fun create(): Pair<BerWriter, Buffer> {
            val buffer = Buffer()
            return BerWriter(buffer) to buffer
        }
    }
}
