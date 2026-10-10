package pw.binom.ldap.asn1

import kotlinx.io.Buffer
import kotlinx.io.Source
import kotlinx.io.readByteArray

/**
 * Streaming decoder for BER (Basic Encoding Rules) elements (X.690 §8).
 *
 * The reader is built around the "read tag, read length, read value" cadence that
 * every BER element follows (TLV — tag/length/value). Constructed elements
 * (`SEQUENCE`, `SET`, LDAP operations, …) are opened with [seq] which yields a
 * sub-reader scoped to exactly the declared length, so the top-level reader can
 * never read past the end of an inner element.
 *
 * Limitations:
 * - Indefinite-length form (length octet 0x80) is **not** supported — LDAP never
 *   emits it, but generic ASN.1 streams can.
 * - INTEGER is decoded as a 64-bit signed value. LDAP integers fit easily.
 * - BIT STRING's "unused bits" byte is consumed but ignored; callers get raw bytes.
 *
 * Typical usage:
 * ```
 * val reader = BerReader(buffer)
 * readTag().let { /* inspect operation tag */ }
 * readLength()
 * seq {  // open SEQUENCE
 *     val messageId = readInteger()
 *     // ...
 * }
 * ```
 */
public class BerReader(
    @PublishedApi internal val source: Source,
) {
    @PublishedApi
    internal var pendingValueBytes: Int = -1

    /** The tag read by the most recent [readTag] / typed-read call. */
    public var lastTag: BerTag? = null
        private set

    /** Reads and returns the next BER identifier (tag) octets (X.690 §8.1.2). */
    public fun readTag(): BerTag {
        pendingValueBytes = -1
        val tag = BerTag.decode(source)
        lastTag = tag
        return tag
    }

    /**
     * Reads and returns the BER length octet(s) (X.690 §8.1.3).
     *
     * Indefinite-length form (the octet 0x80) throws — LDAP doesn't use it.
     * The returned value is the length of the *value* portion that follows;
     * callers must consume exactly that many bytes before opening the next element.
     */
    public fun readLength(): Int {
        val first = source.readByte().toInt() and 0xFF
        if ((first and 0x80) == 0) {
            pendingValueBytes = first
            return first
        }
        val numBytes = first and 0x7F
        require(numBytes != 0) {
            "Indefinite BER length (0x80) is not supported; LDAP never emits it"
        }
        require(numBytes <= 4) { "BER length field too long: $numBytes bytes" }
        var len = 0
        for (i in 0 until numBytes) {
            len = (len shl 8) or (source.readByte().toInt() and 0xFF)
        }
        pendingValueBytes = len
        return len
    }

    /**
     * Reads the next element as TLV, returns `(tag, length)` so callers can
     * dispatch on the tag or recurse into a structured element.
     */
    public fun readHeader(): Pair<BerTag, Int> {
        val tag = readTag()
        val length = readLength()
        return tag to length
    }

    /**
     * Verifies the next tag equals [expected] and reads it. Returns the length
     * of the value portion. Useful when the caller wants to skip the value
     * itself (see [skipValue]).
     */
    public fun readHeader(expected: BerTag): Int {
        val actual = readTag()
        require(actual == expected) {
            "Expected $expected, got $actual"
        }
        return readLength()
    }

    /** Skips the value bytes of a previously read tag/length pair. */
    public fun skipValue(length: Int) {
        source.require(length.toLong())
        source.skip(length.toLong())
        pendingValueBytes = -1
    }

    /** Skips an entire BER element (header + value) — useful for CHOICE alternatives. */
    public fun skipElement() {
        val (_, length) = readHeader()
        skipValue(length)
    }

    /**
     * Reads the next element as a `BOOLEAN` (X.690 §11.1).
     * Any non-zero byte is treated as `true` (BER `TRUE` is 0xFF but interop
     * is the standard convention).
     */
    public fun readBoolean(): Boolean {
        readHeader(BerTag.BOOLEAN)
        require(pendingValueBytes == 1) {
            "BOOLEAN must have length 1, got $pendingValueBytes"
        }
        val b = source.readByte().toInt() and 0xFF
        pendingValueBytes = 0
        return b != 0
    }

    /**
     * Reads the next element as an `INTEGER` (X.690 §12.1).
     *
     * Stored as `Long` because LDAP result codes, message IDs and sizes fit
     * comfortably; full BER INTEGER can encode arbitrary two's-complement
     * values, but LDAP never uses more than 4 bytes.
     */
    public fun readInteger(): Long {
        readHeader(BerTag.INTEGER)
        val len = pendingValueBytes
        require(len in 1..8) { "BER INTEGER length out of range: $len" }
        var value = 0L
        for (i in 0 until len) {
            value = (value shl 8) or (source.readByte().toInt() and 0xFF).toLong()
        }
        pendingValueBytes = 0
        return value
    }

    /**
     * Reads the next element as an `OCTET STRING` (X.690 §11.4).
     * Returns the raw payload as a `ByteArray`.
     */
    public fun readOctetString(): ByteArray {
        readHeader(BerTag.OCTET_STRING)
        val len = pendingValueBytes
        val bytes = source.readByteArray(len)
        pendingValueBytes = 0
        return bytes
    }

    /** Reads the next element as a `UTF8String` (X.690 §11.7). */
    public fun readUtf8String(): String {
        readHeader(BerTag.UTF8_STRING)
        val len = pendingValueBytes
        val bytes = source.readByteArray(len)
        pendingValueBytes = 0
        return bytes.decodeToString()
    }

    /** Reads the next element as `NULL` (X.690 §11.2). */
    public fun readNull() {
        readHeader(BerTag.NULL)
        require(pendingValueBytes == 0) { "NULL must have length 0, got $pendingValueBytes" }
        pendingValueBytes = 0
    }

    /**
     * Reads the next element as an `OBJECT IDENTIFIER` (X.690 §11.4 and X.690 §8.4).
     *
     * Returns the dotted-decimal notation, e.g. `"1.3.6.1.4.1.4203.1.11.3"`.
     */
    public fun readOid(): String {
        readHeader(BerTag.OBJECT_IDENTIFIER)
        val len = pendingValueBytes
        require(len > 0) { "Empty OID" }
        val bytes = source.readByteArray(len)
        pendingValueBytes = 0
        val first = bytes[0].toInt() and 0xFF
        val firstArc = first / 40
        val secondArc = first % 40
        val sb = StringBuilder()
        sb.append(firstArc).append('.').append(secondArc)
        var arc = 0L
        for (i in 1 until bytes.size) {
            val b = bytes[i].toInt() and 0xFF
            arc = (arc shl 7) or (b and 0x7F).toLong()
            if ((b and 0x80) == 0) {
                sb.append('.').append(arc)
                arc = 0
            }
        }
        return sb.toString()
    }

    /**
     * Reads the next element as a constructed SEQUENCE (or any other constructed
     * tag, defaulting to [BerTag.SEQUENCE]) and returns a sub-reader scoped to
     * exactly the declared length of the value portion.
     *
     * Use [block] to operate on the sub-reader:
     * ```
     * seq {  // default tag = SEQUENCE
     *     val v = readInteger()
     *     ...
     * }
     * ```
     */

    public fun exhausted(): Boolean = source.exhausted()

    /** Peeks the next BER tag without consuming any bytes from the source. */
    public fun peekTag(): BerTag {
        val snapshot = source.peek()
        return BerTag.decode(snapshot)
    }

    /**
     * Reads the length of the next element and returns its raw value bytes.
     *
     * The tag must have been read already (via [readTag] or [readHeader]).
     * This is useful for IMPLICIT-tagged elements where the underlying
     * type tag is suppressed (e.g. LDAP `present` filter `[7] AttributeDescription`).
     */
    public fun readRawValue(): ByteArray {
        val length = readLength()
        return source.readByteArray(length)
    }

    /**
     * Reads a complete tag-length-value element with [expected] tag and returns the value bytes.
     * Unlike [readOctetString], the caller specifies the tag and the value can be any bytes.
     */
    public fun readTypedBytes(expected: BerTag): ByteArray {
        val length = readHeader(expected)
        return source.readByteArray(length)
    }

    public inline fun <R> seq(
        tag: BerTag = BerTag.SEQUENCE,
        block: BerReader.() -> R,
    ): R {
        readHeader(tag)
        val length = pendingValueBytes
        val subBytes = source.readByteArray(length)
        pendingValueBytes = 0
        val subBuffer = Buffer().apply { write(subBytes) }
        return BerReader(subBuffer).block()
    }

    public companion object {
        /** Convenience: wraps a [ByteArray] in a one-shot reader. */
        public fun of(bytes: ByteArray): BerReader {
            val buffer = Buffer().apply { write(bytes) }
            return BerReader(buffer)
        }
    }
}
