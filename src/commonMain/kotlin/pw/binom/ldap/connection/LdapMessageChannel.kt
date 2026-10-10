package pw.binom.ldap.connection

import io.ktor.utils.io.ByteReadChannel
import io.ktor.utils.io.ByteWriteChannel
import io.ktor.utils.io.readAvailable
import io.ktor.utils.io.readByte
import io.ktor.utils.io.writeFully
import pw.binom.ldap.protocol.LdapMessage

/**
 * BER encoder/decoder helpers that work directly against a ktor-io channel,
 * so the connection layer can stream messages without allocating a full
 * intermediate `ByteArray` for the wire bytes.
 *
 * The LDAP message envelope is `SEQUENCE { ... }`. We have to write the
 * outer SEQUENCE tag and length bytes so that [LdapMessage.decode] (and the
 * per-type helpers) can pick them up.
 */
internal object LdapMessageChannel {
    /**
     * Reads a complete [LdapMessage] from [input] (tag + length + body) and
     * decodes it. Throws if the leading tag is not 0x30 (the LDAP SEQUENCE)
     * or if the channel is closed mid-message.
     */
    suspend fun read(input: ByteReadChannel): LdapMessage {
        val tag = input.readByte()
        require(tag == 0x30.toByte()) {
            val t = tag.toInt() and 0xFF
            val hi = (t ushr 4) and 0x0F
            val lo = t and 0x0F
            val hex = charArrayOf(
                if (hi < 10) ('0' + hi) else ('a' + hi - 10),
                if (lo < 10) ('0' + lo) else ('a' + lo - 10),
            ).concatToString()
            "Expected LDAPMessage SEQUENCE tag 0x30, got 0x$hex"
        }
        val length = readBerLength(input)
        val body = ByteArray(length)
        readFully(input, body, 0, length)

        // Reassemble the full SEQUENCE (tag + length + body) so that the
        // existing BerReader-based decoder can process it.
        val full = ByteArray(1 + berLengthByteCount(length) + length)
        full[0] = tag
        writeBerLength(full, 1, length)
        body.copyInto(full, 1 + berLengthByteCount(length))
        return LdapMessage.decode(full)
    }

    /** Encodes [message] and writes it to [output], flushing at the end. */
    suspend fun write(
        output: ByteWriteChannel,
        message: LdapMessage,
    ) {
        val bytes = message.encode()
        output.writeFully(bytes, 0, bytes.size)
        output.flush()
    }

    /**
     * BER length octet(s) reader — short and long form. Rejects the
     * indefinite-length 0x80 marker (LDAP never emits it).
     */
    private suspend fun readBerLength(input: ByteReadChannel): Int {
        val first = input.readByte().toInt() and 0xFF
        if ((first and 0x80) == 0) return first
        val count = first and 0x7F
        require(count != 0) {
            "Indefinite BER length (0x80) is not supported; LDAP never emits it"
        }
        require(count in 1..4) { "BER length too long: $count bytes" }
        var length = 0
        for (i in 0 until count) {
            length = (length shl 8) or (input.readByte().toInt() and 0xFF)
        }
        return length
    }

    private fun berLengthByteCount(length: Int): Int = when {
        length < 0x80 -> 1
        length < 0x100 -> 2
        length < 0x10000 -> 3
        else -> 4
    }

    private fun writeBerLength(out: ByteArray, offset: Int, length: Int) {
        when {
            length < 0x80 -> out[offset] = length.toByte()
            length < 0x100 -> {
                out[offset] = 0x81.toByte()
                out[offset + 1] = length.toByte()
            }
            length < 0x10000 -> {
                out[offset] = 0x82.toByte()
                out[offset + 1] = (length ushr 8).toByte()
                out[offset + 2] = length.toByte()
            }
            else -> {
                out[offset] = 0x83.toByte()
                out[offset + 1] = (length ushr 16).toByte()
                out[offset + 2] = (length ushr 8).toByte()
                out[offset + 3] = length.toByte()
            }
        }
    }

    private suspend fun readFully(
        input: ByteReadChannel,
        dst: ByteArray,
        offset: Int,
        length: Int,
    ) {
        var read = 0
        while (read < length) {
            val n = input.readAvailable(dst, offset + read, length - read)
            if (n < 0) {
                throw LdapEndOfStreamException(
                    "Channel closed mid-message: expected $length bytes, got $read",
                )
            }
            if (n == 0) {
                throw LdapEndOfStreamException(
                    "Channel returned 0 bytes mid-read: expected $length total, got $read",
                )
            }
            read += n
        }
    }
}

/**
 * Optional API surface — the connection layer prefers the streaming
 * [LdapMessageChannel] above. This object is kept here so callers wanting to
 * encode a single message to a `ByteArray` (e.g. for tests) can do so without
 * a channel.
 */
internal object LdapMessageBytes {
    fun encode(message: LdapMessage): ByteArray = message.encode()
    fun decode(bytes: ByteArray): LdapMessage = LdapMessage.decode(bytes)
}
