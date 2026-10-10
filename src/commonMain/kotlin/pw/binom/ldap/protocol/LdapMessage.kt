package pw.binom.ldap.protocol

import kotlinx.io.Buffer
import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * LDAP message envelope (RFC 4511 §4.4).
 *
 * ```
 * LDAPMessage ::= SEQUENCE {
 *     messageID       MessageID,
 *     protocolOp      CHOICE { ... },
 *     controls       [0] Controls OPTIONAL
 * }
 *
 * Controls ::= SEQUENCE OF control Control
 * ```
 *
 * @param messageId Identifier for the request/response. Positive integers (RFC 4511 §4.4);
 *                  servers may echo `0` for unsolicited notifications.
 * @param op The protocol operation (request, response, intermediate).
 * @param controls Zero or more [Control]s attached to the message.
 */
public data class LdapMessage(
    val messageId: Int,
    val op: LdapProtocolOp,
    val controls: List<Control> = emptyList(),
) {
    /** Encodes this message as BER bytes. */
    public fun encode(): ByteArray {
        val buffer = Buffer()
        val writer = BerWriter(buffer)
        writer.writeSequence {
            // NOTE: calls use the implicit `this` (the inner writer), so writes
            // land in the sequence's sub-buffer and the length is back-filled.
            writeInteger(messageId.toLong())
            writeProtocolOp(op)
            if (controls.isNotEmpty()) {
                writeTagged(BerTag.contextSpecific(0, constructed = true)) {
                    writeSequence {
                        for (c in controls) writeControl(c)
                    }
                }
            }
        }
        return buffer.readByteArray()
    }

    public companion object {
        /** Decodes a BER-encoded LDAP message. */
        public fun decode(bytes: ByteArray): LdapMessage {
            val reader = BerReader.of(bytes)
            return reader.seq {
                val messageId = readInteger().toInt()
                val op = readProtocolOp()
                val controls =
                    if (source.exhausted()) {
                        emptyList()
                    } else {
                        seq(BerTag.contextSpecific(0, constructed = true)) {
                            seq(BerTag.SEQUENCE) {
                                val list = mutableListOf<Control>()
                                while (!source.exhausted()) list.add(readControl())
                                list
                            }
                        }
                    }
                LdapMessage(messageId, op, controls)
            }
        }
    }
}
