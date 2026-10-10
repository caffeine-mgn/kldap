package pw.binom.ldap.protocol

import kotlinx.io.readByteArray
import pw.binom.ldap.asn1.BerReader
import pw.binom.ldap.asn1.BerTag
import pw.binom.ldap.asn1.BerWriter

/**
 * LDAP change operation type (RFC 4511 §4.6 — `operation` field of ModifyRequest).
 *
 * Encoded as `ENUMERATED`.
 */
public enum class ChangeOperation(
    public val code: Int,
) {
    ADD(0),
    DELETE(1),
    REPLACE(2),
    ;

    public companion object {
        public fun fromCode(code: Int): ChangeOperation =
            entries.firstOrNull { it.code == code } ?: error("Unknown ChangeOperation code: $code")
    }
}

/**
 * A single modification in a [ModifyRequest].
 *
 * Encoded as `SEQUENCE { operation ENUMERATED, modification PartialAttribute }`.
 */
public class Modification(
    public val operation: ChangeOperation,
    public val attribute: PartialAttribute,
) {
    override fun equals(other: Any?): Boolean =
        other is Modification && operation == other.operation && attribute == other.attribute

    override fun hashCode(): Int = operation.hashCode() * 31 + attribute.hashCode()

    override fun toString(): String = "$operation ${attribute.type}"
}

/**
 * LDAP protocol operations (RFC 4511 §4.4 — `protocolOp` CHOICE).
 *
 * Each operation carries an `APPLICATION` tag (0-19) and an APPLICATION-class
 * tag is constructed for the SEQUENCE-bearing ones (BindRequest etc.) and
 * primitive for `NULL`/single-element ones (UnbindRequest, AbandonRequest).
 *
 * This sealed class is the union of all LDAP requests and responses.
 */
public sealed class LdapProtocolOp {
    /**
     * LDAP bind request (RFC 4511 §4.2 — `[APPLICATION 0] SEQUENCE`).
     *
     * @param version Protocol version (typically `3`).
     * @param name Bind DN (often empty for anonymous bind).
     * @param authentication Simple/SASL auth choice.
     */
    public class BindRequest(
        public val version: Int,
        public val name: String,
        public val authentication: Authentication,
    ) : LdapProtocolOp() {
        override fun toString(): String = "BindRequest(version=$version, name='$name', $authentication)"
    }

    /**
     * LDAP bind response (RFC 4511 §4.2 — `[APPLICATION 1] SEQUENCE`).
     *
     * @param result Common LDAP result (resultCode, matchedDn, diagnosticMessage, referrals).
     * @param serverSaslCreds Optional server SASL credentials for in-progress binds.
     */
    public class BindResponse(
        public val result: LdapResult,
        public val serverSaslCreds: ByteArray? = null,
    ) : LdapProtocolOp() {
        override fun toString(): String = "BindResponse($result${if (serverSaslCreds != null) ", saslCreds" else ""})"
    }

    /**
     * LDAP unbind request (RFC 4511 §4.2 — `[APPLICATION 2] NULL`).
     */
    public data object UnbindRequest : LdapProtocolOp() {
        override fun toString(): String = "UnbindRequest"
    }

    /**
     * LDAP search request (RFC 4511 §4.5.1 — `[APPLICATION 3] SEQUENCE`).
     */
    public class SearchRequest(
        public val baseDn: String,
        public val scope: SearchScope,
        public val derefAliases: DerefAliases,
        public val sizeLimit: Int,
        public val timeLimit: Int,
        public val typesOnly: Boolean,
        public val filter: LdapFilter,
        public val attributes: List<String>,
    ) : LdapProtocolOp() {
        override fun toString(): String = "SearchRequest(baseDn='$baseDn', scope=$scope, filter=$filter)"
    }

    /**
     * LDAP search result entry — one entry matching a search (RFC 4511 §4.5.2).
     */
    public class SearchResultEntry(
        public val objectName: String,
        public val attributes: List<PartialAttribute>,
    ) : LdapProtocolOp() {
        override fun toString(): String = "SearchResultEntry(name='$objectName', ${attributes.size} attrs)"
    }

    /**
     * LDAP search done response (RFC 4511 §4.5.3 — `[APPLICATION 5] SEQUENCE { LDAPResult }`).
     */
    public class SearchResultDone(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "SearchResultDone($result)"
    }

    /**
     * LDAP search result reference — a referral encountered mid-search (RFC 4511 §4.5.4).
     */
    public class SearchResultReference(
        public val uris: List<String>,
    ) : LdapProtocolOp() {
        override fun toString(): String = "SearchResultReference($uris)"
    }

    /**
     * LDAP modify request (RFC 4511 §4.6 — `[APPLICATION 6] SEQUENCE`).
     */
    public class ModifyRequest(
        public val dn: String,
        public val changes: List<Modification>,
    ) : LdapProtocolOp() {
        override fun toString(): String = "ModifyRequest(dn='$dn', ${changes.size} changes)"
    }

    /** Modify response (RFC 4511 §4.6 — `[APPLICATION 7] SEQUENCE { LDAPResult }`). */
    public class ModifyResponse(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "ModifyResponse($result)"
    }

    /**
     * LDAP add request (RFC 4511 §4.7 — `[APPLICATION 8] SEQUENCE { entry, AttributeList }`).
     */
    public class AddRequest(
        public val dn: String,
        public val attributes: List<PartialAttribute>,
    ) : LdapProtocolOp() {
        override fun toString(): String = "AddRequest(dn='$dn', ${attributes.size} attrs)"
    }

    /** Add response (RFC 4511 §4.7 — `[APPLICATION 9] SEQUENCE { LDAPResult }`). */
    public class AddResponse(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "AddResponse($result)"
    }

    /** Delete request (RFC 4511 §4.8 — `[APPLICATION 10] NULL`). */
    public class DelRequest(
        public val dn: String,
    ) : LdapProtocolOp() {
        override fun toString(): String = "DelRequest(dn='$dn')"
    }

    /** Delete response (RFC 4511 §4.8 — `[APPLICATION 11] SEQUENCE { LDAPResult }`). */
    public class DelResponse(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "DelResponse($result)"
    }

    /**
     * LDAP modify-DN request (RFC 4511 §4.9 — `[APPLICATION 12] SEQUENCE`).
     */
    public class ModifyDNRequest(
        public val dn: String,
        public val newRdn: String,
        public val deleteOldRdn: Boolean,
        public val newSuperior: String? = null,
    ) : LdapProtocolOp() {
        override fun toString(): String = "ModifyDNRequest(dn='$dn', newRdn='$newRdn')"
    }

    /** Modify-DN response (RFC 4511 §4.9 — `[APPLICATION 13] SEQUENCE { LDAPResult }`). */
    public class ModifyDNResponse(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "ModifyDNResponse($result)"
    }

    /**
     * LDAP compare request (RFC 4511 §4.10 — `[APPLICATION 14] SEQUENCE`).
     */
    public class CompareRequest(
        public val dn: String,
        public val attribute: String,
        public val value: ByteArray,
    ) : LdapProtocolOp() {
        override fun equals(other: Any?): Boolean =
            other is CompareRequest &&
                dn == other.dn &&
                attribute == other.attribute &&
                value.contentEquals(other.value)

        override fun hashCode(): Int = dn.hashCode() * 31 + attribute.hashCode() * 31 + value.contentHashCode()

        override fun toString(): String = "CompareRequest(dn='$dn', $attribute=${value.decodeToString()})"
    }

    /** Compare response (RFC 4511 §4.10 — `[APPLICATION 15] SEQUENCE { LDAPResult }`). */
    public class CompareResponse(
        public val result: LdapResult,
    ) : LdapProtocolOp() {
        override fun toString(): String = "CompareResponse($result)"
    }

    /**
     * LDAP abandon request (RFC 4511 §4.11 — `[APPLICATION 16] MessageID`).
     *
     * @param targetMessageId The message ID of the in-flight request to abandon.
     */
    public class AbandonRequest(
        public val targetMessageId: Int,
    ) : LdapProtocolOp() {
        override fun toString(): String = "AbandonRequest(targetMessageId=$targetMessageId)"
    }
}

internal fun BerWriter.writeProtocolOp(op: LdapProtocolOp) {
    when (op) {
        is LdapProtocolOp.BindRequest ->
            writeTagged(BerTag.application(0)) {
                writeSequence {
                    writeInteger(op.version.toLong())
                    writeUtf8String(op.name)
                    writeAuthentication(op.authentication)
                }
            }
        is LdapProtocolOp.BindResponse ->
            writeTagged(BerTag.application(1)) {
                writeSequence {
                    writeLdapResult(op.result)
                    if (op.serverSaslCreds != null) {
                        writeTagged(BerTag.contextSpecific(7, constructed = false)) {
                            writeRawBytes(op.serverSaslCreds)
                        }
                    }
                }
            }
        is LdapProtocolOp.UnbindRequest ->
            writeTagged(BerTag.application(2, constructed = false)) {
                // No body — [APPLICATION 2] NULL has empty body
            }
        is LdapProtocolOp.SearchRequest ->
            writeTagged(BerTag.application(3)) {
                writeSequence {
                    writeUtf8String(op.baseDn)
                    writeInteger(op.scope.code.toLong())
                    writeInteger(op.derefAliases.code.toLong())
                    writeInteger(op.sizeLimit.toLong())
                    writeInteger(op.timeLimit.toLong())
                    writeBoolean(op.typesOnly)
                    writeFilter(op.filter)
                    writeSequence {
                        for (a in op.attributes) writeUtf8String(a)
                    }
                }
            }
        is LdapProtocolOp.SearchResultEntry ->
            writeTagged(BerTag.application(4)) {
                writeSequence {
                    writeUtf8String(op.objectName)
                    writeSequence {
                        for (pa in op.attributes) writePartialAttribute(pa)
                    }
                }
            }
        is LdapProtocolOp.SearchResultDone ->
            writeTagged(BerTag.application(5)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.SearchResultReference ->
            writeTagged(BerTag.application(19)) {
                // [APPLICATION 19] IMPLICIT SEQUENCE OF LDAPURL — the application tag
                // replaces the SEQUENCE tag, so the body is the URIs themselves (no inner wrapper).
                for (u in op.uris) writeUtf8String(u)
            }
        is LdapProtocolOp.ModifyRequest ->
            writeTagged(BerTag.application(6)) {
                writeSequence {
                    writeUtf8String(op.dn)
                    writeSequence {
                        for (m in op.changes) {
                            writeSequence {
                                writeInteger(m.operation.code.toLong())
                                writePartialAttribute(m.attribute)
                            }
                        }
                    }
                }
            }
        is LdapProtocolOp.ModifyResponse ->
            writeTagged(BerTag.application(7)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.AddRequest ->
            writeTagged(BerTag.application(8)) {
                writeSequence {
                    writeUtf8String(op.dn)
                    writeSequence {
                        for (pa in op.attributes) writePartialAttribute(pa)
                    }
                }
            }
        is LdapProtocolOp.AddResponse ->
            writeTagged(BerTag.application(9)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.DelRequest ->
            writeTagged(BerTag.application(10)) {
                writeSequence {
                    writeUtf8String(op.dn)
                }
            }
        is LdapProtocolOp.DelResponse ->
            writeTagged(BerTag.application(11)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.ModifyDNRequest ->
            writeTagged(BerTag.application(12)) {
                writeSequence {
                    writeUtf8String(op.dn)
                    writeUtf8String(op.newRdn)
                    writeBoolean(op.deleteOldRdn)
                    if (op.newSuperior != null) {
                        // [0] IMPLICIT LDAPDN — replaces the UTF8String tag, so primitive.
                        writeTagged(BerTag.contextSpecific(0, constructed = false)) {
                            writeRawBytes(op.newSuperior.encodeToByteArray())
                        }
                    }
                }
            }
        is LdapProtocolOp.ModifyDNResponse ->
            writeTagged(BerTag.application(13)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.CompareRequest ->
            writeTagged(BerTag.application(14)) {
                writeSequence {
                    writeUtf8String(op.dn)
                    // [3] IMPLICIT AttributeValueAssertion — the [3] tag replaces the SEQUENCE tag,
                    // so body contains the assertion fields directly (type + value, no inner SEQUENCE).
                    writeTagged(BerTag.contextSpecific(3, constructed = true)) {
                        writeOctetString(op.attribute.encodeToByteArray())
                        writeOctetString(op.value)
                    }
                }
            }
        is LdapProtocolOp.CompareResponse ->
            writeTagged(BerTag.application(15)) {
                writeSequence {
                    writeLdapResult(op.result)
                }
            }
        is LdapProtocolOp.AbandonRequest ->
            writeTagged(BerTag.application(16, constructed = false)) {
                writeInteger(op.targetMessageId.toLong())
            }
    }
}

internal fun BerReader.readProtocolOp(): LdapProtocolOp {
    val tag = readTag()
    val length = readLength()
    val bodyBytes = source.readByteArray(length)
    val r = BerReader(kotlinx.io.Buffer().apply { write(bodyBytes) })
    return when (tag.number) {
        0 ->
            r.seq {
                LdapProtocolOp.BindRequest(
                    version = readInteger().toInt(),
                    name = readUtf8String(),
                    authentication = readAuthentication(),
                )
            }
        1 ->
            r.seq {
                LdapProtocolOp.BindResponse(
                    result = readLdapResult(),
                    serverSaslCreds =
                        if (source.exhausted()) {
                            null
                        } else {
                            readTypedBytes(
                                BerTag.contextSpecific(7, constructed = false),
                            )
                        },
                )
            }
        2 -> LdapProtocolOp.UnbindRequest
        3 ->
            r.seq {
                LdapProtocolOp.SearchRequest(
                    baseDn = readUtf8String(),
                    scope = SearchScope.fromCode(readInteger().toInt()),
                    derefAliases = DerefAliases.fromCode(readInteger().toInt()),
                    sizeLimit = readInteger().toInt(),
                    timeLimit = readInteger().toInt(),
                    typesOnly = readBoolean(),
                    filter = readFilter(),
                    attributes =
                        seq {
                            val list = mutableListOf<String>()
                            while (!source.exhausted()) list.add(readUtf8String())
                            list
                        },
                )
            }
        4 ->
            r.seq {
                LdapProtocolOp.SearchResultEntry(
                    objectName = readUtf8String(),
                    attributes =
                        seq {
                            val list = mutableListOf<PartialAttribute>()
                            while (!source.exhausted()) list.add(readPartialAttribute())
                            list
                        },
                )
            }
        5 ->
            r.seq {
                LdapProtocolOp.SearchResultDone(readLdapResult())
            }
        19 -> {
            // [APPLICATION 19] IMPLICIT SEQUENCE OF LDAPURL — no inner SEQUENCE wrapper.
            val uris = mutableListOf<String>()
            while (!r.source.exhausted()) uris.add(r.readUtf8String())
            LdapProtocolOp.SearchResultReference(uris)
        }
        6 ->
            r.seq {
                LdapProtocolOp.ModifyRequest(
                    dn = readUtf8String(),
                    changes =
                        seq {
                            val list = mutableListOf<Modification>()
                            while (!source.exhausted()) {
                                val m =
                                    seq {
                                        Modification(
                                            operation = ChangeOperation.fromCode(readInteger().toInt()),
                                            attribute = readPartialAttribute(),
                                        )
                                    }
                                list.add(m)
                            }
                            list
                        },
                )
            }
        7 ->
            r.seq {
                LdapProtocolOp.ModifyResponse(readLdapResult())
            }
        8 ->
            r.seq {
                LdapProtocolOp.AddRequest(
                    dn = readUtf8String(),
                    attributes =
                        seq {
                            val list = mutableListOf<PartialAttribute>()
                            while (!source.exhausted()) list.add(readPartialAttribute())
                            list
                        },
                )
            }
        9 ->
            r.seq {
                LdapProtocolOp.AddResponse(readLdapResult())
            }
        10 ->
            r.seq {
                LdapProtocolOp.DelRequest(dn = readUtf8String())
            }
        11 ->
            r.seq {
                LdapProtocolOp.DelResponse(readLdapResult())
            }
        12 ->
            r.seq {
                LdapProtocolOp.ModifyDNRequest(
                    dn = readUtf8String(),
                    newRdn = readUtf8String(),
                    deleteOldRdn = readBoolean(),
                    // [0] IMPLICIT LDAPDN — primitive, body is raw UTF-8 bytes (no length prefix inside).
                    newSuperior =
                        if (source.exhausted()) {
                            null
                        } else {
                            seq(BerTag.contextSpecific(0, constructed = false)) {
                                source.readByteArray().decodeToString()
                            }
                        },
                )
            }
        13 ->
            r.seq {
                LdapProtocolOp.ModifyDNResponse(readLdapResult())
            }
        14 ->
            r.seq {
                val dn = readUtf8String()
                val ava =
                    seq(BerTag.contextSpecific(3, constructed = true)) {
                        val attrBytes = readTypedBytes(BerTag.OCTET_STRING)
                        val valBytes = readTypedBytes(BerTag.OCTET_STRING)
                        attrBytes.decodeToString() to valBytes
                    }
                LdapProtocolOp.CompareRequest(dn, ava.first, ava.second)
            }
        15 ->
            r.seq {
                LdapProtocolOp.CompareResponse(readLdapResult())
            }
        16 -> {
            // AbandonRequest: [APPLICATION 16] MessageID (primitive, body is INTEGER)
            LdapProtocolOp.AbandonRequest(r.readInteger().toInt())
        }
        else -> error("Unknown LDAP protocol op tag: $tag")
    }
}
