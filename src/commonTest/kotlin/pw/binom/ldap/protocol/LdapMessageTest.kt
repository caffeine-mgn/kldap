package pw.binom.ldap.protocol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class LdapMessageTest {
    @Test
    fun simpleBindAnonymousRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.BindRequest(
                        version = 3,
                        name = "",
                        authentication = Authentication.Simple(""),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        assertEquals(1, decoded.messageId)
        val op = assertIs<LdapProtocolOp.BindRequest>(decoded.op)
        assertEquals(3, op.version)
        assertEquals("", op.name)
        val auth = assertIs<Authentication.Simple>(op.authentication)
        assertTrue(auth.isAnonymous)
    }

    @Test
    fun simpleBindWithPasswordRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 42,
                op =
                    LdapProtocolOp.BindRequest(
                        version = 3,
                        name = "uid=alice,ou=People,dc=example,dc=com",
                        authentication = Authentication.Simple("hunter2"),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        assertEquals(42, decoded.messageId)
        val op = assertIs<LdapProtocolOp.BindRequest>(decoded.op)
        assertEquals(3, op.version)
        assertEquals("uid=alice,ou=People,dc=example,dc=com", op.name)
        val auth = assertIs<Authentication.Simple>(op.authentication)
        assertEquals("hunter2", auth.password)
    }

    @Test
    fun unbindRoundTrip() {
        val msg = LdapMessage(7, LdapProtocolOp.UnbindRequest)
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        assertEquals(7, decoded.messageId)
        assertEquals(LdapProtocolOp.UnbindRequest, decoded.op)
    }

    @Test
    fun searchRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 100,
                op =
                    LdapProtocolOp.SearchRequest(
                        baseDn = "dc=example,dc=com",
                        scope = SearchScope.WHOLE_SUBTREE,
                        derefAliases = DerefAliases.NEVER_DEREF_ALIASES,
                        sizeLimit = 1000,
                        timeLimit = 60,
                        typesOnly = false,
                        filter =
                            LdapFilter.and(
                                LdapFilter.eq("objectClass", "person"),
                                LdapFilter.present("mail"),
                            ),
                        attributes = listOf("cn", "mail"),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        assertEquals(100, decoded.messageId)
        val op = assertIs<LdapProtocolOp.SearchRequest>(decoded.op)
        assertEquals("dc=example,dc=com", op.baseDn)
        assertEquals(SearchScope.WHOLE_SUBTREE, op.scope)
        assertEquals(DerefAliases.NEVER_DEREF_ALIASES, op.derefAliases)
        assertEquals(1000, op.sizeLimit)
        assertEquals(60, op.timeLimit)
        assertEquals(false, op.typesOnly)
        assertEquals(
            LdapFilter.and(
                LdapFilter.eq("objectClass", "person"),
                LdapFilter.present("mail"),
            ),
            op.filter,
        )
        assertEquals(listOf("cn", "mail"), op.attributes)
    }

    @Test
    fun searchResultEntryRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 100,
                op =
                    LdapProtocolOp.SearchResultEntry(
                        objectName = "uid=alice,ou=People,dc=example,dc=com",
                        attributes =
                            listOf(
                                PartialAttribute(
                                    type = "cn",
                                    values = listOf("Alice Smith".encodeToByteArray()),
                                ),
                                PartialAttribute(
                                    type = "mail",
                                    values =
                                        listOf(
                                            "alice@example.com".encodeToByteArray(),
                                            "alice@personal.example.com".encodeToByteArray(),
                                        ),
                                ),
                            ),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.SearchResultEntry>(decoded.op)
        assertEquals("uid=alice,ou=People,dc=example,dc=com", op.objectName)
        assertEquals(2, op.attributes.size)
        assertEquals("cn", op.attributes[0].type)
        assertEquals(1, op.attributes[0].values.size)
        assertEquals("Alice Smith", op.attributes[0].values[0].decodeToString())
        assertEquals("mail", op.attributes[1].type)
        assertEquals(2, op.attributes[1].values.size)
        assertEquals("alice@example.com", op.attributes[1].values[0].decodeToString())
        assertEquals("alice@personal.example.com", op.attributes[1].values[1].decodeToString())
    }

    @Test
    fun searchResultDoneRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 100,
                op =
                    LdapProtocolOp.SearchResultDone(
                        LdapResult(
                            resultCode = ResultCode.SIZE_LIMIT_EXCEEDED,
                            matchedDn = "",
                            diagnosticMessage = "size limit exceeded",
                        ),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.SearchResultDone>(decoded.op)
        assertEquals(ResultCode.SIZE_LIMIT_EXCEEDED, op.result.resultCode)
        assertEquals("size limit exceeded", op.result.diagnosticMessage)
    }

    @Test
    fun messageWithControls() {
        val msg =
            LdapMessage(
                messageId = 5,
                op =
                    LdapProtocolOp.SearchRequest(
                        baseDn = "",
                        scope = SearchScope.BASE_OBJECT,
                        derefAliases = DerefAliases.NEVER_DEREF_ALIASES,
                        sizeLimit = 0,
                        timeLimit = 0,
                        typesOnly = false,
                        filter = LdapFilter.eq("objectClass", "*"),
                        attributes = emptyList(),
                    ),
                controls =
                    listOf(
                        Control("1.2.3.4.1"),
                        Control("1.2.3.4.2", critical = true, value = byteArrayOf(0x42)),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        assertEquals(5, decoded.messageId)
        assertEquals(2, decoded.controls.size)
        assertEquals("1.2.3.4.1", decoded.controls[0].type)
        assertEquals(false, decoded.controls[0].critical)
        assertEquals("1.2.3.4.2", decoded.controls[1].type)
        assertEquals(true, decoded.controls[1].critical)
    }

    @Test
    fun abandonRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 99,
                op = LdapProtocolOp.AbandonRequest(targetMessageId = 42),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.AbandonRequest>(decoded.op)
        assertEquals(42, op.targetMessageId)
    }

    @Test
    fun bindResponseWithServerSaslCreds() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.BindResponse(
                        result =
                            LdapResult(
                                resultCode = ResultCode.SASL_BIND_IN_PROGRESS,
                                matchedDn = "",
                                diagnosticMessage = "",
                            ),
                        serverSaslCreds = byteArrayOf(0x01, 0x02, 0x03),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.BindResponse>(decoded.op)
        assertEquals(ResultCode.SASL_BIND_IN_PROGRESS, op.result.resultCode)
        assertEquals(3, op.serverSaslCreds?.size)
    }

    @Test
    fun addRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.AddRequest(
                        dn = "uid=bob,ou=People,dc=example,dc=com",
                        attributes =
                            listOf(
                                PartialAttribute("cn", listOf("Bob".encodeToByteArray())),
                                PartialAttribute("objectClass", listOf("inetOrgPerson".encodeToByteArray())),
                            ),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.AddRequest>(decoded.op)
        assertEquals("uid=bob,ou=People,dc=example,dc=com", op.dn)
        assertEquals(2, op.attributes.size)
    }

    @Test
    fun modifyRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.ModifyRequest(
                        dn = "uid=alice,ou=People,dc=example,dc=com",
                        changes =
                            listOf(
                                Modification(
                                    operation = ChangeOperation.REPLACE,
                                    attribute = PartialAttribute("mail", listOf("new@example.com".encodeToByteArray())),
                                ),
                                Modification(
                                    operation = ChangeOperation.ADD,
                                    attribute =
                                        PartialAttribute(
                                            "description",
                                            listOf("New employee".encodeToByteArray()),
                                        ),
                                ),
                            ),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.ModifyRequest>(decoded.op)
        assertEquals(2, op.changes.size)
        assertEquals(ChangeOperation.REPLACE, op.changes[0].operation)
        assertEquals("mail", op.changes[0].attribute.type)
    }

    @Test
    fun modifyDnRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.ModifyDNRequest(
                        dn = "uid=alice,ou=People,dc=example,dc=com",
                        newRdn = "uid=alic",
                        deleteOldRdn = true,
                        newSuperior = "ou=Admins,dc=example,dc=com",
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.ModifyDNRequest>(decoded.op)
        assertEquals("uid=alic", op.newRdn)
        assertEquals(true, op.deleteOldRdn)
        assertEquals("ou=Admins,dc=example,dc=com", op.newSuperior)
    }

    @Test
    fun compareRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.CompareRequest(
                        dn = "uid=alice,ou=People,dc=example,dc=com",
                        attribute = "userPassword",
                        value =
                            byteArrayOf(
                                's'.code.toByte(),
                                'e'.code.toByte(),
                                'c'.code.toByte(),
                                'r'.code.toByte(),
                                'e'.code.toByte(),
                                't'.code.toByte(),
                            ),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.CompareRequest>(decoded.op)
        assertEquals("userPassword", op.attribute)
        assertEquals("secret", op.value.decodeToString())
    }

    @Test
    fun delRequestRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op = LdapProtocolOp.DelRequest("uid=bob,ou=People,dc=example,dc=com"),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.DelRequest>(decoded.op)
        assertEquals("uid=bob,ou=People,dc=example,dc=com", op.dn)
    }

    @Test
    fun searchResultReferenceRoundTrip() {
        val msg =
            LdapMessage(
                messageId = 1,
                op =
                    LdapProtocolOp.SearchResultReference(
                        uris = listOf("ldap://other.example.com/dc=example,dc=com"),
                    ),
            )
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        val op = assertIs<LdapProtocolOp.SearchResultReference>(decoded.op)
        assertEquals(listOf("ldap://other.example.com/dc=example,dc=com"), op.uris)
    }
}
