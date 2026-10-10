package pw.binom.ldap.exception

import pw.binom.ldap.protocol.LdapResult
import pw.binom.ldap.protocol.ResultCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class LdapExceptionTest {

    @Test
    fun fromSuccessReturnsNull() {
        val r = LdapResult(ResultCode.SUCCESS, "", "")
        assertNull(LdapException.from(r))
    }

    @Test
    fun fromInvalidCredentials() {
        val r = LdapResult(ResultCode.INVALID_CREDENTIALS, "", "wrong password")
        val ex = LdapException.from(r)
        assertNotNull(ex)
        assertTrue(ex is InvalidCredentialsException)
        assertEquals(ResultCode.INVALID_CREDENTIALS, ex.resultCode)
    }

    @Test
    fun fromNoSuchObject() {
        val r = LdapResult(ResultCode.NO_SUCH_OBJECT, "ou=users,dc=x", "")
        val ex = LdapException.from(r)
        assertNotNull(ex)
        assertTrue(ex is NoSuchObjectException)
        assertEquals("ou=users,dc=x", ex.matchedDn)
    }

    @Test
    fun fromReferral() {
        val r = LdapResult(ResultCode.REFERRAL, "", "ldap://other:389")
        val ex = LdapException.from(r)
        assertNotNull(ex)
        assertTrue(ex is ReferralException)
    }

    @Test
    fun fromUnknownCodeYieldsGeneric() {
        // Pick a code that has no dedicated mapping.
        val r = LdapResult(ResultCode.fromCode(7) ?: ResultCode.OTHER, "", "")
        val ex = LdapException.from(r)
        assertNotNull(ex)
        assertTrue(ex is GenericLdapException)
    }

    @Test
    fun messageContainsCode() {
        val ex = InvalidCredentialsException(
            LdapResult(ResultCode.INVALID_CREDENTIALS, "", "wrong password"),
        )
        val msg = ex.message ?: ""
        assertTrue(msg.contains("49"), "message should contain the code: $msg")
        assertTrue(msg.contains("wrong password"), "message should contain diagnostic: $msg")
    }

    @Test
    fun matchedDnInMessage() {
        val ex = NoSuchObjectException(
            LdapResult(ResultCode.NO_SUCH_OBJECT, "ou=x,dc=y", "missing"),
        )
        val msg = ex.message ?: ""
        assertTrue(msg.contains("ou=x,dc=y"), "message should contain matched DN: $msg")
    }
}
