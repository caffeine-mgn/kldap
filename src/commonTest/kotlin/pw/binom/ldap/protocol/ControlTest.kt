package pw.binom.ldap.protocol

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ControlTest {
    private fun roundTrip(control: Control): Control {
        val msg = LdapMessage(1, LdapProtocolOp.UnbindRequest, listOf(control))
        val bytes = msg.encode()
        val decoded = LdapMessage.decode(bytes)
        return decoded.controls.single()
    }

    @Test
    fun minimalControlRoundTrip() {
        val original = Control("1.2.3.4.5")
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertFalse(decoded.critical)
        assertEquals(null, decoded.value)
    }

    @Test
    fun criticalControlRoundTrip() {
        val original = Control("1.2.3.4.5", critical = true)
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertTrue(decoded.critical)
    }

    @Test
    fun controlWithValueRoundTrip() {
        val original = Control("1.2.3.4.5", critical = true, value = byteArrayOf(1, 2, 3))
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
        assertContentEquals(byteArrayOf(1, 2, 3), decoded.value)
    }

    @Test
    fun criticalityPresentButValueAbsent() {
        // Real-world encoding where server sends criticality TRUE but no controlValue
        val original = Control("1.2.3.4.5", critical = true, value = null)
        val decoded = roundTrip(original)
        assertEquals(original, decoded)
    }
}
