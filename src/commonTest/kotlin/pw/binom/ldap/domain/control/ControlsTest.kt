package pw.binom.ldap.domain.control

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class ControlsTest {

    @Test
    fun pagedResultsRequestEncodesSequence() {
        val c = PagedResults.request(pageSize = 100)
        assertEquals(PagedResults.OID, c.type)
        assertEquals(false, c.critical)
        assertNotNull(c.value)
        // Request value starts with the SEQUENCE tag (0x30).
        assertEquals(0x30.toByte(), c.value!![0])
        // A request with no cookie parses back to an empty cookie.
        assertEquals(0, PagedResults.parseResponse(c.value)!!.size)
    }

    @Test
    fun pagedResultsCookieRoundTrip() {
        val cookie = byteArrayOf(1, 2, 3, 4, 5)
        val c = PagedResults.request(pageSize = 50, cookie = cookie)
        val out = PagedResults.parseResponse(c.value)
        assertContentEquals(cookie, out)
    }

    @Test
    fun pagedResultsEmptyResponseYieldsNull() {
        // Empty value means "no more pages".
        val bytes = byteArrayOf(0x30, 0x06, 0x02, 0x01, 0x0A, 0x04, 0x01, 0x00) // SEQUENCE { size=10, cookie="" }
        assertNotNull(PagedResults.parseResponse(bytes))
        // empty cookie:
        val cookies = PagedResults.parseResponse(bytes)
        assertContentEquals(byteArrayOf(0), cookies)
    }

    @Test
    fun pagedResultsNullOrEmptyYieldsNull() {
        assertNull(PagedResults.parseResponse(null))
        assertNull(PagedResults.parseResponse(ByteArray(0)))
    }

    @Test
    fun serverSideSortEncodes() {
        val c = ServerSideSort.sort("sn", reverse = false)
        assertEquals(ServerSideSort.OID, c.type)
        assertNotNull(c.value)
    }

    @Test
    fun serverSideSortReverseEncodes() {
        val c = ServerSideSort.sort("cn", reverse = true)
        assertEquals(ServerSideSort.OID, c.type)
        assertNotNull(c.value)
    }

    @Test
    fun manageDsaItIsCritical() {
        val c = ManageDSAIT.CONTROL
        assertEquals(ManageDSAIT.OID, c.type)
        assertEquals(true, c.critical)
        assertNull(c.value)
    }
}
