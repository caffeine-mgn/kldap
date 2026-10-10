package pw.binom.ldap

import kotlin.test.Test
import kotlin.test.assertEquals

class LibraryVersionTest {
    @Test
    fun `version is non empty`() {
        assertEquals("0.1.0-SNAPSHOT", LIBRARY_VERSION)
    }
}
