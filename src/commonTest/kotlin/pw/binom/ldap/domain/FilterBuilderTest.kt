package pw.binom.ldap.domain

import pw.binom.ldap.protocol.LdapFilter
import kotlin.test.Test
import kotlin.test.assertEquals

class FilterBuilderTest {

    @Test
    fun eq() {
        val f = Filter { eq("uid", "alice") }
        assertEquals(LdapFilter.EqualityMatch("uid", "alice".encodeToByteArray()), f)
    }

    @Test
    fun present() {
        val f = Filter { present("objectClass") }
        assertEquals(LdapFilter.Present("objectClass"), f)
    }

    @Test
    fun andCombines() {
        val f = Filter {
            and {
                eq("uid", "alice")
                present("mail")
            }
        }
        assertEquals(
            LdapFilter.And(
                listOf(
                    LdapFilter.EqualityMatch("uid", "alice".encodeToByteArray()),
                    LdapFilter.Present("mail"),
                ),
            ),
            f,
        )
    }

    @Test
    fun orCombines() {
        val f = Filter {
            or {
                eq("cn", "Alice")
                eq("cn", "Alicia")
            }
        }
        assertEquals(
            LdapFilter.Or(
                listOf(
                    LdapFilter.EqualityMatch("cn", "Alice".encodeToByteArray()),
                    LdapFilter.EqualityMatch("cn", "Alicia".encodeToByteArray()),
                ),
            ),
            f,
        )
    }

    @Test
    fun notNegates() {
        val f = Filter { not { eq("uid", "bob") } }
        assertEquals(
            LdapFilter.Not(LdapFilter.EqualityMatch("uid", "bob".encodeToByteArray())),
            f,
        )
    }

    @Test
    fun geLeApprox() {
        val ge = Filter { ge("age", "18") }
        val le = Filter { le("age", "65") }
        val approx = Filter { approx("cn", "Alice") }
        assertEquals(LdapFilter.GreaterOrEqual("age", "18".encodeToByteArray()), ge)
        assertEquals(LdapFilter.LessOrEqual("age", "65".encodeToByteArray()), le)
        assertEquals(LdapFilter.ApproxMatch("cn", "Alice".encodeToByteArray()), approx)
    }

    @Test
    fun substring() {
        val f = Filter { substring("cn", initial = "A", any = listOf("li"), final = "ce") }
        assertEquals(
            LdapFilter.Substring("cn", initial = "A", any = listOf("li"), final = "ce"),
            f,
        )
    }

    @Test
    fun toStringRoundTrip() {
        val f = Filter {
            and {
                eq("objectClass", "person")
                present("mail")
            }
        }
        val s = f.toString()
        // RFC 4515 human-readable form.
        assertEquals("(&(objectClass=person)(mail=*))", s)
    }
}
