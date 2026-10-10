package pw.binom.ldap.connection

/** Thrown when an LDAP stream ends before the expected number of bytes have been read. */
public class LdapEndOfStreamException(message: String) : RuntimeException(message)
