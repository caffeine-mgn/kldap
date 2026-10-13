package pw.binom.ldap.transport

import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.EmptyCoroutineContext

/**
 * Connection parameters for [ldapConnect]. Mutable for builder-style use; read once at connect time.
 */
public class LdapConnectionConfig {
    /** Server hostname or IP. */
    public var host: String = "localhost"

    /** Server port. Defaults are applied by the [ssl] field — see [ldapConnect]. */
    public var port: Int = 0

    /** When `true`, negotiate TLS over the TCP socket (LDAPS, port 636 by default). */
    public var ssl: Boolean = false

    /**
     * Server name for the TLS SNI extension and hostname verification.
     * Defaults to [host] when [ssl] is `true`.
     */
    public var serverName: String? = null

    /**
     * When `true`, TLS peer certificates are accepted without verification.
     * **Never use in production** — intended for tests against self-signed servers.
     */
    public var trustAll: Boolean = false

    /**
     * Coroutine context used for the underlying socket's selector and (for TLS) the
     * TLS coroutine. Defaults to [EmptyCoroutineContext] — the caller is expected to
     * dispatch on `Dispatchers.IO` themselves. The LdapClient wraps this into a
     * `CoroutineScope(context + Job)` so a single close() cancels everything.
     */
    public var coroutineContext: CoroutineContext = EmptyCoroutineContext
}
