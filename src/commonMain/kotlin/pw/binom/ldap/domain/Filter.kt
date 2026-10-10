package pw.binom.ldap.domain

import pw.binom.ldap.protocol.LdapFilter

/**
 * DSL for building LDAP filter trees.
 *
 * ```
 * Filter { and { eq("uid", "alice"); present("mail") } }
 * Filter { or { eq("cn", "Alice"); eq("cn", "Alicia") } }
 * Filter { not { eq("uid", "bob") } }
 * ```
 *
 * The terminal leaves (eq, present, substring, ge, le, approx) produce a
 * concrete [LdapFilter]. The combinators (and, or, not) consume a block
 * that yields one or more [LdapFilter]s — the last expression of the
 * block is the result.
 */
public object Filter {
    public operator fun invoke(block: FilterBuilder.() -> LdapFilter): LdapFilter =
        block(FilterBuilder())
}

/** Builder for [LdapFilter]. Use [Filter.invoke] with a receiver lambda. */
public open class FilterBuilder {
    public open fun eq(attribute: String, value: String): LdapFilter =
        LdapFilter.EqualityMatch(attribute, value.encodeToByteArray())

    public open fun eq(attribute: String, value: ByteArray): LdapFilter =
        LdapFilter.EqualityMatch(attribute, value)

    public open fun present(attribute: String): LdapFilter =
        LdapFilter.Present(attribute)

    public open fun substring(
        attribute: String,
        initial: String? = null,
        any: List<String> = emptyList(),
        final: String? = null,
    ): LdapFilter = LdapFilter.Substring(
        attribute = attribute,
        initial = initial,
        any = any,
        final = final,
    )

    public open fun ge(attribute: String, value: String): LdapFilter =
        LdapFilter.GreaterOrEqual(attribute, value.encodeToByteArray())

    public open fun le(attribute: String, value: String): LdapFilter =
        LdapFilter.LessOrEqual(attribute, value.encodeToByteArray())

    public open fun approx(attribute: String, value: String): LdapFilter =
        LdapFilter.ApproxMatch(attribute, value.encodeToByteArray())

    /**
     * `(&(f1)(f2)...)` — collects all filter-producing expressions in
     * the block, in order. The block's last expression is ignored (only
     * the side-effects matter).
     */
    public fun and(block: FilterBuilder.() -> Unit): LdapFilter {
        val collected = FilterCollector().apply { block() }
        return LdapFilter.And(collected.filters)
    }

    public fun and(filters: List<LdapFilter>): LdapFilter = LdapFilter.And(filters)

    public fun and(vararg filters: LdapFilter): LdapFilter = LdapFilter.And(filters.toList())

    public fun or(block: FilterBuilder.() -> Unit): LdapFilter {
        val collected = FilterCollector().apply { block() }
        return LdapFilter.Or(collected.filters)
    }

    public fun or(filters: List<LdapFilter>): LdapFilter = LdapFilter.Or(filters)

    public fun or(vararg filters: LdapFilter): LdapFilter = LdapFilter.Or(filters.toList())

    public fun not(block: FilterBuilder.() -> LdapFilter): LdapFilter =
        LdapFilter.Not(block(FilterBuilder()))
}

private class FilterCollector : FilterBuilder() {
    val filters: MutableList<LdapFilter> = mutableListOf()

    override fun eq(attribute: String, value: String): LdapFilter {
        val f = super.eq(attribute, value)
        filters += f
        return f
    }

    override fun eq(attribute: String, value: ByteArray): LdapFilter {
        val f = super.eq(attribute, value)
        filters += f
        return f
    }

    override fun present(attribute: String): LdapFilter {
        val f = super.present(attribute)
        filters += f
        return f
    }

    override fun substring(
        attribute: String,
        initial: String?,
        any: List<String>,
        final: String?,
    ): LdapFilter {
        val f = super.substring(attribute, initial, any, final)
        filters += f
        return f
    }

    override fun ge(attribute: String, value: String): LdapFilter {
        val f = super.ge(attribute, value)
        filters += f
        return f
    }

    override fun le(attribute: String, value: String): LdapFilter {
        val f = super.le(attribute, value)
        filters += f
        return f
    }

    override fun approx(attribute: String, value: String): LdapFilter {
        val f = super.approx(attribute, value)
        filters += f
        return f
    }
}
