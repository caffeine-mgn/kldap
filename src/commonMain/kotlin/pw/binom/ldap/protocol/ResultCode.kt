package pw.binom.ldap.protocol

/**
 * LDAP result codes (RFC 4511 §4.1.9).
 *
 * Encoded as `ENUMERATED` in BER, which is identical to `INTEGER`.
 *
 * @property code Numeric value sent on the wire.
 */
public enum class ResultCode(
    public val code: Int,
) {
    SUCCESS(0),
    OPERATIONS_ERROR(1),
    PROTOCOL_ERROR(2),
    TIME_LIMIT_EXCEEDED(3),
    SIZE_LIMIT_EXCEEDED(4),
    COMPARE_FALSE(5),
    COMPARE_TRUE(6),
    AUTH_METHOD_NOT_SUPPORTED(7),
    STRONGER_AUTH_REQUIRED(8),
    REFERRAL(10),
    ADMIN_LIMIT_EXCEEDED(11),
    UNAVAILABLE_CRITICAL_EXTENSION(12),
    CONFIDENTIALITY_REQUIRED(13),
    SASL_BIND_IN_PROGRESS(14),
    NO_SUCH_ATTRIBUTE(16),
    UNDEFINED_ATTRIBUTE_TYPE(17),
    INAPPROPRIATE_MATCHING(18),
    CONSTRAINT_VIOLATION(19),
    ATTRIBUTE_OR_VALUE_EXISTS(20),
    INVALID_ATTRIBUTE_SYNTAX(21),
    NO_SUCH_OBJECT(32),
    ALIAS_PROBLEM(33),
    INVALID_DN_SYNTAX(34),
    ALIAS_DEREFERENCING_PROBLEM(36),
    INAPPROPRIATE_AUTHENTICATION(48),
    INVALID_CREDENTIALS(49),
    INSUFFICIENT_ACCESS_RIGHTS(50),
    BUSY(51),
    UNAVAILABLE(52),
    UNWILLING_TO_PERFORM(53),
    LOOP_DETECT(54),
    NAMING_VIOLATION(64),
    OBJECT_CLASS_VIOLATION(65),
    NOT_ALLOWED_ON_NON_LEAF(66),
    NOT_ALLOWED_ON_RDN(67),
    ENTRY_ALREADY_EXISTS(68),
    OBJECT_CLASS_MODS_PROHIBITED(69),
    AFFECTS_MULTIPLE_DSAS(71),
    OTHER(80),
    ;

    public companion object {
        /** Looks up a [ResultCode] by numeric value. Returns [OTHER] for unknown codes. */
        public fun fromCode(code: Int): ResultCode = entries.firstOrNull { it.code == code } ?: OTHER
    }
}
