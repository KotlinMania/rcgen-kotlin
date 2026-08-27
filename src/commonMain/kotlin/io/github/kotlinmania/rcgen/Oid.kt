// port-lint: source oid.rs
package io.github.kotlinmania.rcgen

/**
 * Object Identifier constants and helper methods.
 */
public object Oid {
    public val PKCS_9_AT_EXTENSION_REQUEST: LongArray = longArrayOf(1, 2, 840, 113549, 1, 9, 14)

    public val COUNTRY_NAME: LongArray = longArrayOf(2, 5, 4, 6)
    public val LOCALITY_NAME: LongArray = longArrayOf(2, 5, 4, 7)
    public val STATE_OR_PROVINCE_NAME: LongArray = longArrayOf(2, 5, 4, 8)
    public val ORG_NAME: LongArray = longArrayOf(2, 5, 4, 10)
    public val ORG_UNIT_NAME: LongArray = longArrayOf(2, 5, 4, 11)
    public val COMMON_NAME: LongArray = longArrayOf(2, 5, 4, 3)

    public val EC_PUBLIC_KEY: LongArray = longArrayOf(1, 2, 840, 10045, 2, 1)
    public val EC_SECP_256_R1: LongArray = longArrayOf(1, 2, 840, 10045, 3, 1, 7)
    public val EC_SECP_384_R1: LongArray = longArrayOf(1, 3, 132, 0, 34)
    public val EC_SECP_521_R1: LongArray = longArrayOf(1, 3, 132, 0, 35)

    public val ML_DSA_44: LongArray = longArrayOf(2, 16, 840, 1, 101, 3, 4, 3, 17)
    public val ML_DSA_65: LongArray = longArrayOf(2, 16, 840, 1, 101, 3, 4, 3, 18)
    public val ML_DSA_87: LongArray = longArrayOf(2, 16, 840, 1, 101, 3, 4, 3, 19)

    public val RSA_ENCRYPTION: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 1)
    public val RSASSA_PSS: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 10)

    public val KEY_USAGE: LongArray = longArrayOf(2, 5, 29, 15)
    public val SUBJECT_ALT_NAME: LongArray = longArrayOf(2, 5, 29, 17)
    public val BASIC_CONSTRAINTS: LongArray = longArrayOf(2, 5, 29, 19)
    public val SUBJECT_KEY_IDENTIFIER: LongArray = longArrayOf(2, 5, 29, 14)
    public val AUTHORITY_KEY_IDENTIFIER: LongArray = longArrayOf(2, 5, 29, 35)
    public val EXT_KEY_USAGE: LongArray = longArrayOf(2, 5, 29, 37)
    public val NAME_CONSTRAINTS: LongArray = longArrayOf(2, 5, 29, 30)
    public val CRL_DISTRIBUTION_POINTS: LongArray = longArrayOf(2, 5, 29, 31)

    public val PE_ACME: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 1, 31)

    public val CRL_NUMBER: LongArray = longArrayOf(2, 5, 29, 20)
    public val CRL_REASONS: LongArray = longArrayOf(2, 5, 29, 21)
    public val CRL_INVALIDITY_DATE: LongArray = longArrayOf(2, 5, 29, 24)
    public val CRL_ISSUING_DISTRIBUTION_POINT: LongArray = longArrayOf(2, 5, 29, 28)

    // Extended Key Usage OIDs
    public val EKU_ANY: LongArray = longArrayOf(2, 5, 29, 37, 0)
    public val EKU_SERVER_AUTH: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 1)
    public val EKU_CLIENT_AUTH: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 2)
    public val EKU_CODE_SIGNING: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 3)
    public val EKU_EMAIL_PROTECTION: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 4)
    public val EKU_TIME_STAMPING: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 8)
    public val EKU_OCSP_SIGNING: LongArray = longArrayOf(1, 3, 6, 1, 5, 5, 7, 3, 9)

    // Signature Algorithm OIDs
    public val SHA256_WITH_RSA_ENCRYPTION: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 11)
    public val SHA384_WITH_RSA_ENCRYPTION: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 12)
    public val SHA512_WITH_RSA_ENCRYPTION: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 13)
    public val ECDSA_WITH_SHA256: LongArray = longArrayOf(1, 2, 840, 10045, 4, 3, 2)
    public val ECDSA_WITH_SHA384: LongArray = longArrayOf(1, 2, 840, 10045, 4, 3, 3)
    public val ECDSA_WITH_SHA512: LongArray = longArrayOf(1, 2, 840, 10045, 4, 3, 4)
    public val ED25519: LongArray = longArrayOf(1, 3, 101, 112)
    public val ID_SHA256: LongArray = longArrayOf(2, 16, 840, 1, 101, 3, 4, 2, 1)
    public val ID_MGF1: LongArray = longArrayOf(1, 2, 840, 113549, 1, 1, 8)

    public fun toString(oid: LongArray): String = oid.joinToString(".")

    public fun fromString(s: String): LongArray = s.split('.').map { it.toLong() }.toLongArray()
}
