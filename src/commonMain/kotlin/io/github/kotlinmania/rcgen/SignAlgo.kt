// port-lint: source sign_algo.rs
package io.github.kotlinmania.rcgen

/**
 * Signature algorithm parameters.
 */
public sealed class SignatureAlgorithmParams {
    public object None : SignatureAlgorithmParams()

    public object Null : SignatureAlgorithmParams()

    public data class RsaPss(
        public val hashAlgorithm: LongArray,
        public val saltLength: Long,
    ) : SignatureAlgorithmParams() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is RsaPss) return false
            return hashAlgorithm.contentEquals(other.hashAlgorithm) && saltLength == other.saltLength
        }

        override fun hashCode(): Int = 31 * hashAlgorithm.contentHashCode() + saltLength.hashCode()
    }
}

/**
 * Signature algorithm type.
 */
public class SignatureAlgorithm(
    public val oidsSignAlg: List<LongArray>,
    public val oidComponents: LongArray,
    public val params: SignatureAlgorithmParams,
    public val name: String,
) {
    public fun writeAlgIdent(writer: DerWriter) {
        writer.writeSequence {
            next().writeOid(oidComponents)
            writeParamsToSeq(this)
        }
    }

    public fun writeOidsSignAlg(writer: DerWriter) {
        writer.writeSequence {
            for (oid in oidsSignAlg) {
                next().writeOid(oid)
            }
            writeParamsToSeq(this)
        }
    }

    private fun writeParamsToSeq(seq: DerWriterSeq) {
        when (params) {
            is SignatureAlgorithmParams.None -> Unit
            is SignatureAlgorithmParams.Null -> seq.next().writeNull()
            is SignatureAlgorithmParams.RsaPss -> {
                seq.next().writeSequence {
                    next().writeTagged(0) { w ->
                        w.writeSequence {
                            next().writeOid(params.hashAlgorithm)
                        }
                    }
                    next().writeTagged(1) { w ->
                        w.writeSequence {
                            next().writeOid(Oid.ID_MGF1)
                            next().writeSequence {
                                next().writeOid(params.hashAlgorithm)
                                next().writeNull()
                            }
                        }
                    }
                    next().writeTagged(2) { w ->
                        w.writeInteger(params.saltLength)
                    }
                }
            }
        }
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SignatureAlgorithm) return false
        if (oidsSignAlg.size != other.oidsSignAlg.size) return false
        for (i in oidsSignAlg.indices) {
            if (!oidsSignAlg[i].contentEquals(other.oidsSignAlg[i])) return false
        }
        return oidComponents.contentEquals(other.oidComponents)
    }

    override fun hashCode(): Int = oidComponents.contentHashCode()

    override fun toString(): String = name

    public companion object {
        public val PKCS_RSA_SHA256: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.RSA_ENCRYPTION),
                oidComponents = Oid.SHA256_WITH_RSA_ENCRYPTION,
                params = SignatureAlgorithmParams.Null,
                name = "PKCS_RSA_SHA256",
            )

        public val PKCS_RSA_SHA384: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.RSA_ENCRYPTION),
                oidComponents = Oid.SHA384_WITH_RSA_ENCRYPTION,
                params = SignatureAlgorithmParams.Null,
                name = "PKCS_RSA_SHA384",
            )

        public val PKCS_RSA_SHA512: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.RSA_ENCRYPTION),
                oidComponents = Oid.SHA512_WITH_RSA_ENCRYPTION,
                params = SignatureAlgorithmParams.Null,
                name = "PKCS_RSA_SHA512",
            )

        public val PKCS_RSA_PSS_SHA256: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.RSASSA_PSS),
                oidComponents = Oid.RSASSA_PSS,
                params =
                    SignatureAlgorithmParams.RsaPss(
                        hashAlgorithm = Oid.ID_SHA256,
                        saltLength = 20,
                    ),
                name = "PKCS_RSA_PSS_SHA256",
            )

        public val PKCS_ECDSA_P256_SHA256: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.EC_PUBLIC_KEY, Oid.EC_SECP_256_R1),
                oidComponents = Oid.ECDSA_WITH_SHA256,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ECDSA_P256_SHA256",
            )

        public val PKCS_ECDSA_P384_SHA384: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.EC_PUBLIC_KEY, Oid.EC_SECP_384_R1),
                oidComponents = Oid.ECDSA_WITH_SHA384,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ECDSA_P384_SHA384",
            )

        public val PKCS_ECDSA_P521_SHA256: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.EC_PUBLIC_KEY, Oid.EC_SECP_521_R1),
                oidComponents = Oid.ECDSA_WITH_SHA256,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ECDSA_P521_SHA256",
            )

        public val PKCS_ECDSA_P521_SHA384: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.EC_PUBLIC_KEY, Oid.EC_SECP_521_R1),
                oidComponents = Oid.ECDSA_WITH_SHA384,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ECDSA_P521_SHA384",
            )

        public val PKCS_ECDSA_P521_SHA512: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.EC_PUBLIC_KEY, Oid.EC_SECP_521_R1),
                oidComponents = Oid.ECDSA_WITH_SHA512,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ECDSA_P521_SHA512",
            )

        public val PKCS_ED25519: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.ED25519),
                oidComponents = Oid.ED25519,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ED25519",
            )

        public val PKCS_ML_DSA_44: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.ML_DSA_44),
                oidComponents = Oid.ML_DSA_44,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ML_DSA_44",
            )

        public val PKCS_ML_DSA_65: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.ML_DSA_65),
                oidComponents = Oid.ML_DSA_65,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ML_DSA_65",
            )

        public val PKCS_ML_DSA_87: SignatureAlgorithm =
            SignatureAlgorithm(
                oidsSignAlg = listOf(Oid.ML_DSA_87),
                oidComponents = Oid.ML_DSA_87,
                params = SignatureAlgorithmParams.None,
                name = "PKCS_ML_DSA_87",
            )

        private val ALL_ALGORITHMS =
            listOf(
                PKCS_RSA_SHA256,
                PKCS_RSA_SHA384,
                PKCS_RSA_SHA512,
                PKCS_ECDSA_P256_SHA256,
                PKCS_ECDSA_P384_SHA384,
                PKCS_ECDSA_P521_SHA256,
                PKCS_ECDSA_P521_SHA384,
                PKCS_ECDSA_P521_SHA512,
                PKCS_ED25519,
            )

        public fun iter(): List<SignatureAlgorithm> = ALL_ALGORITHMS

        public fun fromOidOrNull(oid: LongArray): SignatureAlgorithm? {
            for (algo in ALL_ALGORITHMS) {
                if (algo.oidComponents.contentEquals(oid)) {
                    return algo
                }
            }
            return null
        }

        public fun fromOid(oid: LongArray): SignatureAlgorithm =
            fromOidOrNull(oid) ?: throw RcgenException.UnsupportedSignatureAlgorithm()
    }
}
