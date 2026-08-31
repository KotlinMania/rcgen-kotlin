// port-lint: source rcgen/src/crl.rs
package io.github.kotlinmania.rcgen

import kotlin.time.Instant

/**
 * A certificate revocation list (CRL).
 */
public class CertificateRevocationList(
    private val derBytes: ByteArray,
) {
    public fun der(): ByteArray = derBytes.copyOf()

    public fun pem(): String = Pem.encode("X509 CRL", derBytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificateRevocationList) return false
        return derBytes.contentEquals(other.derBytes)
    }

    override fun hashCode(): Int = derBytes.contentHashCode()
}

/**
 * A CRL distribution point.
 */
public data class CrlDistributionPoint(
    public val uris: List<String>,
) {
    public fun writeDer(writer: DerWriter) {
        writer.writeSequence {
            writeDistributionPointNameUris(next(), uris)
        }
    }
}

internal fun writeDistributionPointNameUris(writer: DerWriter, uris: List<String>) {
    writer.writeTaggedImplicit(0) { w ->
        w.writeSequence {
            next().writeTaggedImplicit(0) { gnWriter ->
                gnWriter.writeSequence {
                    for (uri in uris) {
                        next().writeTaggedImplicit(6) { uWriter ->
                            uWriter.writeIa5String(uri)
                        }
                    }
                }
            }
        }
    }
}

/**
 * Revocation Reason.
 */
public enum class RevocationReason(
    public val code: Long,
) {
    Unspecified(0),
    KeyCompromise(1),
    CaCompromise(2),
    AffiliationChanged(3),
    Superseded(4),
    CessationOfOperation(5),
    CertificateHold(6),
    RemoveFromCrl(8),
    PrivilegeWithdrawn(9),
    AaCompromise(10),
}

/**
 * CRL Scope.
 */
public enum class CrlScope {
    UserCertsOnly,
    CaCertsOnly,
}

/**
 * CRL Issuing Distribution Point.
 */
public data class CrlIssuingDistributionPoint(
    public val distributionPoint: CrlDistributionPoint,
    public val scope: CrlScope? = null,
) {
    public fun writeDer(writer: DerWriter) {
        writer.writeSequence {
            writeDistributionPointNameUris(next(), distributionPoint.uris)
            scope?.let { s ->
                val tag =
                    when (s) {
                        CrlScope.UserCertsOnly -> 1
                        CrlScope.CaCertsOnly -> 2
                    }
                next().writeTaggedImplicit(tag) { w ->
                    w.writeBoolean(true)
                }
            }
        }
    }
}

/**
 * Revoked Certificate Parameters.
 */
public data class RevokedCertParams(
    public val serialNumber: SerialNumber,
    public val revocationTime: Instant,
    public val reasonCode: RevocationReason? = null,
    public val invalidityDate: Instant? = null,
) {
    public fun writeDer(writer: DerWriter) {
        writer.writeSequence {
            next().writeBigIntBytes(serialNumber.inner, positive = true)
            writeDtUtcOrGeneralized(next(), revocationTime)

            val reason = reasonCode
            val invalidity = invalidityDate

            val hasReason = reason != null && reason != RevocationReason.Unspecified
            val hasInvalidity = invalidity != null

            if (hasReason || hasInvalidity) {
                next().writeSequence {
                    if (reason != null && reason != RevocationReason.Unspecified) {
                        writeX509Extension(next(), Oid.CRL_REASONS, false) { w ->
                            w.writeEnum(reason.code)
                        }
                    }
                    if (invalidity != null) {
                        writeX509Extension(next(), Oid.CRL_INVALIDITY_DATE, false) { w ->
                            writeDtUtcOrGeneralized(w, invalidity)
                        }
                    }
                }
            }
        }
    }
}

/**
 * Parameters used for CRL generation.
 */
public class CertificateRevocationListParams(
    public var thisUpdate: Instant,
    public var nextUpdate: Instant,
    public var crlNumber: SerialNumber,
    public var issuingDistributionPoint: CrlIssuingDistributionPoint? = null,
    public var revokedCerts: List<RevokedCertParams> = emptyList(),
    public var keyIdentifierMethod: KeyIdMethod = KeyIdMethod.Sha256,
) {
    public fun signedBy(issuer: Issuer): CertificateRevocationList {
        if (nextUpdate <= thisUpdate) {
            throw RcgenException.InvalidCrlNextUpdate()
        }
        if (issuer.keyUsages.isNotEmpty() && !issuer.keyUsages.contains(KeyUsagePurpose.CrlSign)) {
            throw RcgenException.IssuerNotCrlSigner()
        }
        return CertificateRevocationList(serializeDer(issuer))
    }

    public fun serializeDer(issuer: Issuer): ByteArray =
        signDer(issuer.signingKey) {
            // Version 2 (represented as integer 1)
            next().writeInteger(1)

            // Algorithm identifier
            issuer.signingKey.algorithm().writeAlgIdent(next())

            // Issuer DN
            writeDistinguishedName(next(), issuer.distinguishedName)

            // thisUpdate
            writeDtUtcOrGeneralized(next(), thisUpdate)

            // nextUpdate
            writeDtUtcOrGeneralized(next(), nextUpdate)

            // Revoked certificates
            if (revokedCerts.isNotEmpty()) {
                next().writeSequence {
                    for (rc in revokedCerts) {
                        rc.writeDer(next())
                    }
                }
            }

            // CRL Extensions
            next().writeTagged(0) { w ->
                w.writeSequence {
                    // Authority Key Identifier
                    val aki = keyIdentifierMethod.derive(issuer.signingKey.subjectPublicKeyInfo())
                    writeX509AuthorityKeyIdentifier(next(), aki)

                    // CRL Number
                    writeX509Extension(next(), Oid.CRL_NUMBER, false) { crlNumW ->
                        crlNumW.writeBigIntBytes(crlNumber.inner, positive = true)
                    }

                    // Issuing distribution point
                    issuingDistributionPoint?.let { idp ->
                        writeX509Extension(next(), Oid.CRL_ISSUING_DISTRIBUTION_POINT, true) { idpW ->
                            idp.writeDer(idpW)
                        }
                    }
                }
            }
        }
}
