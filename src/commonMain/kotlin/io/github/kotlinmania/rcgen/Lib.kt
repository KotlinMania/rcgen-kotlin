// port-lint: source lib.rs
package io.github.kotlinmania.rcgen

/**
 * Top-level rcgen metadata and constants.
 */
public object Rcgen {
    public const val VERSION: String = "0.14.7"
}

/**
 * An issued certificate, together with the subject key pair.
 */
public data class CertifiedKey<S : SigningKey>(
    public val cert: Certificate,
    public val signingKey: S,
)

/**
 * An issuer that can sign certificates.
 */
public class Issuer(
    public val distinguishedName: DistinguishedName,
    public val keyIdentifierMethod: KeyIdMethod,
    public val keyUsages: List<KeyUsagePurpose>,
    public val signingKey: SigningKey,
) {
    public companion object {
        public fun new(params: CertificateParams, signingKey: SigningKey): Issuer =
            Issuer(
                distinguishedName = params.distinguishedName,
                keyIdentifierMethod = params.keyIdentifierMethod,
                keyUsages = params.keyUsages.toList(),
                signingKey = signingKey,
            )

        public fun fromParams(params: CertificateParams, signingKey: SigningKey): Issuer = new(params, signingKey)

        public fun fromCaCertDer(caCertDer: ByteArray, signingKey: SigningKey): Issuer {
            val root = DerReader.parseElement(caCertDer)
            val topSeq = root.asSequence()
            require(topSeq.size >= 3) { "Invalid Certificate sequence" }

            val tbsCert = topSeq[0].asSequence()
            val dn = DistinguishedName()
            if (tbsCert.size >= 6) {
                val subjectSeq = tbsCert[5].asSequence()
                for (rdnSet in subjectSeq) {
                    for (attrSeq in rdnSet.asSequence()) {
                        val items = attrSeq.asSequence()
                        if (items.size >= 2) {
                            val oid = items[0].asOid()
                            val valueStr = items[1].content.decodeToString()
                            dn.push(DnType.fromOid(oid), valueStr)
                        }
                    }
                }
            }

            var keyIdMethod: KeyIdMethod = KeyIdMethod.Sha256
            val kuList = mutableListOf<KeyUsagePurpose>()

            val extsElement = tbsCert.find { (it.tag and 0x1F) == 3 && (it.tag and Asn1Tag.CONTEXT_SPECIFIC) != 0 }
            if (extsElement != null) {
                val extsSeq = extsElement.asSequence()
                for (ext in extsSeq) {
                    val extItems = ext.asSequence()
                    if (extItems.size >= 2) {
                        val oid = extItems[0].asOid()
                        if (oid.contentEquals(Oid.SUBJECT_KEY_IDENTIFIER)) {
                            val rawSki = extItems.last().content
                            keyIdMethod = KeyIdMethod.PreSpecified(rawSki)
                        }
                    }
                }
            }

            return Issuer(
                distinguishedName = dn,
                keyIdentifierMethod = keyIdMethod,
                keyUsages = kuList,
                signingKey = signingKey,
            )
        }

        public fun fromCaCertPem(pemStr: String, signingKey: SigningKey): Issuer {
            val (_, contents) = Pem.parse(pemStr)
            return fromCaCertDer(contents, signingKey)
        }
    }
}

/**
 * An Issuer wrapper that also contains the issuer's Certificate.
 */
public class CertifiedIssuer(
    public val certificate: Certificate,
    public val issuer: Issuer,
) {
    public fun pem(): String = certificate.pem()

    public fun der(): ByteArray = certificate.der()

    public companion object {
        public fun selfSigned(params: CertificateParams, signingKey: SigningKey): CertifiedIssuer {
            val cert = params.selfSigned(signingKey)
            val issuer = Issuer.new(params, signingKey)
            return CertifiedIssuer(cert, issuer)
        }

        public fun signedBy(params: CertificateParams, signingKey: SigningKey, issuer: Issuer): CertifiedIssuer {
            val cert = params.signedBy(signingKey, issuer)
            val newIssuer = Issuer.new(params, signingKey)
            return CertifiedIssuer(cert, newIssuer)
        }
    }
}

/**
 * Convenience function to generate a self-signed certificate.
 */
public fun generateSimpleSelfSigned(subjectAltNames: List<String>): CertifiedKey<KeyPair> {
    val signingKey = KeyPair.generate()
    val cert = CertificateParams.new(subjectAltNames).selfSigned(signingKey)
    return CertifiedKey(cert, signingKey)
}
