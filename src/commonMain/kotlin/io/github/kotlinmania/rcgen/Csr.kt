// port-lint: source rcgen/src/csr.rs
package io.github.kotlinmania.rcgen

/**
 * A public key extracted from a CSR.
 */
public class PublicKey(
    public val raw: ByteArray,
    public val alg: SignatureAlgorithm,
) : PublicKeyData {
    override fun derBytes(): ByteArray = raw

    override fun algorithm(): SignatureAlgorithm = alg

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is PublicKey) return false
        return raw.contentEquals(other.raw) && alg == other.alg
    }

    override fun hashCode(): Int = 31 * raw.contentHashCode() + alg.hashCode()
}

/**
 * A certificate signing request (CSR).
 */
public class CertificateSigningRequest(
    private val derBytes: ByteArray,
) {
    public fun der(): ByteArray = derBytes.copyOf()

    public fun pem(): String = Pem.encode("CERTIFICATE REQUEST", derBytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CertificateSigningRequest) return false
        return derBytes.contentEquals(other.derBytes)
    }

    override fun hashCode(): Int = derBytes.contentHashCode()
}

/**
 * Parameters for a certificate signing request.
 */
public class CertificateSigningRequestParams(
    public val params: CertificateParams,
    public val publicKey: PublicKey,
) {
    public fun signedBy(issuer: Issuer): Certificate =
        Certificate(params.serializeDerWithSigner(publicKey, issuer))

    public companion object {
        public fun fromDer(csrDer: ByteArray): CertificateSigningRequestParams {
            val root = DerReader.parseElement(csrDer)
            val seq = root.asSequence()
            if (seq.size < 3) throw RcgenException.CouldNotParseCertificationRequest()

            val infoSeq = seq[0].asSequence()
            if (infoSeq.size < 3) throw RcgenException.CouldNotParseCertificationRequest()

            val algSeq = seq[1].asSequence()
            val sigOid =
                algSeq.firstOrNull { it.tag == Asn1Tag.OBJECT_IDENTIFIER }?.asOid()
                    ?: throw RcgenException.CouldNotParseCertificationRequest()
            val matchedAlg =
                SignatureAlgorithm.fromOidOrNull(sigOid)
                    ?: SignatureAlgorithm.iter().find { alg ->
                        alg.oidsSignAlg.any { it.contentEquals(sigOid) }
                    }
                    ?: throw RcgenException.UnsupportedSignatureAlgorithm()

            val subjectSeq = infoSeq[1].asSequence()
            val dn = DistinguishedName()
            for (rdn in subjectSeq) {
                for (attrSeq in rdn.asSequence()) {
                    val attrParts = attrSeq.asSequence()
                    if (attrParts.size >= 2) {
                        val oid = attrParts[0].asOid()
                        val dnType = DnType.fromOid(oid)
                        val dnValue = DnValue.Utf8StringVal(attrParts[1].content.decodeToString())
                        dn.push(dnType, dnValue)
                    }
                }
            }

            val spkiSeq = infoSeq[2].asSequence()
            val spkiAlgSeq = if (spkiSeq.isNotEmpty()) spkiSeq[0].asSequence() else emptyList()
            val spkiOids = spkiAlgSeq.filter { it.tag == Asn1Tag.OBJECT_IDENTIFIER }.map { it.asOid() }
            val spkiAlg =
                SignatureAlgorithm.iter().find { alg ->
                    if (alg.oidsSignAlg.size == spkiOids.size) {
                        alg.oidsSignAlg.indices.all { i -> alg.oidsSignAlg[i].contentEquals(spkiOids[i]) }
                    } else {
                        false
                    }
                } ?: matchedAlg
            val rawPub = if (spkiSeq.size >= 2) spkiSeq[1].asBitString() else byteArrayOf()
            val publicKey = PublicKey(rawPub, spkiAlg)

            val params = CertificateParams()
            params.distinguishedName = dn

            return CertificateSigningRequestParams(params, publicKey)
        }

        public fun fromPem(pemStr: String): CertificateSigningRequestParams {
            val (_, contents) = Pem.parse(pemStr)
            return fromDer(contents)
        }
    }
}
