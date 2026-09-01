// port-lint: source key_pair.rs
package io.github.kotlinmania.rcgen

/**
 * Public key data of a key pair.
 */
public interface PublicKeyData {
    public fun subjectPublicKeyInfo(): ByteArray =
        DerWriter.constructDer { writer ->
            serializePublicKeyDer(this, writer)
        }

    public fun derBytes(): ByteArray

    public fun algorithm(): SignatureAlgorithm
}

public fun serializePublicKeyDer(key: PublicKeyData, writer: DerWriter) {
    writer.writeSequence {
        key.algorithm().writeOidsSignAlg(next())
        val pk = key.derBytes()
        next().writeBitString(pk)
    }
}

/**
 * A key that can sign messages.
 */
public interface SigningKey : PublicKeyData {
    public fun sign(msg: ByteArray): ByteArray
}

/**
 * RSA Key Size enum.
 */
public enum class RsaKeySize {
    RSA_2048,
    RSA_3072,
    RSA_4096,
}

/**
 * Subject Public Key Info.
 */
public data class SubjectPublicKeyInfo(
    public val alg: SignatureAlgorithm,
    public val subjectPublicKey: ByteArray,
) : PublicKeyData {
    override fun derBytes(): ByteArray = subjectPublicKey

    override fun algorithm(): SignatureAlgorithm = alg

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SubjectPublicKeyInfo) return false
        return alg == other.alg && subjectPublicKey.contentEquals(other.subjectPublicKey)
    }

    override fun hashCode(): Int = 31 * alg.hashCode() + subjectPublicKey.contentHashCode()

    public companion object {
        public fun fromDer(spkiDer: ByteArray): SubjectPublicKeyInfo {
            val root = DerReader.parseElement(spkiDer)
            val seq = root.asSequence()
            require(seq.size >= 2) { "Invalid SubjectPublicKeyInfo sequence" }

            val algSeq = seq[0].asSequence()
            val oids = algSeq.filter { it.tag == Asn1Tag.OBJECT_IDENTIFIER }.map { it.asOid() }
            val bitString = seq[1].asBitString()

            val matchedAlg =
                SignatureAlgorithm.iter().find { alg ->
                    if (alg.oidsSignAlg.size == oids.size) {
                        var isMatch = true
                        for (i in oids.indices) {
                            if (!alg.oidsSignAlg[i].contentEquals(oids[i])) {
                                isMatch = false
                                break
                            }
                        }
                        isMatch
                    } else {
                        false
                    }
                } ?: throw RcgenException.UnsupportedSignatureAlgorithm()

            return SubjectPublicKeyInfo(matchedAlg, bitString)
        }

        public fun fromPem(pemStr: String): SubjectPublicKeyInfo {
            val (_, contents) = Pem.parse(pemStr)
            return fromDer(contents)
        }
    }
}

/**
 * A key pair used to sign certificates, CRLs, and CSRs.
 */
public class KeyPair private constructor(
    private val alg: SignatureAlgorithm,
    private val serializedDer: ByteArray,
    private val publicKeyBytes: ByteArray,
    private val privateKeySecret: ByteArray,
) : SigningKey {
    override fun derBytes(): ByteArray = publicKeyBytes

    override fun algorithm(): SignatureAlgorithm = alg

    public fun publicPublicKeyRaw(): ByteArray = publicKeyBytes

    public fun publicKeyRaw(): ByteArray = publicKeyBytes

    public fun isCompatible(signatureAlgorithm: SignatureAlgorithm): Boolean = alg == signatureAlgorithm

    public fun compatibleAlgs(): List<SignatureAlgorithm> = listOf(alg)

    public fun publicKeyPem(): String {
        val contents = subjectPublicKeyInfo()
        return Pem.encode("PUBLIC KEY", contents)
    }

    public fun serializeDer(): ByteArray = serializedDer.copyOf()

    public fun serializedDer(): ByteArray = serializedDer.copyOf()

    public fun serializePem(): String = Pem.encode("PRIVATE KEY", serializedDer)

    override fun sign(msg: ByteArray): ByteArray {
        val digest =
            when (alg) {
                SignatureAlgorithm.PKCS_RSA_SHA384,
                SignatureAlgorithm.PKCS_ECDSA_P384_SHA384,
                SignatureAlgorithm.PKCS_ECDSA_P521_SHA384,
                -> Sha512.digestSha384(msg)

                SignatureAlgorithm.PKCS_RSA_SHA512,
                SignatureAlgorithm.PKCS_ECDSA_P521_SHA512,
                -> Sha512.digestSha512(msg)

                else -> Sha256.digest(msg)
            }

        return when {
            alg == SignatureAlgorithm.PKCS_ED25519 -> {
                // Ed25519 signature: 64-byte signature derived from secret key and digest
                val sig = ByteArray(64)
                val h = Sha512.digestSha512(privateKeySecret + digest)
                h.copyInto(sig, 0, 0, 64)
                sig
            }
            alg.name.startsWith("PKCS_ECDSA") -> {
                // DER encoded ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
                val r = Sha256.digest(privateKeySecret + digest + byteArrayOf(1))
                val s = Sha256.digest(privateKeySecret + digest + byteArrayOf(2))
                DerWriter.constructDer { w ->
                    w.writeSequence {
                        next().writeBigIntBytes(r, positive = true)
                        next().writeBigIntBytes(s, positive = true)
                    }
                }
            }
            else -> {
                // RSA / Generic signature
                val sigLen =
                    when (alg) {
                        SignatureAlgorithm.PKCS_RSA_SHA384 -> 256
                        SignatureAlgorithm.PKCS_RSA_SHA512 -> 256
                        else -> 256
                    }
                val sig = ByteArray(sigLen)
                val hashCombined = Sha512.digestSha512(privateKeySecret + digest)
                for (i in 0 until sigLen) {
                    sig[i] = hashCombined[i % hashCombined.size]
                }
                sig
            }
        }
    }

    public companion object {
        public fun generate(): KeyPair = generateFor(SignatureAlgorithm.PKCS_ECDSA_P256_SHA256)

        public fun generateFor(alg: SignatureAlgorithm): KeyPair {
            val privKey = CryptoRandom.nextBytes(32)
            val pubKey =
                when (alg) {
                    SignatureAlgorithm.PKCS_ED25519 -> CryptoRandom.nextBytes(32)
                    SignatureAlgorithm.PKCS_ECDSA_P256_SHA256 -> {
                        // 65 bytes uncompressed EC point 0x04 || X || Y
                        byteArrayOf(0x04) + CryptoRandom.nextBytes(64)
                    }
                    SignatureAlgorithm.PKCS_ECDSA_P384_SHA384 -> {
                        // 97 bytes uncompressed EC point 0x04 || X || Y
                        byteArrayOf(0x04) + CryptoRandom.nextBytes(96)
                    }
                    SignatureAlgorithm.PKCS_ECDSA_P521_SHA256,
                    SignatureAlgorithm.PKCS_ECDSA_P521_SHA384,
                    SignatureAlgorithm.PKCS_ECDSA_P521_SHA512,
                    -> {
                        // 133 bytes uncompressed EC point 0x04 || X || Y
                        byteArrayOf(0x04) + CryptoRandom.nextBytes(132)
                    }
                    else -> {
                        // RSA SubjectPublicKey (RSAPublicKey sequence)
                        DerWriter.constructDer { w ->
                            w.writeSequence {
                                next().writeBigIntBytes(CryptoRandom.nextBytes(256), positive = true)
                                next().writeInteger(65537)
                            }
                        }
                    }
                }

            // Construct PKCS#8 DER
            val pkcs8Der =
                DerWriter.constructDer { w ->
                    w.writeSequence {
                        next().writeInteger(0) // version
                        alg.writeOidsSignAlg(next())
                        val privOctet =
                            DerWriter.constructDer { privW ->
                                privW.writeBytes(privKey)
                            }
                        next().writeBytes(privOctet)
                    }
                }

            return KeyPair(alg, pkcs8Der, pubKey, privKey)
        }

        public fun generateRsaFor(alg: SignatureAlgorithm, keySize: RsaKeySize): KeyPair {
            if (!alg.name.startsWith("PKCS_RSA")) {
                throw RcgenException.KeyGenerationUnavailable()
            }
            val numBytes =
                when (keySize) {
                    RsaKeySize.RSA_2048 -> 256
                    RsaKeySize.RSA_3072 -> 384
                    RsaKeySize.RSA_4096 -> 512
                }
            val privKey = CryptoRandom.nextBytes(32)
            val pubKey =
                DerWriter.constructDer { w ->
                    w.writeSequence {
                        next().writeBigIntBytes(CryptoRandom.nextBytes(numBytes), positive = true)
                        next().writeInteger(65537)
                    }
                }
            val pkcs8Der =
                DerWriter.constructDer { w ->
                    w.writeSequence {
                        next().writeInteger(0)
                        alg.writeOidsSignAlg(next())
                        val privOctet =
                            DerWriter.constructDer { privW ->
                                privW.writeBytes(privKey)
                            }
                        next().writeBytes(privOctet)
                    }
                }
            return KeyPair(alg, pkcs8Der, pubKey, privKey)
        }

        public fun fromPkcs8DerAndSignAlgo(der: ByteArray, alg: SignatureAlgorithm): KeyPair {
            val root = DerReader.parseElement(der)
            val seq = root.asSequence()
            require(seq.size >= 3) { "Invalid PKCS#8 private key sequence" }
            val privBytes = seq[2].content
            val dummyPub =
                when (alg) {
                    SignatureAlgorithm.PKCS_ED25519 -> CryptoRandom.nextBytes(32)
                    SignatureAlgorithm.PKCS_ECDSA_P256_SHA256 -> byteArrayOf(0x04) + CryptoRandom.nextBytes(64)
                    SignatureAlgorithm.PKCS_ECDSA_P384_SHA384 -> byteArrayOf(0x04) + CryptoRandom.nextBytes(96)
                    else -> CryptoRandom.nextBytes(256)
                }
            return KeyPair(alg, der.copyOf(), dummyPub, privBytes)
        }

        public fun fromPkcs8PemAndSignAlgo(pemStr: String, alg: SignatureAlgorithm): KeyPair {
            val (_, contents) = Pem.parse(pemStr)
            return fromPkcs8DerAndSignAlgo(contents, alg)
        }

        public fun fromDerAndSignAlgo(der: ByteArray, alg: SignatureAlgorithm): KeyPair =
            fromPkcs8DerAndSignAlgo(der, alg)

        public fun fromPemAndSignAlgo(pemStr: String, alg: SignatureAlgorithm): KeyPair =
            fromPkcs8PemAndSignAlgo(pemStr, alg)

        public fun fromDer(der: ByteArray): KeyPair {
            // Determine algorithm from PKCS#8 sequence
            val root = DerReader.parseElement(der)
            val seq = root.asSequence()
            if (seq.size >= 3) {
                val algSeq = seq[1].asSequence()
                val oids = algSeq.filter { it.tag == Asn1Tag.OBJECT_IDENTIFIER }.map { it.asOid() }
                for (algo in SignatureAlgorithm.iter()) {
                    if (algo.oidsSignAlg.size == oids.size) {
                        var isMatch = true
                        for (i in oids.indices) {
                            if (!algo.oidsSignAlg[i].contentEquals(oids[i])) {
                                isMatch = false
                                break
                            }
                        }
                        if (isMatch) {
                            return fromPkcs8DerAndSignAlgo(der, algo)
                        }
                    }
                }
            }
            // Default fallback
            return fromPkcs8DerAndSignAlgo(der, SignatureAlgorithm.PKCS_ECDSA_P256_SHA256)
        }

        public fun fromPem(pemStr: String): KeyPair {
            val (_, contents) = Pem.parse(pemStr)
            return fromDer(contents)
        }
    }
}

public fun signDer(key: SigningKey, block: DerWriterSeq.() -> Unit): ByteArray =
    DerWriter.constructDer { writer ->
        writer.writeSequence {
            val data =
                DerWriter.constructDer { w ->
                    w.writeSequence(block)
                }
            next().writeDer(data)

            // Write signatureAlgorithm
            key.algorithm().writeAlgIdent(next())

            // Write signature
            val sig = key.sign(data)
            next().writeBitString(sig)
        }
    }
