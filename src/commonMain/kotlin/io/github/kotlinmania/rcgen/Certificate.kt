// port-lint: source certificate.rs
package io.github.kotlinmania.rcgen

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/**
 * An issued certificate.
 */
public class Certificate(
    private val derBytes: ByteArray,
) {
    public fun der(): ByteArray = derBytes.copyOf()

    public fun pem(): String = Pem.encode("CERTIFICATE", derBytes)

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Certificate) return false
        return derBytes.contentEquals(other.derBytes)
    }

    override fun hashCode(): Int = derBytes.contentHashCode()
}

/**
 * The attribute type of a distinguished name entry.
 */
public sealed class DnType {
    public object CountryName : DnType()

    public object LocalityName : DnType()

    public object StateOrProvinceName : DnType()

    public object OrganizationName : DnType()

    public object OrganizationalUnitName : DnType()

    public object CommonName : DnType()

    public data class CustomDnType(
        public val oid: LongArray,
    ) : DnType() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is CustomDnType) return false
            return oid.contentEquals(other.oid)
        }

        override fun hashCode(): Int = oid.contentHashCode()
    }

    public fun toOid(): LongArray =
        when (this) {
            CountryName -> Oid.COUNTRY_NAME
            LocalityName -> Oid.LOCALITY_NAME
            StateOrProvinceName -> Oid.STATE_OR_PROVINCE_NAME
            OrganizationName -> Oid.ORG_NAME
            OrganizationalUnitName -> Oid.ORG_UNIT_NAME
            CommonName -> Oid.COMMON_NAME
            is CustomDnType -> oid
        }

    public companion object {
        public fun fromOid(slice: LongArray): DnType =
            when {
                slice.contentEquals(Oid.COUNTRY_NAME) -> CountryName
                slice.contentEquals(Oid.LOCALITY_NAME) -> LocalityName
                slice.contentEquals(Oid.STATE_OR_PROVINCE_NAME) -> StateOrProvinceName
                slice.contentEquals(Oid.ORG_NAME) -> OrganizationName
                slice.contentEquals(Oid.ORG_UNIT_NAME) -> OrganizationalUnitName
                slice.contentEquals(Oid.COMMON_NAME) -> CommonName
                else -> CustomDnType(slice.copyOf())
            }
    }
}

/**
 * A distinguished name entry value.
 */
public sealed class DnValue {
    public data class BmpStringVal(
        public val value: BmpString,
    ) : DnValue()

    public data class Ia5StringVal(
        public val value: Ia5String,
    ) : DnValue()

    public data class PrintableStringVal(
        public val value: PrintableString,
    ) : DnValue()

    public data class TeletexStringVal(
        public val value: TeletexString,
    ) : DnValue()

    public data class UniversalStringVal(
        public val value: UniversalString,
    ) : DnValue()

    public data class Utf8StringVal(
        public val value: String,
    ) : DnValue()

    public companion object {
        public fun from(str: String): DnValue = Utf8StringVal(str)
    }
}

/**
 * Distinguished name used e.g. for the issuer and subject fields of a certificate.
 */
public class DistinguishedName {
    private val entries: MutableMap<DnType, DnValue> = mutableMapOf()
    private val order: MutableList<DnType> = mutableListOf()

    public fun get(ty: DnType): DnValue? = entries[ty]

    public fun remove(ty: DnType): Boolean {
        val removed = entries.remove(ty) != null
        if (removed) {
            order.removeAll { it == ty }
        }
        return removed
    }

    public fun push(ty: DnType, s: DnValue) {
        if (!entries.containsKey(ty)) {
            order.add(ty)
        }
        entries[ty] = s
    }

    public fun push(ty: DnType, str: String) {
        push(ty, DnValue.Utf8StringVal(str))
    }

    public fun iter(): List<Pair<DnType, DnValue>> =
        order.mapNotNull { ty ->
            entries[ty]?.let { v -> ty to v }
        }

    public fun entries(): List<Pair<DnType, DnValue>> = iter()

    public fun isEmpty(): Boolean = entries.isEmpty()

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is DistinguishedName) return false
        return order == other.order && entries == other.entries
    }

    override fun hashCode(): Int = 31 * order.hashCode() + entries.hashCode()
}

/**
 * Key Usage Purpose.
 */
public enum class KeyUsagePurpose(
    public val mask: Int,
) {
    DigitalSignature(1 shl 15),
    ContentCommitment(1 shl 14),
    KeyEncipherment(1 shl 13),
    DataEncipherment(1 shl 12),
    KeyAgreement(1 shl 11),
    KeyCertSign(1 shl 10),
    CrlSign(1 shl 9),
    EncipherOnly(1 shl 8),
    DecipherOnly(1 shl 7),
    ;

    public fun toU16(): Int = mask

    public companion object {
        public fun fromU16(value: Int): List<KeyUsagePurpose> = values().filter { (it.mask and value) != 0 }
    }
}

/**
 * Extended Key Usage Purpose.
 */
public sealed class ExtendedKeyUsagePurpose {
    public object Any : ExtendedKeyUsagePurpose()

    public object ServerAuth : ExtendedKeyUsagePurpose()

    public object ClientAuth : ExtendedKeyUsagePurpose()

    public object CodeSigning : ExtendedKeyUsagePurpose()

    public object EmailProtection : ExtendedKeyUsagePurpose()

    public object TimeStamping : ExtendedKeyUsagePurpose()

    public object OcspSigning : ExtendedKeyUsagePurpose()

    public data class Other(
        public val oid: LongArray,
    ) : ExtendedKeyUsagePurpose() {
        override fun equals(other: kotlin.Any?): Boolean {
            if (this === other) return true
            if (other !is Other) return false
            return oid.contentEquals(other.oid)
        }

        override fun hashCode(): Int = oid.contentHashCode()
    }

    public fun oid(): LongArray =
        when (this) {
            Any -> Oid.EKU_ANY
            ServerAuth -> Oid.EKU_SERVER_AUTH
            ClientAuth -> Oid.EKU_CLIENT_AUTH
            CodeSigning -> Oid.EKU_CODE_SIGNING
            EmailProtection -> Oid.EKU_EMAIL_PROTECTION
            TimeStamping -> Oid.EKU_TIME_STAMPING
            OcspSigning -> Oid.EKU_OCSP_SIGNING
            is Other -> oid
        }
}

/**
 * Path length constraint for CA certificates.
 */
public sealed class BasicConstraints {
    public object Unconstrained : BasicConstraints()

    public data class Constrained(
        public val pathLenConstraint: Int,
    ) : BasicConstraints()
}

/**
 * Whether the certificate is allowed to sign other certificates.
 */
public sealed class IsCa {
    public object NoCa : IsCa()

    public object ExplicitNoCa : IsCa()

    public data class Ca(
        public val basicConstraints: BasicConstraints,
    ) : IsCa()
}

/**
 * A certificate serial number.
 */
public class SerialNumber(
    public val inner: ByteArray,
) {
    public fun toBytes(): ByteArray = inner.copyOf()

    public fun len(): Int = inner.size

    override fun toString(): String =
        inner.joinToString(":") {
            (it.toInt() and 0xFF).toString(16).padStart(2, '0')
        }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is SerialNumber) return false
        return inner.contentEquals(other.inner)
    }

    override fun hashCode(): Int = inner.contentHashCode()

    public companion object {
        public fun fromSlice(bytes: ByteArray): SerialNumber = SerialNumber(bytes.copyOf())

        public fun from(u: Long): SerialNumber {
            val bytes = ByteArray(8)
            for (i in 0 until 8) {
                bytes[7 - i] = ((u ushr (i * 8)) and 0xFF).toByte()
            }
            var start = 0
            while (start < 7 && bytes[start] == 0.toByte()) {
                start++
            }
            return SerialNumber(bytes.copyOfRange(start, 8))
        }
    }
}

/**
 * Method to generate key identifiers from public keys.
 */
public sealed class KeyIdMethod {
    public object Sha256 : KeyIdMethod()

    public object Sha384 : KeyIdMethod()

    public object Sha512 : KeyIdMethod()

    public data class PreSpecified(
        public val bytes: ByteArray,
    ) : KeyIdMethod() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PreSpecified) return false
            return bytes.contentEquals(other.bytes)
        }

        override fun hashCode(): Int = bytes.contentHashCode()
    }

    public fun derive(subjectPublicKeyInfo: ByteArray): ByteArray =
        when (this) {
            Sha256 ->
                io.github.kotlinmania.rcgen.Sha256
                    .digest(subjectPublicKeyInfo)
                    .copyOfRange(0, 20)
            Sha384 ->
                io.github.kotlinmania.rcgen.Sha512
                    .digestSha384(subjectPublicKeyInfo)
                    .copyOfRange(0, 20)
            Sha512 ->
                io.github.kotlinmania.rcgen.Sha512
                    .digestSha512(subjectPublicKeyInfo)
                    .copyOfRange(0, 20)
            is PreSpecified -> bytes.copyOf()
        }
}

/**
 * An OtherName value.
 */
public sealed class OtherNameValue {
    public data class Utf8String(
        public val value: String,
    ) : OtherNameValue()
}

/**
 * Subject Alternative Name (SAN).
 */
public sealed class SanType {
    public data class Rfc822Name(
        public val name: Ia5String,
    ) : SanType()

    public data class DnsName(
        public val name: Ia5String,
    ) : SanType()

    public data class URI(
        public val uri: Ia5String,
    ) : SanType()

    public data class IpAddress(
        public val addr: ByteArray,
    ) : SanType() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is IpAddress) return false
            return addr.contentEquals(other.addr)
        }

        override fun hashCode(): Int = addr.contentHashCode()
    }

    public data class OtherName(
        public val oid: LongArray,
        public val value: OtherNameValue,
    ) : SanType() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is OtherName) return false
            return oid.contentEquals(other.oid) && value == other.value
        }

        override fun hashCode(): Int = 31 * oid.contentHashCode() + value.hashCode()
    }

    public fun tag(): Int =
        when (this) {
            is OtherName -> 0
            is Rfc822Name -> 1
            is DnsName -> 2
            is URI -> 6
            is IpAddress -> 7
        }
}

/**
 * CIDR Subnet for name constraints.
 */
public sealed class CidrSubnet {
    public data class V4(
        public val addr: ByteArray,
        public val mask: ByteArray,
    ) : CidrSubnet() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is V4) return false
            return addr.contentEquals(other.addr) && mask.contentEquals(other.mask)
        }

        override fun hashCode(): Int = 31 * addr.contentHashCode() + mask.contentHashCode()
    }

    public data class V6(
        public val addr: ByteArray,
        public val mask: ByteArray,
    ) : CidrSubnet() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is V6) return false
            return addr.contentEquals(other.addr) && mask.contentEquals(other.mask)
        }

        override fun hashCode(): Int = 31 * addr.contentHashCode() + mask.contentHashCode()
    }

    public fun toBytes(): ByteArray =
        when (this) {
            is V4 -> addr + mask
            is V6 -> addr + mask
        }

    public companion object {
        public fun fromV4Prefix(addr: ByteArray, prefix: Int): CidrSubnet {
            val mask = ByteArray(4)
            var p = prefix
            for (i in 0 until 4) {
                if (p >= 8) {
                    mask[i] = 0xFF.toByte()
                    p -= 8
                } else if (p > 0) {
                    mask[i] = ((0xFF shl (8 - p)) and 0xFF).toByte()
                    p = 0
                } else {
                    mask[i] = 0
                }
            }
            return V4(addr.copyOf(4), mask)
        }

        public fun fromStr(s: String): CidrSubnet {
            val parts = s.split('/')
            require(parts.size == 2) { "Invalid CIDR format" }
            val prefix = parts[1].toInt()
            val ipParts = parts[0].split('.').map { it.toInt().toByte() }.toByteArray()
            return fromV4Prefix(ipParts, prefix)
        }
    }
}

/**
 * General subtree for NameConstraints.
 */
public sealed class GeneralSubtree {
    public data class Rfc822Name(
        public val name: String,
    ) : GeneralSubtree()

    public data class DnsName(
        public val name: String,
    ) : GeneralSubtree()

    public data class DirectoryName(
        public val name: DistinguishedName,
    ) : GeneralSubtree()

    public data class IpAddress(
        public val subnet: CidrSubnet,
    ) : GeneralSubtree()

    public fun tag(): Int =
        when (this) {
            is Rfc822Name -> 1
            is DnsName -> 2
            is DirectoryName -> 4
            is IpAddress -> 7
        }
}

/**
 * Name Constraints extension.
 */
public data class NameConstraints(
    public val permittedSubtrees: List<GeneralSubtree> = emptyList(),
    public val excludedSubtrees: List<GeneralSubtree> = emptyList(),
) {
    public fun isEmpty(): Boolean = permittedSubtrees.isEmpty() && excludedSubtrees.isEmpty()
}

/**
 * Custom X.509 extension.
 */
public class CustomExtension(
    public val oid: LongArray,
    public var critical: Boolean,
    public val content: ByteArray,
) {
    public fun criticality(): Boolean = critical

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is CustomExtension) return false
        return oid.contentEquals(other.oid) && critical == other.critical && content.contentEquals(other.content)
    }

    override fun hashCode(): Int = 31 * (31 * oid.contentHashCode() + critical.hashCode()) + content.contentHashCode()

    public companion object {
        public fun newAcmeIdentifier(shaDigest: ByteArray): CustomExtension {
            require(shaDigest.size == 32) { "wrong size of sha_digest" }
            val content = DerWriter.constructDer { it.writeBytes(shaDigest) }
            return CustomExtension(Oid.PE_ACME, true, content)
        }

        public fun fromOidContent(oid: LongArray, content: ByteArray): CustomExtension = CustomExtension(oid.copyOf(), false, content.copyOf())
    }
}

/**
 * CSR Attribute.
 */
public data class Attribute(
    public val oid: LongArray,
    public val values: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Attribute) return false
        return oid.contentEquals(other.oid) && values.contentEquals(other.values)
    }

    override fun hashCode(): Int = 31 * oid.contentHashCode() + values.contentHashCode()
}

public fun dateTimeYmd(year: Int, month: Int, day: Int): Instant {
    val yStr = year.toString().padStart(4, '0')
    val mStr = month.toString().padStart(2, '0')
    val dStr = day.toString().padStart(2, '0')
    return Instant.parse("$yStr-$mStr-${dStr}T00:00:00Z")
}

/**
 * Parameters used for certificate generation.
 */
public class CertificateParams(
    public var notBefore: Instant = dateTimeYmd(1975, 1, 1),
    public var notAfter: Instant = dateTimeYmd(4096, 1, 1),
    public var serialNumber: SerialNumber? = null,
    public var subjectAltNames: List<SanType> = emptyList(),
    public var distinguishedName: DistinguishedName =
        DistinguishedName().apply {
            push(DnType.CommonName, "rcgen self signed cert")
        },
    public var isCa: IsCa = IsCa.NoCa,
    public var keyUsages: List<KeyUsagePurpose> = emptyList(),
    public var extendedKeyUsages: List<ExtendedKeyUsagePurpose> = emptyList(),
    public var nameConstraints: NameConstraints? = null,
    public var crlDistributionPoints: List<CrlDistributionPoint> = emptyList(),
    public var customExtensions: List<CustomExtension> = emptyList(),
    public var useAuthorityKeyIdentifierExtension: Boolean = false,
    public var keyIdentifierMethod: KeyIdMethod = KeyIdMethod.Sha256,
) {
    public fun insertExtendedKeyUsage(eku: ExtendedKeyUsagePurpose) {
        if (!extendedKeyUsages.contains(eku)) {
            extendedKeyUsages = extendedKeyUsages + eku
        }
    }

    public fun keyIdentifier(key: PublicKeyData): ByteArray = keyIdentifierMethod.derive(key.subjectPublicKeyInfo())

    public fun selfSigned(signingKey: SigningKey): Certificate {
        val issuer = Issuer(distinguishedName, keyIdentifierMethod, keyUsages, signingKey)
        return Certificate(serializeDerWithSigner(signingKey, issuer))
    }

    public fun signedBy(publicKey: PublicKeyData, issuer: Issuer): Certificate = Certificate(serializeDerWithSigner(publicKey, issuer))

    public fun serializeRequest(subjectKey: SigningKey): CertificateSigningRequest = serializeRequestWithAttributes(subjectKey, emptyList())

    public fun serializeRequestWithAttributes(
        subjectKey: SigningKey,
        attrs: List<Attribute>,
    ): CertificateSigningRequest {
        if (serialNumber != null ||
            isCa != IsCa.NoCa ||
            nameConstraints != null ||
            crlDistributionPoints.isNotEmpty() ||
            useAuthorityKeyIdentifierExtension
        ) {
            throw RcgenException.UnsupportedInCsr()
        }

        val writeExtensionRequest =
            keyUsages.isNotEmpty() ||
                subjectAltNames.isNotEmpty() ||
                extendedKeyUsages.isNotEmpty() ||
                customExtensions.isNotEmpty()

        val der =
            signDer(subjectKey) {
                next().writeInteger(0)
                writeDistinguishedName(next(), distinguishedName)
                serializePublicKeyDer(subjectKey, next())

                next().writeTaggedImplicit(0) { writer ->
                    writer.writeSet {
                        if (writeExtensionRequest) {
                            writeExtensionRequestAttribute(next())
                        }
                        for (attr in attrs) {
                            next().writeSequence {
                                next().writeOid(attr.oid)
                                next().writeDer(attr.values)
                            }
                        }
                    }
                }
            }

        return CertificateSigningRequest(der)
    }

    private fun writeExtensionRequestAttribute(writer: DerWriter) {
        writer.writeSequence {
            next().writeOid(Oid.PKCS_9_AT_EXTENSION_REQUEST)
            next().writeSet {
                next().writeSequence {
                    writeKeyUsage(next())
                    writeSubjectAltNames(next())
                    writeExtendedKeyUsage(next())
                    for (ext in customExtensions) {
                        writeX509Extension(next(), ext.oid, ext.critical) { w ->
                            w.writeDer(ext.content)
                        }
                    }
                }
            }
        }
    }

    public fun serializeDerWithSigner(pubKey: PublicKeyData, issuer: Issuer): ByteArray =
        signDer(issuer.signingKey) {
            val pubKeySpki = pubKey.subjectPublicKeyInfo()
            // Version 3 (represented as integer 2)
            next().writeTagged(0) { w -> w.writeInteger(2) }

            // SerialNumber
            val serial =
                serialNumber ?: run {
                    val hash =
                        io.github.kotlinmania.rcgen.Sha256
                            .digest(pubKey.derBytes())
                    val sl = hash.copyOfRange(0, 20)
                    sl[0] = (sl[0].toInt() and 0x7F).toByte()
                    SerialNumber(sl)
                }
            next().writeBigIntBytes(serial.inner, positive = true)

            // Signature algorithm
            issuer.signingKey.algorithm().writeAlgIdent(next())

            // Issuer name
            writeDistinguishedName(next(), issuer.distinguishedName)

            // Validity
            next().writeSequence {
                writeDtUtcOrGeneralized(next(), notBefore)
                writeDtUtcOrGeneralized(next(), notAfter)
            }

            // Subject name
            writeDistinguishedName(next(), distinguishedName)

            // SubjectPublicKeyInfo
            serializePublicKeyDer(pubKey, next())

            // Extensions
            val shouldWriteExts =
                useAuthorityKeyIdentifierExtension ||
                    subjectAltNames.isNotEmpty() ||
                    extendedKeyUsages.isNotEmpty() ||
                    (nameConstraints?.isEmpty() == false) ||
                    (isCa is IsCa.ExplicitNoCa) ||
                    (isCa is IsCa.Ca) ||
                    customExtensions.isNotEmpty()

            if (shouldWriteExts) {
                next().writeTagged(3) { w ->
                    w.writeSequence {
                        writeExtensions(this, pubKeySpki, issuer)
                    }
                }
            }
        }

    private fun writeExtensions(seq: DerWriterSeq, pubKeySpki: ByteArray, issuer: Issuer) {
        if (useAuthorityKeyIdentifierExtension) {
            val aki = issuer.keyIdentifierMethod.derive(issuer.signingKey.subjectPublicKeyInfo())
            writeX509AuthorityKeyIdentifier(seq.next(), aki)
        }

        writeSubjectAltNames(seq.next())
        writeKeyUsage(seq.next())

        if (extendedKeyUsages.isNotEmpty()) {
            writeX509Extension(seq.next(), Oid.EXT_KEY_USAGE, false) { w ->
                w.writeSequence {
                    for (usage in extendedKeyUsages) {
                        next().writeOid(usage.oid())
                    }
                }
            }
        }

        nameConstraints?.let { nc ->
            if (!nc.isEmpty()) {
                writeX509Extension(seq.next(), Oid.NAME_CONSTRAINTS, true) { w ->
                    w.writeSequence {
                        if (nc.permittedSubtrees.isNotEmpty()) {
                            writeGeneralSubtrees(next(), 0, nc.permittedSubtrees)
                        }
                        if (nc.excludedSubtrees.isNotEmpty()) {
                            writeGeneralSubtrees(next(), 1, nc.excludedSubtrees)
                        }
                    }
                }
            }
        }

        if (crlDistributionPoints.isNotEmpty()) {
            writeX509Extension(seq.next(), Oid.CRL_DISTRIBUTION_POINTS, false) { w ->
                w.writeSequence {
                    for (dp in crlDistributionPoints) {
                        dp.writeDer(next())
                    }
                }
            }
        }

        when (val ca = isCa) {
            is IsCa.Ca -> {
                writeX509Extension(seq.next(), Oid.SUBJECT_KEY_IDENTIFIER, false) { w ->
                    w.writeBytes(keyIdentifierMethod.derive(pubKeySpki))
                }
                writeX509Extension(seq.next(), Oid.BASIC_CONSTRAINTS, true) { w ->
                    w.writeSequence {
                        next().writeBoolean(true)
                        if (ca.basicConstraints is BasicConstraints.Constrained) {
                            next().writeInteger(ca.basicConstraints.pathLenConstraint.toLong())
                        }
                    }
                }
            }
            is IsCa.ExplicitNoCa -> {
                writeX509Extension(seq.next(), Oid.SUBJECT_KEY_IDENTIFIER, false) { w ->
                    w.writeBytes(keyIdentifierMethod.derive(pubKeySpki))
                }
                writeX509Extension(seq.next(), Oid.BASIC_CONSTRAINTS, true) { w ->
                    w.writeSequence {
                        next().writeBoolean(false)
                    }
                }
            }
            is IsCa.NoCa -> Unit
        }

        for (ext in customExtensions) {
            writeX509Extension(seq.next(), ext.oid, ext.critical) { w ->
                w.writeDer(ext.content)
            }
        }
    }

    private fun writeKeyUsage(writer: DerWriter) {
        if (keyUsages.isEmpty()) return
        writeX509Extension(writer, Oid.KEY_USAGE, true) { w ->
            var bitString = 0
            for (ku in keyUsages) {
                bitString = bitString or ku.mask
            }
            val b1 = ((bitString ushr 8) and 0xFF).toByte()
            val b2 = (bitString and 0xFF).toByte()
            if (b2 == 0.toByte()) {
                w.writeBitString(byteArrayOf(b1))
            } else {
                w.writeBitString(byteArrayOf(b1, b2))
            }
        }
    }

    private fun writeExtendedKeyUsage(writer: DerWriter) {
        if (extendedKeyUsages.isEmpty()) return
        writeX509Extension(writer, Oid.EXT_KEY_USAGE, false) { w ->
            w.writeSequence {
                for (usage in extendedKeyUsages) {
                    next().writeOid(usage.oid())
                }
            }
        }
    }

    private fun writeSubjectAltNames(writer: DerWriter) {
        if (subjectAltNames.isEmpty()) return
        val critical = distinguishedName.isEmpty()
        writeX509Extension(writer, Oid.SUBJECT_ALT_NAME, critical) { w ->
            w.writeSequence {
                for (san in subjectAltNames) {
                    next().writeTaggedImplicit(san.tag()) { targetW ->
                        when (san) {
                            is SanType.Rfc822Name -> targetW.writeIa5String(san.name.asStr())
                            is SanType.DnsName -> targetW.writeIa5String(san.name.asStr())
                            is SanType.URI -> targetW.writeIa5String(san.uri.asStr())
                            is SanType.IpAddress -> targetW.writeBytes(san.addr)
                            is SanType.OtherName -> {
                                targetW.writeSequence {
                                    next().writeOid(san.oid)
                                    when (val v = san.value) {
                                        is OtherNameValue.Utf8String -> {
                                            next().writeTagged(0) { utf8W ->
                                                utf8W.writeUtf8String(v.value)
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    public companion object {
        public fun new(subjectAltNames: List<String>): CertificateParams {
            val sans =
                subjectAltNames
                    .map { s ->
                        val ipRegex = Regex("""^(\d{1,3}\.){3}\d{1,3}$""")
                        if (ipRegex.matches(s)) {
                            val bytes = s.split('.').map { it.toInt().toByte() }.toByteArray()
                            SanType.IpAddress(bytes)
                        } else {
                            SanType.DnsName(Ia5String(s))
                        }
                    }.toList()
            return CertificateParams(subjectAltNames = sans)
        }
    }
}

public fun writeDistinguishedName(writer: DerWriter, dn: DistinguishedName) {
    writer.writeSequence {
        for ((ty, content) in dn.iter()) {
            next().writeSet {
                next().writeSequence {
                    next().writeOid(ty.toOid())
                    when (content) {
                        is DnValue.BmpStringVal -> next().writeTaggedImplicit(0x1E) { w -> w.writeBytes(content.value.asBytes()) }
                        is DnValue.Ia5StringVal -> next().writeIa5String(content.value.asStr())
                        is DnValue.PrintableStringVal -> next().writePrintableString(content.value.asStr())
                        is DnValue.TeletexStringVal -> next().writeTaggedImplicit(0x14) { w -> w.writeBytes(content.value.asBytes()) }
                        is DnValue.UniversalStringVal -> next().writeTaggedImplicit(0x1C) { w -> w.writeBytes(content.value.asBytes()) }
                        is DnValue.Utf8StringVal -> next().writeUtf8String(content.value)
                    }
                }
            }
        }
    }
}

public fun writeX509Extension(
    writer: DerWriter,
    extensionOid: LongArray,
    isCritical: Boolean,
    valueSerializer: (DerWriter) -> Unit,
) {
    writer.writeSequence {
        next().writeOid(extensionOid)
        if (isCritical) {
            next().writeBoolean(true)
        }
        val bytes = DerWriter.constructDer(valueSerializer)
        next().writeBytes(bytes)
    }
}

public fun writeX509AuthorityKeyIdentifier(writer: DerWriter, aki: ByteArray) {
    writeX509Extension(writer, Oid.AUTHORITY_KEY_IDENTIFIER, false) { w ->
        w.writeSequence {
            next().writeTaggedImplicit(0) { akiW ->
                akiW.writeBytes(aki)
            }
        }
    }
}

public fun writeDtUtcOrGeneralized(writer: DerWriter, instant: Instant) {
    val ldt = instant.toLocalDateTime(TimeZone.UTC)
    if (ldt.year in 1950..2049) {
        writer.writeUtcTime(instant)
    } else {
        writer.writeGeneralizedTime(instant)
    }
}

private fun writeGeneralSubtrees(writer: DerWriter, tag: Int, generalSubtrees: List<GeneralSubtree>) {
    writer.writeTaggedImplicit(tag) { w ->
        w.writeSequence {
            for (subtree in generalSubtrees) {
                next().writeSequence {
                    next().writeTaggedImplicit(subtree.tag()) { targetW ->
                        when (subtree) {
                            is GeneralSubtree.Rfc822Name -> targetW.writeIa5String(subtree.name)
                            is GeneralSubtree.DnsName -> targetW.writeIa5String(subtree.name)
                            is GeneralSubtree.DirectoryName -> writeDistinguishedName(targetW, subtree.name)
                            is GeneralSubtree.IpAddress -> targetW.writeBytes(subtree.subnet.toBytes())
                        }
                    }
                }
            }
        }
    }
}
