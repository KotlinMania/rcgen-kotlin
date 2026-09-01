// port-lint: source error.rs
package io.github.kotlinmania.rcgen

/**
 * The error type of the rcgen library.
 */
public sealed class RcgenException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause) {
    public class CouldNotParseCertificate(
        message: String = "Could not parse certificate",
    ) : RcgenException(message)

    public class CouldNotParseCertificationRequest(
        message: String = "Could not parse certificate signing request",
    ) : RcgenException(message)

    public class CouldNotParseKeyPair(
        message: String = "Could not parse key pair",
    ) : RcgenException(message)

    public class InvalidCertificationRequestSignature(
        message: String = "Invalid CSR signature",
    ) : RcgenException(message)

    public class InvalidNameType(
        message: String = "Invalid subject alternative name type",
    ) : RcgenException(message)

    public class InvalidAsn1(
        public val details: InvalidAsn1String,
    ) : RcgenException(details.toString())

    public class InvalidIpAddressOctetLength(
        public val actual: Int,
    ) : RcgenException("Invalid IP address octet length of $actual bytes")

    public class KeyGenerationUnavailable(
        message: String = "There is no support for generating keys for the given algorithm",
    ) : RcgenException(message)

    public class UnsupportedExtension(
        message: String = "Unsupported extension requested in CSR",
    ) : RcgenException(message)

    public class UnsupportedSignatureAlgorithm(
        message: String = "The requested signature algorithm is not supported",
    ) : RcgenException(message)

    public class RingUnspecified(
        message: String = "Unspecified crypto error",
    ) : RcgenException(message)

    public class RingKeyRejected(
        public val reason: String,
    ) : RcgenException("Key rejected: $reason")

    public class TimeError(
        message: String = "Time error",
    ) : RcgenException(message)

    public class Pem(
        public val reason: String,
    ) : RcgenException("PEM error: $reason")

    public class RemoteKey(
        message: String = "Remote key error",
    ) : RcgenException(message)

    public class UnsupportedInCsr(
        message: String = "Certificate parameter unsupported in CSR",
    ) : RcgenException(message)

    public class InvalidCrlNextUpdate(
        message: String = "Invalid CRL next update parameter",
    ) : RcgenException(message)

    public class IssuerNotCrlSigner(
        message: String = "CRL issuer must specify no key usage, or key usage including cRLSign",
    ) : RcgenException(message)

    public class MissingSerialNumber(
        message: String = "A serial number must be specified",
    ) : RcgenException(message)

    public class X509(
        public val reason: String,
    ) : RcgenException("X.509 parsing error: $reason")
}

/**
 * Invalid ASN.1 string type error description.
 */
public sealed class InvalidAsn1String {
    public abstract val value: String

    public data class PrintableString(
        override val value: String,
    ) : InvalidAsn1String() {
        override fun toString(): String = "Invalid PrintableString: '$value'"
    }

    public data class UniversalString(
        override val value: String,
    ) : InvalidAsn1String() {
        override fun toString(): String = "Invalid UniversalString: '$value'"
    }

    public data class Ia5String(
        override val value: String,
    ) : InvalidAsn1String() {
        override fun toString(): String = "Invalid IA5String: '$value'"
    }

    public data class TeletexString(
        override val value: String,
    ) : InvalidAsn1String() {
        override fun toString(): String = "Invalid TeletexString: '$value'"
    }

    public data class BmpString(
        override val value: String,
    ) : InvalidAsn1String() {
        override fun toString(): String = "Invalid BMPString: '$value'"
    }
}
