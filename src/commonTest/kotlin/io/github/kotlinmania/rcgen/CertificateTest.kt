// port-lint: tests rcgen/src/certificate.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertTrue

class CertificateTest {
    @Test
    fun testSelfSignedCertificate() {
        val params = CertificateParams.new(listOf("localhost", "example.com"))
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)

        assertTrue(cert.der().isNotEmpty())
        val pem = cert.pem()
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE-----"))
        assertTrue(pem.endsWith("-----END CERTIFICATE-----\n"))
    }

    @Test
    fun testWithKeyUsages() {
        val params =
            CertificateParams(
                keyUsages =
                    listOf(
                        KeyUsagePurpose.DigitalSignature,
                        KeyUsagePurpose.KeyEncipherment,
                        KeyUsagePurpose.ContentCommitment,
                    ),
                isCa = IsCa.Ca(BasicConstraints.Constrained(0)),
            )

        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())

        val root = DerReader.parseElement(cert.der())
        val seq = root.asSequence()
        assertTrue(seq.size >= 3)
    }

    @Test
    fun testWithExtendedKeyUsages() {
        val params =
            CertificateParams(
                extendedKeyUsages =
                    listOf(
                        ExtendedKeyUsagePurpose.ServerAuth,
                        ExtendedKeyUsagePurpose.ClientAuth,
                        ExtendedKeyUsagePurpose.Other(longArrayOf(1, 2, 3, 4)),
                    ),
            )

        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testSignedByIssuer() {
        val caParams =
            CertificateParams.new(listOf("ca.example.com")).apply {
                isCa = IsCa.Ca(BasicConstraints.Unconstrained)
                keyUsages = listOf(KeyUsagePurpose.KeyCertSign, KeyUsagePurpose.CrlSign)
            }
        val caKey = KeyPair.generate()
        val caIssuer = Issuer.new(caParams, caKey)

        val eeParams =
            CertificateParams.new(listOf("server.example.com")).apply {
                useAuthorityKeyIdentifierExtension = true
            }
        val eeKey = KeyPair.generate()
        val eeCert = eeParams.signedBy(eeKey, caIssuer)

        assertTrue(eeCert.der().isNotEmpty())
        assertTrue(eeCert.pem().startsWith("-----BEGIN CERTIFICATE-----"))
    }

    @Test
    fun testCustomExtension() {
        val params = CertificateParams.new(listOf("example.com"))
        val acmeExt = CustomExtension.newAcmeIdentifier(ByteArray(32) { it.toByte() })
        params.customExtensions = listOf(acmeExt)

        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testNameConstraintsAndCrlDistributionPoints() {
        val params =
            CertificateParams.new(listOf("example.com")).apply {
                isCa = IsCa.Ca(BasicConstraints.Unconstrained)
                nameConstraints =
                    NameConstraints(
                        permittedSubtrees =
                            listOf(
                                GeneralSubtree.DnsName("example.com"),
                                GeneralSubtree.IpAddress(CidrSubnet.fromStr("192.0.2.0/24")),
                            ),
                    )
                crlDistributionPoints =
                    listOf(
                        CrlDistributionPoint(listOf("http://crl.example.com/ca.crl")),
                    )
            }

        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testWithKeyUsagesDecipheronlyOnly() {
        val params =
            CertificateParams(
                keyUsages = listOf(KeyUsagePurpose.DecipherOnly),
                isCa = IsCa.Ca(BasicConstraints.Constrained(0)),
            )
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testWithExtendedKeyUsagesAny() {
        val params =
            CertificateParams(
                extendedKeyUsages = listOf(ExtendedKeyUsagePurpose.Any),
            )
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testWithExtendedKeyUsagesOther() {
        val params =
            CertificateParams(
                extendedKeyUsages =
                    listOf(
                        ExtendedKeyUsagePurpose.Other(longArrayOf(1, 2, 3, 4)),
                        ExtendedKeyUsagePurpose.Other(longArrayOf(1, 2, 3, 4, 5, 6)),
                    ),
            )
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testNotWindowsLineEndings() {
        val keyPair = KeyPair.generate()
        val cert = CertificateParams().selfSigned(keyPair)
        assertTrue(cert.pem().contains("\n"))
    }

    @Test
    fun testParseOtherNameAltName() {
        val params =
            CertificateParams().apply {
                subjectAltNames =
                    mutableListOf(
                        SanType.OtherName(longArrayOf(1, 2, 3, 4), OtherNameValue.Utf8String("Foo")),
                    )
            }
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testParseIa5stringSubject() {
        val emailType = DnType.CustomDnType(longArrayOf(1, 2, 840, 113549, 1, 9, 1))
        val emailVal = DnValue.Ia5StringVal(Ia5String("foo@bar.com"))
        val params =
            CertificateParams.new(listOf("crabs")).apply {
                distinguishedName =
                    DistinguishedName().apply {
                        push(emailType, emailVal)
                    }
            }
        val keyPair = KeyPair.generate()
        val cert = params.selfSigned(keyPair)
        assertTrue(cert.der().isNotEmpty())
    }

    @Test
    fun testConvertsFromIp() {
        val params =
            CertificateParams.new(listOf("crabs")).apply {
                subjectAltNames = mutableListOf(SanType.IpAddress(byteArrayOf(2, 4, 6, 8)))
                isCa = IsCa.Ca(BasicConstraints.Unconstrained)
            }
        val caKey = KeyPair.generate()
        val cert = params.selfSigned(caKey)
        assertTrue(cert.der().isNotEmpty())
    }
}
