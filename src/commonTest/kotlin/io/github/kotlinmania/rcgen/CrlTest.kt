// port-lint: tests crl.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertTrue

class CrlTest {
    @Test
    fun testGenerateCrl() {
        val issuerParams =
            CertificateParams.new(listOf("crl.issuer.example.com")).apply {
                serialNumber = SerialNumber.from(9999)
                isCa = IsCa.Ca(BasicConstraints.Unconstrained)
                keyUsages = mutableListOf(KeyUsagePurpose.KeyCertSign, KeyUsagePurpose.DigitalSignature, KeyUsagePurpose.CrlSign)
            }
        val keyPair = KeyPair.generate()
        val issuer = Issuer.new(issuerParams, keyPair)

        val revokedCert =
            RevokedCertParams(
                serialNumber = SerialNumber.from(9999),
                revocationTime = dateTimeYmd(2024, 6, 17),
                reasonCode = RevocationReason.KeyCompromise,
                invalidityDate = null,
            )

        val crlParams =
            CertificateRevocationListParams(
                thisUpdate = dateTimeYmd(2023, 6, 17),
                nextUpdate = dateTimeYmd(2024, 6, 17),
                crlNumber = SerialNumber.from(1234),
                issuingDistributionPoint = null,
                revokedCerts = listOf(revokedCert),
            )

        val crl = crlParams.signedBy(issuer)
        assertTrue(crl.der().isNotEmpty())
        val pem = crl.pem()
        assertTrue(pem.startsWith("-----BEGIN X509 CRL-----"))
        assertTrue(pem.endsWith("-----END X509 CRL-----\n"))
    }
}
