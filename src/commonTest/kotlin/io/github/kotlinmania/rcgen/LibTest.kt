// port-lint: tests rcgen/src/lib.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class LibTest {
    @Test
    fun testGenerateSimpleSelfSigned() {
        val subjectAltNames = listOf("hello.world.example", "localhost")
        val certifiedKey = generateSimpleSelfSigned(subjectAltNames)

        assertNotNull(certifiedKey.cert)
        assertNotNull(certifiedKey.signingKey)
        assertTrue(certifiedKey.cert.pem().contains("BEGIN CERTIFICATE"))
        assertTrue(certifiedKey.signingKey.serializePem().contains("BEGIN PRIVATE KEY"))
    }

    @Test
    fun testCertifiedIssuer() {
        val caParams =
            CertificateParams.new(listOf("ca.example.com")).apply {
                isCa = IsCa.Ca(BasicConstraints.Unconstrained)
                keyUsages = mutableListOf(KeyUsagePurpose.KeyCertSign, KeyUsagePurpose.CrlSign)
            }
        val caKey = KeyPair.generate()
        val certifiedIssuer = CertifiedIssuer.selfSigned(caParams, caKey)

        assertTrue(certifiedIssuer.pem().contains("BEGIN CERTIFICATE"))
        assertTrue(certifiedIssuer.der().isNotEmpty())
    }

    @Test
    fun testSignatureAlgosDifferent() {
        val algs = SignatureAlgorithm.iter()
        for (i in algs.indices) {
            for (j in algs.indices) {
                kotlin.test.assertEquals(i == j, algs[i] == algs[j], "Mismatch for pair $i and $j")
            }
        }
    }
}
