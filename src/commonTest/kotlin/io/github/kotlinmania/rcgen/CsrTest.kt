// port-lint: tests csr.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CsrTest {
    @Test
    fun testGenerateCsr() {
        val params =
            CertificateParams.new(listOf("csr.example.com")).apply {
                keyUsages = mutableListOf(KeyUsagePurpose.DigitalSignature)
            }
        val keyPair = KeyPair.generate()
        val csr = params.serializeRequest(keyPair)

        assertTrue(csr.der().isNotEmpty())
        val pem = csr.pem()
        assertTrue(pem.startsWith("-----BEGIN CERTIFICATE REQUEST-----"))
        assertTrue(pem.endsWith("-----END CERTIFICATE REQUEST-----\n"))

        val parsed = CertificateSigningRequestParams.fromPem(pem)
        assertEquals(keyPair.algorithm(), parsed.publicKey.algorithm())
    }

    @Test
    fun testDontWriteSansExtensionIfNoSansArePresent() {
        val params =
            CertificateParams().apply {
                keyUsages = mutableListOf(KeyUsagePurpose.DigitalSignature)
            }
        val keyPair = KeyPair.generate()
        val csr = params.serializeRequest(keyPair)
        assertTrue(csr.der().isNotEmpty())
    }

    @Test
    fun testWriteExtensionRequestIfEkusArePresent() {
        val params =
            CertificateParams().apply {
                extendedKeyUsages = mutableListOf(ExtendedKeyUsagePurpose.ClientAuth)
            }
        val keyPair = KeyPair.generate()
        val csr = params.serializeRequest(keyPair)
        assertTrue(csr.der().isNotEmpty())
    }
}
