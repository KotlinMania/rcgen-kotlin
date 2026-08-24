// port-lint: tests key_pair.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class KeyPairTest {
    @Test
    fun testGenerateAndSerialize() {
        val kp = KeyPair.generate()
        assertEquals(SignatureAlgorithm.PKCS_ECDSA_P256_SHA256, kp.algorithm())
        assertTrue(kp.derBytes().isNotEmpty())
        assertTrue(kp.serializeDer().isNotEmpty())

        val pem = kp.serializePem()
        assertTrue(pem.startsWith("-----BEGIN PRIVATE KEY-----"))
        assertTrue(pem.endsWith("-----END PRIVATE KEY-----\n"))

        val pubPem = kp.publicKeyPem()
        assertTrue(pubPem.startsWith("-----BEGIN PUBLIC KEY-----"))
        assertTrue(pubPem.endsWith("-----END PUBLIC KEY-----\n"))
    }

    @Test
    fun testSubjectPublicKeyInfoFromPemAndDer() {
        for (alg in listOf(
            SignatureAlgorithm.PKCS_ED25519,
            SignatureAlgorithm.PKCS_ECDSA_P256_SHA256,
            SignatureAlgorithm.PKCS_ECDSA_P384_SHA384,
            SignatureAlgorithm.PKCS_RSA_SHA256,
        )) {
            val kp = KeyPair.generateFor(alg)
            val pem = kp.publicKeyPem()
            val der = kp.subjectPublicKeyInfo()

            val spkiPem = SubjectPublicKeyInfo.fromPem(pem)
            assertTrue(kp.derBytes().contentEquals(spkiPem.derBytes()))

            val spkiDer = SubjectPublicKeyInfo.fromDer(der)
            assertTrue(kp.derBytes().contentEquals(spkiDer.derBytes()))
        }
    }

    @Test
    fun testSigning() {
        val kp = KeyPair.generate()
        val msg = "Test message to sign".encodeToByteArray()
        val sig = kp.sign(msg)
        assertTrue(sig.isNotEmpty())
    }
}
