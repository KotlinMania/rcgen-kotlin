// port-lint: tests sign_algo.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class SignAlgoTest {
    @Test
    fun testSignatureAlgorithmsDifferent() {
        val algs = SignatureAlgorithm.iter()
        for (i in algs.indices) {
            for (j in algs.indices) {
                assertEquals(i == j, algs[i] == algs[j], "Mismatch for index pair $i and $j")
            }
        }
    }

    @Test
    fun testFromOid() {
        val algo = SignatureAlgorithm.fromOid(Oid.SHA256_WITH_RSA_ENCRYPTION)
        assertEquals(SignatureAlgorithm.PKCS_RSA_SHA256, algo)

        val ecAlgo = SignatureAlgorithm.fromOid(Oid.ECDSA_WITH_SHA256)
        assertEquals(SignatureAlgorithm.PKCS_ECDSA_P256_SHA256, ecAlgo)

        val edAlgo = SignatureAlgorithm.fromOid(Oid.ED25519)
        assertEquals(SignatureAlgorithm.PKCS_ED25519, edAlgo)
    }

    @Test
    fun testWriteAlgIdentAndOids() {
        val algo = SignatureAlgorithm.PKCS_ECDSA_P256_SHA256
        val der =
            DerWriter.constructDer { w ->
                algo.writeAlgIdent(w)
            }
        assertTrue(der.isNotEmpty())

        val spkiDer =
            DerWriter.constructDer { w ->
                algo.writeOidsSignAlg(w)
            }
        assertTrue(spkiDer.isNotEmpty())
    }
}
