import Testing
import Rcgen

@Suite("Rcgen Swift Export Smoke Tests")
struct RcgenExportTests {
    @Test("Rcgen swift module imports cleanly")
    func swiftModuleLoads() {
        #expect(Bool(true))
    }

    @Test("Rcgen exported types instantiate cleanly")
    func exportedTypesInstantiate() {
        let keyPair = KeyPair.Companion.shared.generate()
        #expect(keyPair.algorithm() == SignatureAlgorithm.Companion.shared.PKCS_ECDSA_P256_SHA256)
    }
}
