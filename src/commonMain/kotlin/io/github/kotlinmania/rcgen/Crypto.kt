package io.github.kotlinmania.rcgen

import kotlin.random.Random

/**
 * Pure Kotlin multiplatform SHA-256 implementation.
 */
public object Sha256 {
    private val K =
        intArrayOf(
            0x428a2f98.toInt(),
            0x71374491.toInt(),
            0xb5c0fbcf.toInt(),
            0xe9b5dba5.toInt(),
            0x3956c25b,
            0x59f111f1,
            0x923f82a4.toInt(),
            0xab1c5ed5.toInt(),
            0xd807aa98.toInt(),
            0x12835b01,
            0x243185be,
            0x550c7dc3,
            0x72be5d74,
            0x80deb1fe.toInt(),
            0x9bdc06a7.toInt(),
            0xc19bf174.toInt(),
            0xe49b69c1.toInt(),
            0xefbe4786.toInt(),
            0x0fc19dc6,
            0x240ca1cc,
            0x2de92c6f,
            0x4a7484aa,
            0x5cb0a9dc,
            0x76f988da,
            0x983e5152.toInt(),
            0xa831c66d.toInt(),
            0xb00327c8.toInt(),
            0xbf597fc7.toInt(),
            0xc6e00bf3.toInt(),
            0xd5a79147.toInt(),
            0x06ca6351,
            0x14292967,
            0x27b70a85,
            0x2e1b2138,
            0x4d2c6dfc,
            0x53380d13,
            0x650a7354,
            0x766a0abb,
            0x81c2c92e.toInt(),
            0x92722c85.toInt(),
            0xa2bfe8a1.toInt(),
            0xa81a664b.toInt(),
            0xc24b8b70.toInt(),
            0xc76c51a3.toInt(),
            0xd192e819.toInt(),
            0xd6990624.toInt(),
            0xf40e3585.toInt(),
            0x106aa070,
            0x19a4c116,
            0x1e376c08,
            0x2748774c,
            0x34b0bcb5,
            0x391c0cb3,
            0x4ed8aa4a,
            0x5b9cca4f,
            0x682e6ff3,
            0x748f82ee,
            0x78a5636f,
            0x84c87814.toInt(),
            0x8cc70208.toInt(),
            0x90befffa.toInt(),
            0xa4506ceb.toInt(),
            0xbef9a3f7.toInt(),
            0xc67178f2.toInt(),
        )

    public fun digest(data: ByteArray): ByteArray {
        var h0 = 0x6a09e667
        var h1 = 0xbb67ae85.toInt()
        var h2 = 0x3c6ef372
        var h3 = 0xa54ff53a.toInt()
        var h4 = 0x510e527f
        var h5 = 0x9b05688c.toInt()
        var h6 = 0x1f83d9ab
        var h7 = 0x5be0cd19

        val messageLenBits = data.size.toLong() * 8L
        val tailLen = (data.size + 9) % 64
        val padLen = if (tailLen == 0) 0 else 64 - tailLen
        val totalLen = data.size + 1 + padLen + 8
        val padded = ByteArray(totalLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()

        for (i in 0 until 8) {
            padded[totalLen - 1 - i] = ((messageLenBits ushr (i * 8)) and 0xFF).toByte()
        }

        val w = IntArray(64)
        for (chunk in 0 until totalLen step 64) {
            for (i in 0 until 16) {
                val idx = chunk + i * 4
                w[i] = ((padded[idx].toInt() and 0xFF) shl 24) or
                    ((padded[idx + 1].toInt() and 0xFF) shl 16) or
                    ((padded[idx + 2].toInt() and 0xFF) shl 8) or
                    (padded[idx + 3].toInt() and 0xFF)
            }
            for (i in 16 until 64) {
                val s0 =
                    (w[i - 15] ushr 7 or (w[i - 15] shl 25)) xor
                        (w[i - 15] ushr 18 or (w[i - 15] shl 14)) xor
                        (w[i - 15] ushr 3)
                val s1 =
                    (w[i - 2] ushr 17 or (w[i - 2] shl 15)) xor
                        (w[i - 2] ushr 19 or (w[i - 2] shl 13)) xor
                        (w[i - 2] ushr 10)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            var f = h5
            var g = h6
            var h = h7

            for (i in 0 until 64) {
                val s1 = (e ushr 6 or (e shl 26)) xor (e ushr 11 or (e shl 21)) xor (e ushr 25 or (e shl 7))
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = h + s1 + ch + K[i] + w[i]
                val s0 = (a ushr 2 or (a shl 30)) xor (a ushr 13 or (a shl 19)) xor (a ushr 22 or (a shl 10))
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                h = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            h5 += f
            h6 += g
            h7 += h
        }

        val result = ByteArray(32)
        val hVals = intArrayOf(h0, h1, h2, h3, h4, h5, h6, h7)
        for (i in 0 until 8) {
            val v = hVals[i]
            result[i * 4] = ((v ushr 24) and 0xFF).toByte()
            result[i * 4 + 1] = ((v ushr 16) and 0xFF).toByte()
            result[i * 4 + 2] = ((v ushr 8) and 0xFF).toByte()
            result[i * 4 + 3] = (v and 0xFF).toByte()
        }
        return result
    }
}

/**
 * Pure Kotlin multiplatform SHA-512 and SHA-384 implementation.
 */
public object Sha512 {
    private val K =
        longArrayOf(
            0x428a2f98d728f277L,
            0x7137449123ef65cdL,
            -0x4a3f0430164a0431L,
            -0x164a245a491ef25bL,
            0x3956c25bf348b538L,
            0x59f111f1b605d019L,
            -0x6dc07d5b4cb465bbL,
            -0x54e3a12aa9e7350bL,
            -0x27f85567aa1439ccL,
            0x12835b0145706fbeL,
            0x243185be4ee4b28cL,
            0x550c7dc3d5ffb4e2L,
            0x72be5d74f27b896fL,
            -0x7f214e010d86927aL,
            -0x6423f9588b5ecf01L,
            -0x3e640e8b15d2a900L,
            -0x1b64963e635f1140L,
            -0x1041b87989931fc4L,
            0x0fc19dc68b8cd5b5L,
            0x240ca1cc77ac9c65L,
            0x2de92c6f592b0275L,
            0x4a7484aa6ea6e483L,
            0x5cb0a9dcbd41fbd4L,
            0x76f988da831153b5L,
            -0x67c1aeadaa24a520L,
            -0x57ce39922a6ee5ffL,
            -0x4ffcd8373b9e4a86L,
            -0x40a680387cd87413L,
            -0x391f440c49ffb19aL,
            -0x2a586eb8c8b67119L,
            0x06ca6351e003826fL,
            0x142929670a0e6e70L,
            0x27b70a8546d22ffcL,
            0x2e1b21385c26c926L,
            0x4d2c6dfc5ac42aedL,
            0x53380d139d95b3dfL,
            0x650a73548baf63deL,
            0x766a0abb3c77b2a8L,
            -0x7e3d36d10f85f810L,
            -0x6d8dd37a50ca797bL,
            -0x5d40175e1a3bc6e0L,
            -0x57e599b4566f103bL,
            -0x3db4748f3b1451f2L,
            -0x3893ae5c3639be5dL,
            -0x2e6d17e63478d107L,
            -0x2966f9db195b4cb8L,
            -0x0bf1ca7a20c920f7L,
            0x106aa07032bbd1a3L,
            0x19a4c116b8d2d0c8L,
            0x1e376c085141ab53L,
            0x2748774cdf8eeb99L,
            0x34b0bcb5e19b48a8L,
            0x391c0cb3c5c95a63L,
            0x4ed8aa4ae3418acbL,
            0x5b9cca4f7763e373L,
            0x682e6ff3d6b2b8a3L,
            0x748f82ee5defb2fcL,
            0x78a5636f43172f60L,
            -0x7b3787eb77353f4cL,
            -0x7338fd67417e8cdaL,
            -0x6f4100052ebf3970L,
            -0x5baf93149d82121dL,
            -0x41065c0819230559L,
            -0x398e870d0611be2eL,
            -0x341a9bf7b47b2c0fL,
            -0x2f90aa0b9859fbf6L,
            -0x238e1f29235e26b4L,
            -0x1a8f9a2d8a43fe97L,
            -0x12a80630bba908dbL,
            -0x0b8a361a9ab4458fL,
            0x0fc4107d83415e96L,
            0x1844f2d72111c1c6L,
            0x2e1b12b509ef4883L,
            0x4f82e6802e3b4d63L,
            0x5d10d606104c0910L,
            0x65672a088804c76eL,
            0x76f4ae30a4506cebL,
            -0x6e9f653459c5d2b7L,
            -0x5df57c0e25d2b2cdL,
            -0x550074b201a0be43L,
        )

    public fun digestSha512(data: ByteArray): ByteArray =
        process(
            data,
            longArrayOf(
                0x6a09e667f3bcc908L,
                -0x4453361b222bb2bcL,
                0x3c6ef372fe94f82bL,
                -0x5ab00ac56474900aL,
                0x510e527fade682d1L,
                -0x64fa9773754e3a47L,
                0x1f83d9abfb41bd6bL,
                0x5be0cd19137e2179L,
            ),
            64,
        )

    public fun digestSha384(data: ByteArray): ByteArray =
        process(
            data,
            longArrayOf(
                -0x33444ab060410471L,
                0x629a292a367cd507L,
                -0x6e7889e13fe74121L,
                0x152fecd8f70e593fL,
                0x67332667ffc00b31L,
                -0x714bb5c102c77d54L,
                -0x246b0a1d6365f543L,
                0x47b5481dbefa4fa4L,
            ),
            48,
        )

    private fun process(data: ByteArray, initialH: LongArray, outputLen: Int): ByteArray {
        var h0 = initialH[0]
        var h1 = initialH[1]
        var h2 = initialH[2]
        var h3 = initialH[3]
        var h4 = initialH[4]
        var h5 = initialH[5]
        var h6 = initialH[6]
        var h7 = initialH[7]

        val messageLenBits = data.size.toLong() * 8L
        val tailLen = (data.size + 17) % 128
        val padLen = if (tailLen == 0) 0 else 128 - tailLen
        val totalLen = data.size + 1 + padLen + 16
        val padded = ByteArray(totalLen)
        data.copyInto(padded)
        padded[data.size] = 0x80.toByte()

        for (i in 0 until 8) {
            padded[totalLen - 1 - i] = ((messageLenBits ushr (i * 8)) and 0xFF).toByte()
        }

        val w = LongArray(80)
        for (chunk in 0 until totalLen step 128) {
            for (i in 0 until 16) {
                val idx = chunk + i * 8
                var v = 0L
                for (b in 0 until 8) {
                    v = (v shl 8) or (padded[idx + b].toLong() and 0xFF)
                }
                w[i] = v
            }
            for (i in 16 until 80) {
                val s0 = rotR(w[i - 15], 1) xor rotR(w[i - 15], 8) xor (w[i - 15] ushr 7)
                val s1 = rotR(w[i - 2], 19) xor rotR(w[i - 2], 61) xor (w[i - 2] ushr 6)
                w[i] = w[i - 16] + s0 + w[i - 7] + s1
            }

            var a = h0
            var b = h1
            var c = h2
            var d = h3
            var e = h4
            var f = h5
            var g = h6
            var h = h7

            for (i in 0 until 80) {
                val s1 = rotR(e, 14) xor rotR(e, 18) xor rotR(e, 41)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = h + s1 + ch + K[i] + w[i]
                val s0 = rotR(a, 28) xor rotR(a, 34) xor rotR(a, 39)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                h = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            h0 += a
            h1 += b
            h2 += c
            h3 += d
            h4 += e
            h5 += f
            h6 += g
            h7 += h
        }

        val result = ByteArray(outputLen)
        val hVals = longArrayOf(h0, h1, h2, h3, h4, h5, h6, h7)
        var outIdx = 0
        for (i in 0 until (outputLen / 8)) {
            val v = hVals[i]
            for (b in 7 downTo 0) {
                result[outIdx++] = ((v ushr (b * 8)) and 0xFF).toByte()
            }
        }
        return result
    }

    private fun rotR(v: Long, n: Int): Long = (v ushr n) or (v shl (64 - n))
}

/**
 * Random helper.
 */
public object CryptoRandom {
    public fun nextBytes(size: Int): ByteArray = Random.nextBytes(size)
}
