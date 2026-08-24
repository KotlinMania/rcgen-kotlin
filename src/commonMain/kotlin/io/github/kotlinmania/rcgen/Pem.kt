package io.github.kotlinmania.rcgen

import kotlin.io.encoding.Base64
import kotlin.io.encoding.ExperimentalEncodingApi

/**
 * PEM encoder and parser.
 */
public data class Pem(
    public val tag: String,
    public val contents: ByteArray,
) {
    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is Pem) return false
        return tag == other.tag && contents.contentEquals(other.contents)
    }

    override fun hashCode(): Int = 31 * tag.hashCode() + contents.contentHashCode()

    public companion object {
        @OptIn(ExperimentalEncodingApi::class)
        public fun encode(tag: String, contents: ByteArray): String {
            val b64 = Base64.encode(contents)
            val sb = StringBuilder()
            sb.append("-----BEGIN ").append(tag).append("-----\n")
            var idx = 0
            while (idx < b64.length) {
                val end = minOf(idx + 64, b64.length)
                sb.append(b64.substring(idx, end)).append("\n")
                idx = end
            }
            sb.append("-----END ").append(tag).append("-----\n")
            return sb.toString()
        }

        @OptIn(ExperimentalEncodingApi::class)
        public fun decode(pemStr: String): Pem {
            val startHeader = "-----BEGIN "
            val startIdx = pemStr.indexOf(startHeader)
            if (startIdx == -1) throw RcgenException.CouldNotParseCertificate("Missing BEGIN tag")
            val endHeaderIdx = pemStr.indexOf("-----", startIdx + startHeader.length)
            if (endHeaderIdx == -1) throw RcgenException.CouldNotParseCertificate("Invalid BEGIN line")
            val tag = pemStr.substring(startIdx + startHeader.length, endHeaderIdx)

            val endFooter = "-----END $tag-----"
            val footerIdx = pemStr.indexOf(endFooter, endHeaderIdx)
            if (footerIdx == -1) throw RcgenException.CouldNotParseCertificate("Missing END tag for $tag")

            val base64Content =
                pemStr
                    .substring(endHeaderIdx + 5, footerIdx)
                    .replace("\r", "")
                    .replace("\n", "")
                    .replace(" ", "")
                    .trim()

            val contents =
                try {
                    Base64.decode(base64Content)
                } catch (e: Throwable) {
                    throw RcgenException.CouldNotParseCertificate("Failed to decode base64: ${e.message}")
                }
            return Pem(tag, contents)
        }

        public fun parse(pemStr: String): Pair<String, ByteArray> {
            val pem = decode(pemStr)
            return Pair(pem.tag, pem.contents)
        }
    }
}
