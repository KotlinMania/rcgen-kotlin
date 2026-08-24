// port-lint: source string.rs
package io.github.kotlinmania.rcgen

/**
 * ASN.1 PrintableString type.
 *
 * Supports a subset of the ASCII printable characters:
 * A..Z, a..z, 0..9, space, ', (, ), +, ,, -, ., /, :, =, ?
 */
public class PrintableString(
    private val value: String,
) {
    init {
        if (!isValid(value)) {
            throw RcgenException.InvalidAsn1(InvalidAsn1String.PrintableString(value))
        }
    }

    public fun asString(): String = value

    public fun asStr(): String = value

    public fun asBytes(): ByteArray = value.encodeToByteArray()

    override fun equals(other: Any?): Boolean =
        when (other) {
            is PrintableString -> value == other.value
            is String -> value == other
            else -> false
        }

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value

    public companion object {
        private const val ALLOWED_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?"

        public fun isValid(s: String): Boolean {
            for (ch in s) {
                if (ch !in ALLOWED_CHARS) return false
            }
            return true
        }

        public fun tryFrom(value: String): PrintableString = PrintableString(value)

        public fun fromStr(value: String): PrintableString = PrintableString(value)
    }
}

/**
 * ASN.1 IA5String type.
 *
 * Supports the 128 characters of the ASCII alphabet (0x00..0x7F).
 */
public class Ia5String(
    private val value: String,
) {
    init {
        if (!isValid(value)) {
            throw RcgenException.InvalidAsn1(InvalidAsn1String.Ia5String(value))
        }
    }

    public fun asString(): String = value

    public fun asStr(): String = value

    public fun asBytes(): ByteArray = value.encodeToByteArray()

    override fun equals(other: Any?): Boolean =
        when (other) {
            is Ia5String -> value == other.value
            is String -> value == other
            else -> false
        }

    override fun hashCode(): Int = value.hashCode()

    override fun toString(): String = value

    public companion object {
        public fun isValid(s: String): Boolean {
            for (ch in s) {
                if (ch.code > 0x7F) return false
            }
            return true
        }

        public fun tryFrom(value: String): Ia5String = Ia5String(value)

        public fun fromStr(value: String): Ia5String = Ia5String(value)
    }
}

/**
 * ASN.1 TeletexString (T.61) type.
 */
public class TeletexString(
    private val bytes: ByteArray,
) {
    public constructor(str: String) : this(str.encodeToByteArray())

    public fun asBytes(): ByteArray = bytes.copyOf()

    public fun asString(): String = bytes.decodeToString()

    public fun asStr(): String = asString()

    override fun equals(other: Any?): Boolean =
        when (other) {
            is TeletexString -> bytes.contentEquals(other.bytes)
            is ByteArray -> bytes.contentEquals(other)
            else -> false
        }

    override fun hashCode(): Int = bytes.contentHashCode()

    override fun toString(): String = asString()

    public companion object {
        public fun tryFrom(str: String): TeletexString = TeletexString(str)

        public fun fromBytes(bytes: ByteArray): TeletexString = TeletexString(bytes)
    }
}

/**
 * ASN.1 BMPString (UCS-2 / UTF-16BE) type.
 */
public class BmpString(
    private val str: String,
) {
    private val bytes: ByteArray

    init {
        val out = ByteArray(str.length * 2)
        for (i in 0 until str.length) {
            val code = str[i].code
            if (code > 0xFFFF) {
                throw RcgenException.InvalidAsn1(InvalidAsn1String.BmpString(str))
            }
            out[i * 2] = ((code ushr 8) and 0xFF).toByte()
            out[i * 2 + 1] = (code and 0xFF).toByte()
        }
        this.bytes = out
    }

    public fun asBytes(): ByteArray = bytes.copyOf()

    public fun asString(): String = str

    public fun asStr(): String = str

    override fun equals(other: Any?): Boolean =
        when (other) {
            is BmpString -> str == other.str
            is String -> str == other
            else -> false
        }

    override fun hashCode(): Int = str.hashCode()

    override fun toString(): String = str

    public companion object {
        public fun fromUtf16be(bytes: ByteArray): BmpString {
            if (bytes.size % 2 != 0) {
                throw RcgenException.InvalidAsn1(InvalidAsn1String.BmpString(bytes.joinToString("") { it.toString(16) }))
            }
            val chars = CharArray(bytes.size / 2)
            for (i in chars.indices) {
                val hi = bytes[i * 2].toInt() and 0xFF
                val lo = bytes[i * 2 + 1].toInt() and 0xFF
                chars[i] = ((hi shl 8) or lo).toChar()
            }
            return BmpString(chars.concatToString())
        }
    }
}

/**
 * ASN.1 UniversalString (UTF-32BE) type.
 */
public class UniversalString(
    private val str: String,
) {
    private val bytes: ByteArray

    init {
        val out = mutableListOf<Byte>()
        var i = 0
        while (i < str.length) {
            val cp = str.codePointAt(i)
            out.add(((cp ushr 24) and 0xFF).toByte())
            out.add(((cp ushr 16) and 0xFF).toByte())
            out.add(((cp ushr 8) and 0xFF).toByte())
            out.add((cp and 0xFF).toByte())
            i += if (cp > 0xFFFF) 2 else 1
        }
        this.bytes = out.toByteArray()
    }

    public fun asBytes(): ByteArray = bytes.copyOf()

    public fun asString(): String = str

    public fun asStr(): String = str

    override fun equals(other: Any?): Boolean =
        when (other) {
            is UniversalString -> str == other.str
            is String -> str == other
            else -> false
        }

    override fun hashCode(): Int = str.hashCode()

    override fun toString(): String = str

    public companion object {
        public fun fromUtf32be(bytes: ByteArray): UniversalString {
            if (bytes.size % 4 != 0) {
                throw RcgenException.InvalidAsn1(InvalidAsn1String.UniversalString(bytes.joinToString("") { it.toString(16) }))
            }
            val sb = StringBuilder()
            var i = 0
            while (i < bytes.size) {
                val b0 = bytes[i].toInt() and 0xFF
                val b1 = bytes[i + 1].toInt() and 0xFF
                val b2 = bytes[i + 2].toInt() and 0xFF
                val b3 = bytes[i + 3].toInt() and 0xFF
                val cp = (b0 shl 24) or (b1 shl 16) or (b2 shl 8) or b3
                if (cp > 0x10FFFF) {
                    throw RcgenException.InvalidAsn1(InvalidAsn1String.UniversalString(cp.toString(16)))
                }
                sb.appendCodePoint(cp)
                i += 4
            }
            return UniversalString(sb.toString())
        }
    }
}

private fun String.codePointAt(index: Int): Int {
    val high = this[index]
    if (high.isHighSurrogate() && index + 1 < length) {
        val low = this[index + 1]
        if (low.isLowSurrogate()) {
            return (high.code - 0xD800) * 0x400 + (low.code - 0xDC00) + 0x10000
        }
    }
    return high.code
}

private fun StringBuilder.appendCodePoint(cp: Int): StringBuilder {
    if (cp <= 0xFFFF) {
        append(cp.toChar())
    } else {
        val high = ((cp - 0x10000) ushr 10) + 0xD800
        val low = ((cp - 0x10000) and 0x3FF) + 0xDC00
        append(high.toChar())
        append(low.toChar())
    }
    return this
}
