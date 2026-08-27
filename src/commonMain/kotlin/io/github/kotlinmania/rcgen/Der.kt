// port-lint: source rcgen/src/lib.rs
package io.github.kotlinmania.rcgen

import kotlinx.datetime.TimeZone
import kotlinx.datetime.toLocalDateTime
import kotlin.time.Instant

/**
 * ASN.1 DER Tag constants.
 */
public object Asn1Tag {
    public const val BOOLEAN: Int = 0x01
    public const val INTEGER: Int = 0x02
    public const val BIT_STRING: Int = 0x03
    public const val OCTET_STRING: Int = 0x04
    public const val NULL: Int = 0x05
    public const val OBJECT_IDENTIFIER: Int = 0x06
    public const val UTF8_STRING: Int = 0x0C
    public const val PRINTABLE_STRING: Int = 0x13
    public const val TELETEX_STRING: Int = 0x14
    public const val IA5_STRING: Int = 0x16
    public const val UTC_TIME: Int = 0x17
    public const val GENERALIZED_TIME: Int = 0x18
    public const val UNIVERSAL_STRING: Int = 0x1C
    public const val BMP_STRING: Int = 0x1E
    public const val SEQUENCE: Int = 0x30
    public const val SET: Int = 0x31
    public const val CONSTRUCTED: Int = 0x20
    public const val CONTEXT_SPECIFIC: Int = 0x80

    public fun contextExplicit(tagNumber: Int): Int = CONTEXT_SPECIFIC or CONSTRUCTED or tagNumber

    public fun contextImplicit(tagNumber: Int, constructed: Boolean = false): Int =
        CONTEXT_SPECIFIC or (if (constructed) CONSTRUCTED else 0) or tagNumber
}

/**
 * ASN.1 DER Writer.
 */
public open class DerWriter internal constructor(
    private val buffer: MutableList<Byte>,
) {
    public constructor() : this(mutableListOf())

    public fun toByteArray(): ByteArray = buffer.toByteArray()

    public open fun writeRaw(bytes: ByteArray) {
        for (b in bytes) buffer.add(b)
    }

    public open fun writeTlv(tag: Int, value: ByteArray) {
        buffer.add((tag and 0xFF).toByte())
        encodeLength(value.size)
        writeRaw(value)
    }

    private fun encodeLength(length: Int) {
        if (length < 128) {
            buffer.add(length.toByte())
        } else if (length <= 0xFF) {
            buffer.add(0x81.toByte())
            buffer.add(length.toByte())
        } else if (length <= 0xFFFF) {
            buffer.add(0x82.toByte())
            buffer.add(((length ushr 8) and 0xFF).toByte())
            buffer.add((length and 0xFF).toByte())
        } else if (length <= 0xFFFFFF) {
            buffer.add(0x83.toByte())
            buffer.add(((length ushr 16) and 0xFF).toByte())
            buffer.add(((length ushr 8) and 0xFF).toByte())
            buffer.add((length and 0xFF).toByte())
        } else {
            buffer.add(0x84.toByte())
            buffer.add(((length ushr 24) and 0xFF).toByte())
            buffer.add(((length ushr 16) and 0xFF).toByte())
            buffer.add(((length ushr 8) and 0xFF).toByte())
            buffer.add((length and 0xFF).toByte())
        }
    }

    public open fun writeSequence(block: DerWriterSeq.() -> Unit) {
        val seq = DerWriterSeq()
        seq.block()
        writeTlv(Asn1Tag.SEQUENCE, seq.toByteArray())
    }

    public open fun writeSet(block: DerWriterSeq.() -> Unit) {
        val seq = DerWriterSeq()
        seq.block()
        writeTlv(Asn1Tag.SET, seq.toByteArray())
    }

    public open fun writeTagged(tagNumber: Int, block: (DerWriter) -> Unit) {
        val writer = DerWriter()
        block(writer)
        writeTlv(Asn1Tag.contextExplicit(tagNumber), writer.toByteArray())
    }

    public open fun writeTaggedImplicit(tagNumber: Int, block: (DerWriter) -> Unit) {
        val writer = DerWriter()
        block(writer)
        writeTlv(Asn1Tag.contextImplicit(tagNumber, constructed = false), writer.toByteArray())
    }

    public open fun writeTaggedImplicitConstructed(tagNumber: Int, block: (DerWriter) -> Unit) {
        val writer = DerWriter()
        block(writer)
        writeTlv(Asn1Tag.contextImplicit(tagNumber, constructed = true), writer.toByteArray())
    }

    public open fun writeBool(value: Boolean) {
        writeTlv(Asn1Tag.BOOLEAN, byteArrayOf(if (value) 0xFF.toByte() else 0x00.toByte()))
    }

    public open fun writeBoolean(value: Boolean) {
        writeBool(value)
    }

    public open fun writeNull() {
        writeTlv(Asn1Tag.NULL, byteArrayOf())
    }

    public open fun writeInteger(value: Long) {
        var v = value
        val bytes = mutableListOf<Byte>()
        if (v == 0L) {
            bytes.add(0)
        } else {
            while (v != 0L && v != -1L) {
                bytes.add((v and 0xFF).toByte())
                v = v shr 8
            }
            if (value > 0 && (bytes.last().toInt() and 0x80) != 0) {
                bytes.add(0)
            } else if (value < 0 && (bytes.last().toInt() and 0x80) == 0) {
                bytes.add(0xFF.toByte())
            }
            bytes.reverse()
        }
        writeTlv(Asn1Tag.INTEGER, bytes.toByteArray())
    }

    public open fun writeEnum(value: Long) {
        writeInteger(value)
    }

    public open fun writeBigIntBytes(bytes: ByteArray, positive: Boolean = true) {
        var start = 0
        while (start < bytes.size - 1 && bytes[start] == 0.toByte()) {
            start++
        }
        val trimmed = bytes.copyOfRange(start, bytes.size)
        val finalBytes =
            if (positive && trimmed.isNotEmpty() && (trimmed[0].toInt() and 0x80) != 0) {
                byteArrayOf(0) + trimmed
            } else if (trimmed.isEmpty()) {
                byteArrayOf(0)
            } else {
                trimmed
            }
        writeTlv(Asn1Tag.INTEGER, finalBytes)
    }

    public open fun writeBytes(bytes: ByteArray) {
        writeTlv(Asn1Tag.OCTET_STRING, bytes)
    }

    public open fun writeBitString(bytes: ByteArray, unusedBits: Int = 0) {
        val payload = ByteArray(bytes.size + 1)
        payload[0] = unusedBits.toByte()
        bytes.copyInto(payload, 1)
        writeTlv(Asn1Tag.BIT_STRING, payload)
    }

    public open fun writeOid(oid: LongArray) {
        require(oid.size >= 2) { "OID must have at least 2 components" }
        val out = mutableListOf<Byte>()
        val first = oid[0] * 40 + oid[1]
        encodeOidComponent(first, out)
        for (i in 2 until oid.size) {
            encodeOidComponent(oid[i], out)
        }
        writeTlv(Asn1Tag.OBJECT_IDENTIFIER, out.toByteArray())
    }

    private fun encodeOidComponent(v: Long, out: MutableList<Byte>) {
        if (v == 0L) {
            out.add(0)
            return
        }
        val parts = mutableListOf<Byte>()
        var cur = v
        parts.add((cur and 0x7F).toByte())
        cur = cur ushr 7
        while (cur > 0) {
            parts.add(((cur and 0x7F) or 0x80).toByte())
            cur = cur ushr 7
        }
        parts.reverse()
        out.addAll(parts)
    }

    public open fun writeUtf8String(s: String) {
        writeTlv(Asn1Tag.UTF8_STRING, s.encodeToByteArray())
    }

    public open fun writePrintableString(s: String) {
        writeTlv(Asn1Tag.PRINTABLE_STRING, s.encodeToByteArray())
    }

    public open fun writeIa5String(s: String) {
        writeTlv(Asn1Tag.IA5_STRING, s.encodeToByteArray())
    }

    public open fun writeUtcTime(str: String) {
        writeTlv(Asn1Tag.UTC_TIME, str.encodeToByteArray())
    }

    public open fun writeUtcTime(instant: Instant) {
        val ldt = instant.toLocalDateTime(TimeZone.UTC)
        val yy = (ldt.year % 100).toString().padStart(2, '0')
        val mm = (ldt.month.ordinal + 1).toString().padStart(2, '0')
        val dd = ldt.day.toString().padStart(2, '0')
        val hh = ldt.hour.toString().padStart(2, '0')
        val min = ldt.minute.toString().padStart(2, '0')
        val ss = ldt.second.toString().padStart(2, '0')
        val str = "$yy$mm$dd$hh$min${ss}Z"
        writeUtcTime(str)
    }

    public open fun writeGeneralizedTime(str: String) {
        writeTlv(Asn1Tag.GENERALIZED_TIME, str.encodeToByteArray())
    }

    public open fun writeGeneralizedTime(instant: Instant) {
        val ldt = instant.toLocalDateTime(TimeZone.UTC)
        val yyyy = ldt.year.toString().padStart(4, '0')
        val mm = (ldt.month.ordinal + 1).toString().padStart(2, '0')
        val dd = ldt.day.toString().padStart(2, '0')
        val hh = ldt.hour.toString().padStart(2, '0')
        val min = ldt.minute.toString().padStart(2, '0')
        val ss = ldt.second.toString().padStart(2, '0')
        val str = "$yyyy$mm$dd$hh$min${ss}Z"
        writeGeneralizedTime(str)
    }

    public open fun writeDer(bytes: ByteArray) {
        writeRaw(bytes)
    }

    public fun next(): DerWriter = this

    public companion object {
        public fun constructDer(block: (DerWriter) -> Unit): ByteArray {
            val writer = DerWriter()
            block(writer)
            return writer.toByteArray()
        }
    }
}

/**
 * ASN.1 DER sequence writer helper.
 */
public class DerWriterSeq internal constructor(
    private val buffer: MutableList<Byte>,
) {
    public constructor() : this(mutableListOf())

    public fun toByteArray(): ByteArray = buffer.toByteArray()

    public fun next(): DerWriter = DerWriter(buffer)
}

/**
 * ASN.1 DER Element representing a parsed TLV structure.
 */
public class DerElement(
    public val tag: Int,
    public val rawBytes: ByteArray,
    public val content: ByteArray,
) {
    public val isConstructed: Boolean get() = (tag and Asn1Tag.CONSTRUCTED) != 0

    public fun asSequence(): List<DerElement> {
        val elements = mutableListOf<DerElement>()
        var offset = 0
        while (offset < content.size) {
            val element = DerReader.parseElement(content, offset)
            elements.add(element)
            offset += element.rawBytes.size
        }
        return elements
    }

    public fun asSet(): List<DerElement> = asSequence()

    public fun asString(): String = content.decodeToString()

    public fun asOid(): LongArray {
        require(tag == Asn1Tag.OBJECT_IDENTIFIER) { "Not an OID" }
        return DerReader.decodeOid(content)
    }

    public fun asInteger(): Long {
        require(tag == Asn1Tag.INTEGER) { "Not an INTEGER" }
        return DerReader.decodeInteger(content)
    }

    public fun asBitString(): ByteArray {
        require(tag == Asn1Tag.BIT_STRING) { "Not a BIT STRING" }
        require(content.isNotEmpty()) { "Empty BIT STRING" }
        return content.copyOfRange(1, content.size)
    }

    public fun asOctetString(): ByteArray {
        require(tag == Asn1Tag.OCTET_STRING) { "Not an OCTET STRING" }
        return content.copyOf()
    }
}

/**
 * ASN.1 DER Reader.
 */
public object DerReader {
    public fun parseElement(bytes: ByteArray, offset: Int = 0): DerElement {
        require(offset < bytes.size) { "Unexpected end of input" }
        val tag = bytes[offset].toInt() and 0xFF
        var idx = offset + 1

        require(idx < bytes.size) { "Unexpected end of input reading length" }
        val firstLen = bytes[idx].toInt() and 0xFF
        idx++

        val length: Int
        if (firstLen < 128) {
            length = firstLen
        } else {
            val numBytes = firstLen and 0x7F
            require(numBytes <= 4) { "Length too large: $numBytes bytes" }
            require(idx + numBytes <= bytes.size) { "Unexpected end of input reading long length" }
            var len = 0
            for (i in 0 until numBytes) {
                len = (len shl 8) or (bytes[idx].toInt() and 0xFF)
                idx++
            }
            length = len
        }

        require(idx + length <= bytes.size) { "Length $length exceeds remaining bytes (${bytes.size - idx})" }
        val rawBytes = bytes.copyOfRange(offset, idx + length)
        val content = bytes.copyOfRange(idx, idx + length)

        return DerElement(tag, rawBytes, content)
    }

    public fun decodeOid(bytes: ByteArray): LongArray {
        require(bytes.isNotEmpty()) { "Empty OID content" }
        val result = mutableListOf<Long>()
        val first = bytes[0].toLong() and 0xFF
        result.add(first / 40)
        result.add(first % 40)

        var cur = 0L
        for (i in 1 until bytes.size) {
            val b = bytes[i].toLong() and 0xFF
            cur = (cur shl 7) or (b and 0x7F)
            if ((b and 0x80L) == 0L) {
                result.add(cur)
                cur = 0L
            }
        }
        return result.toLongArray()
    }

    public fun decodeInteger(bytes: ByteArray): Long {
        require(bytes.isNotEmpty()) { "Empty integer content" }
        var result = if ((bytes[0].toInt() and 0x80) != 0) -1L else 0L
        for (b in bytes) {
            result = (result shl 8) or (b.toLong() and 0xFF)
        }
        return result
    }
}
