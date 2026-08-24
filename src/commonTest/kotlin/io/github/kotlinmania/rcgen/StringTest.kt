// port-lint: tests string.rs
package io.github.kotlinmania.rcgen

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class StringTest {
    @Test
    fun testPrintableStringValid() {
        val s = "Hello World 123 '()+,-./:=?"
        val ps = PrintableString(s)
        assertEquals(s, ps.asStr())
        assertEquals(s, ps.toString())
        assertEquals(ps, PrintableString(s))
    }

    @Test
    fun testPrintableStringInvalid() {
        assertFailsWith<RcgenException.InvalidAsn1> {
            PrintableString("Hello\nWorld")
        }
        assertFailsWith<RcgenException.InvalidAsn1> {
            PrintableString("Hello@World")
        }
        assertFailsWith<RcgenException.InvalidAsn1> {
            PrintableString("Hello#World")
        }
    }

    @Test
    fun testIa5StringValid() {
        val s = "hello@world.com"
        val ia5 = Ia5String(s)
        assertEquals(s, ia5.asStr())
        assertEquals(s, ia5.toString())
        assertEquals(ia5, Ia5String(s))
    }

    @Test
    fun testIa5StringInvalid() {
        assertFailsWith<RcgenException.InvalidAsn1> {
            Ia5String("Hello\u0080World")
        }
    }

    @Test
    fun testPrintableString() {
        val example = "CertificateTemplate"
        val ps = PrintableString.tryFrom(example)
        assertEquals(example, ps.asStr())
        assertFailsWith<RcgenException.InvalidAsn1> { PrintableString.tryFrom("@") }
        assertFailsWith<RcgenException.InvalidAsn1> { PrintableString.tryFrom("*") }
    }

    @Test
    fun testIa5String() {
        val example = "CertificateTemplate"
        val ia5 = Ia5String.tryFrom(example)
        assertEquals(example, ia5.asStr())
        val valid = Ia5String.tryFrom("\u007F")
        assertEquals("\u007F", valid.asStr())
        assertFailsWith<RcgenException.InvalidAsn1> { Ia5String.tryFrom("\u008F") }
    }

    @Test
    fun testTeletextString() {
        val example = "CertificateTemplate"
        val ts = TeletexString.tryFrom(example)
        assertEquals(example, ts.asStr())
        val valid = Ia5String.tryFrom("\u007F")
        assertEquals("\u007F", valid.asStr())
        assertFailsWith<RcgenException.InvalidAsn1> { Ia5String.tryFrom("\u008F") }
    }

    @Test
    fun testBmpString() {
        val expectedBytes = byteArrayOf(
            0x00, 0x43, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69,
            0x00, 0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x54, 0x00, 0x65, 0x00, 0x6d,
            0x00, 0x70, 0x00, 0x6c, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65,
        )
        val example = "CertificateTemplate"
        val bs = BmpString(example)
        assertTrue(expectedBytes.contentEquals(bs.asBytes()))
        val valid = BmpString("\uFFFE")
        assertEquals("\uFFFE", valid.asStr())
        assertFailsWith<RcgenException.InvalidAsn1> { BmpString("\uFFFF") }
    }

    @Test
    fun testUniversalString() {
        val expectedBytes = byteArrayOf(
            0x00, 0x00, 0x00, 0x43, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x72, 0x00, 0x00,
            0x00, 0x74, 0x00, 0x00, 0x00, 0x69, 0x00, 0x00, 0x00, 0x66, 0x00, 0x00, 0x00, 0x69,
            0x00, 0x00, 0x00, 0x63, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00, 0x00, 0x74, 0x00, 0x00,
            0x00, 0x65, 0x00, 0x00, 0x00, 0x54, 0x00, 0x00, 0x00, 0x65, 0x00, 0x00, 0x00, 0x6d,
            0x00, 0x00, 0x00, 0x70, 0x00, 0x00, 0x00, 0x6c, 0x00, 0x00, 0x00, 0x61, 0x00, 0x00,
            0x00, 0x74, 0x00, 0x00, 0x00, 0x65,
        )
        val example = "CertificateTemplate"
        val us = UniversalString(example)
        assertTrue(expectedBytes.contentEquals(us.asBytes()))
    }
}
