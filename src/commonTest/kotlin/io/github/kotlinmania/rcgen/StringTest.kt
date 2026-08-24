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
    fun testTeletexString() {
        val bytes = byteArrayOf(0x48, 0x65, 0x6C, 0x6C, 0x6F)
        val ts = TeletexString(bytes)
        assertTrue(bytes.contentEquals(ts.asBytes()))
        assertEquals("Hello", ts.asStr())
    }

    @Test
    fun testBmpString() {
        val bs = BmpString("Hello")
        assertEquals("Hello", bs.asStr())
        assertEquals(10, bs.asBytes().size)
    }

    @Test
    fun testUniversalString() {
        val us = UniversalString("Hello")
        assertEquals("Hello", us.asStr())
        assertEquals(20, us.asBytes().size)
    }
}
