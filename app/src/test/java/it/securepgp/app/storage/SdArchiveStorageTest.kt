package it.securepgp.app.storage

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SdArchiveStorageTest {

    @Test
    fun testExtractGenerationIndex_validNames() {
        assertEquals(1, SdArchiveStorage.extractGenerationIndex("spgp_archive_g00001.dat"))
        assertEquals(42, SdArchiveStorage.extractGenerationIndex("spgp_archive_g00042.tmp"))
        assertEquals(99999, SdArchiveStorage.extractGenerationIndex("spgp_archive_g99999.dat"))
    }

    @Test
    fun testExtractGenerationIndex_invalidNames() {
        assertNull(SdArchiveStorage.extractGenerationIndex("random_file.txt"))
        assertNull(SdArchiveStorage.extractGenerationIndex("spgp_archive_g12.dat")) // Not 5 digits
        assertNull(SdArchiveStorage.extractGenerationIndex("spgp_archive_gabcde.dat"))
        assertNull(SdArchiveStorage.extractGenerationIndex("spgp_archive_g00001.bin"))
    }

    @Test
    fun testIsTmpFile() {
        assertTrue(SdArchiveStorage.isTmpFile("spgp_archive_g00001.tmp"))
        assertTrue(SdArchiveStorage.isTmpFile("SPGP_ARCHIVE_G00001.TMP"))
        assertFalse(SdArchiveStorage.isTmpFile("spgp_archive_g00001.dat"))
    }

    @Test
    fun testFormatGenerationFileName() {
        assertEquals("spgp_archive_g00001.dat", SdArchiveStorage.formatGenerationFileName(1, isTmp = false))
        assertEquals("spgp_archive_g00042.tmp", SdArchiveStorage.formatGenerationFileName(42, isTmp = true))
        assertEquals("spgp_archive_g99999.dat", SdArchiveStorage.formatGenerationFileName(99999, isTmp = false))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testFormatGenerationFileName_outOfBoundsLow() {
        SdArchiveStorage.formatGenerationFileName(0, isTmp = false)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testFormatGenerationFileName_outOfBoundsHigh() {
        SdArchiveStorage.formatGenerationFileName(100_000, isTmp = false)
    }
}
