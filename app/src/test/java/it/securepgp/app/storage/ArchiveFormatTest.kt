package it.securepgp.app.storage

import it.securepgp.app.crypto.InvalidKdfParamsException
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class ArchiveFormatTest {

    private val dummyPassphrase = "FormatTestPassphrase123!".toCharArray()
    private val dummyPayload = "DummyTestPayloadData1234567890".toByteArray(StandardCharsets.UTF_8)

    @Test
    fun testBinaryFormatRoundTrip() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        assertNotNull(archiveBytes)

        val decryptedPayload = ArchiveFormat.openArchive(archiveBytes, dummyPassphrase)
        assertArrayEquals(dummyPayload, decryptedPayload)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionInvalidMagic() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Corrupt magic bytes (e.g. replace 'S' with 'X')
        archiveBytes[0] = 'X'.code.toByte()

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = UnsupportedArchiveVersionException::class)
    fun testRejectionUnsupportedVersion() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Set version byte (index 8) to 2
        archiveBytes[8] = 0x02

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionUnknownKdfAlgorithm() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Set KDF algo byte (index 9) to 99
        archiveBytes[9] = 99.toByte()

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionTruncatedHeader() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Take only 50 bytes (< FIXED_HEADER_SIZE 122)
        val truncated = archiveBytes.copyOf(50)

        ArchiveFormat.parseAndValidateArchive(truncated)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionTruncatedPayload() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Remove 5 bytes from payload end
        val truncated = archiveBytes.copyOf(archiveBytes.size - 5)

        ArchiveFormat.parseAndValidateArchive(truncated)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionDeclaredPayloadTooLarge() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Index 118-121 holds encryptedPayloadLength
        val buffer = ByteBuffer.wrap(archiveBytes)
        buffer.putInt(118, ArchiveFormat.MAX_PAYLOAD_SIZE + 1)

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionNegativePayloadLength() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        val buffer = ByteBuffer.wrap(archiveBytes)
        buffer.putInt(118, -5)

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidKdfParamsException::class)
    fun testRejectionLowKdfIterations() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Index 42-45 holds kdfIterations
        val buffer = ByteBuffer.wrap(archiveBytes)
        buffer.putInt(42, 99_999) // Below MIN_KDF_ITERATIONS 100_000

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidKdfParamsException::class)
    fun testRejectionHighKdfIterations() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        val buffer = ByteBuffer.wrap(archiveBytes)
        buffer.putInt(42, 2_000_001) // Above MAX_KDF_ITERATIONS 2_000_000

        ArchiveFormat.parseAndValidateArchive(archiveBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testRejectionUnexpectedTrailingBytes() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        val withTrailing = archiveBytes + byteArrayOf(0x01, 0x02, 0x03)

        ArchiveFormat.parseAndValidateArchive(withTrailing)
    }

    @Test(expected = CorruptedArchiveException::class)
    fun testAadAlteredCausesAuthFailure() {
        val archiveBytes = ArchiveFormat.createArchive(dummyPayload, dummyPassphrase)
        // Alter salt (part of AAD)
        archiveBytes[10] = (archiveBytes[10].toInt() xor 0xFF).toByte()

        ArchiveFormat.openArchive(archiveBytes, dummyPassphrase)
    }
}
