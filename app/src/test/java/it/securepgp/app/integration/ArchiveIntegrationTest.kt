package it.securepgp.app.integration

import android.net.DummyUri
import android.net.Uri
import it.securepgp.app.crypto.ArchiveCrypto
import it.securepgp.app.repository.ArchiveRepository
import it.securepgp.app.repository.RepositoryLoadResult
import it.securepgp.app.repository.RepositorySaveResult
import it.securepgp.app.storage.ArchiveFormat
import it.securepgp.app.storage.ArchivePayload
import it.securepgp.app.storage.ArchiveRecord
import it.securepgp.app.storage.CorruptedArchiveException
import it.securepgp.app.storage.InvalidArchiveFormatException
import it.securepgp.app.storage.LoadResult
import it.securepgp.app.storage.SaveResult
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchiveIntegrationTest {

    private val dummyPassphrase = "IntegrationTestPassphrase123!".toCharArray()
    private val wrongPassphrase = "WrongTestPassphrase999!".toCharArray()
    private val dummyUri: Uri = DummyUri()

    @Test
    fun testFullEndToEnd_CreateFormatCryptoPayload_Success() {
        val dummyPrivKey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\nDummyPrivateKeyData12345".toByteArray(StandardCharsets.UTF_8)
        val dummyPubKey = "-----BEGIN PGP PUBLIC KEY BLOCK-----\nDummyPublicKeyData67890".toByteArray(StandardCharsets.UTF_8)

        val records = listOf(
            ArchiveRecord.PrivateKeyRecord("master_key_001", dummyPrivKey),
            ArchiveRecord.PublicKeyRecord("contact_key_002", dummyPubKey),
            ArchiveRecord.MetadataRecord("archive_version", "1.0"),
        )

        val payload = ArchivePayload(records = records)
        val payloadBytes = payload.serialize()

        var archiveBytes: ByteArray? = null
        var decryptedPayloadBytes: ByteArray? = null

        try {
            // 1. Create binary archive (ciphers DEK with KEK, ciphers payload with DEK, attaches GCM tags & AAD)
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            assertNotNull(archiveBytes)
            assertTrue(archiveBytes.size > ArchiveFormat.FIXED_HEADER_SIZE)

            // 2. Open binary archive (parses header, validates AAD, derives KEK, decrypts DEK, decrypts payload)
            decryptedPayloadBytes = ArchiveFormat.openArchive(archiveBytes, dummyPassphrase)
            assertNotNull(decryptedPayloadBytes)

            // 3. Deserialize payload and compare records
            val deserializedPayload = ArchivePayload.deserialize(decryptedPayloadBytes)
            assertEquals(ArchivePayload.CURRENT_PAYLOAD_VERSION, deserializedPayload.version)
            assertEquals(3, deserializedPayload.records.size)

            val rec1 = deserializedPayload.records[0] as ArchiveRecord.PrivateKeyRecord
            assertEquals("master_key_001", rec1.keyId)
            assertArrayEquals(dummyPrivKey, rec1.keyData)

            val rec2 = deserializedPayload.records[1] as ArchiveRecord.PublicKeyRecord
            assertEquals("contact_key_002", rec2.keyId)
            assertArrayEquals(dummyPubKey, rec2.keyData)

            val rec3 = deserializedPayload.records[2] as ArchiveRecord.MetadataRecord
            assertEquals("archive_version", rec3.key)
            assertEquals("1.0", rec3.value)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
            if (decryptedPayloadBytes != null) ArchiveCrypto.zeroize(decryptedPayloadBytes)
        }
    }

    @Test(expected = CorruptedArchiveException::class)
    fun testIntegration_WrongPassphraseRejection() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val payloadBytes = payload.serialize()
        var archiveBytes: ByteArray? = null

        try {
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            // Attempt to open with wrong passphrase
            ArchiveFormat.openArchive(archiveBytes, wrongPassphrase)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
        }
    }

    @Test(expected = CorruptedArchiveException::class)
    fun testIntegration_CiphertextTamperingRejection() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val payloadBytes = payload.serialize()
        var archiveBytes: ByteArray? = null

        try {
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            // Corrupt 1 byte in the ciphertext payload area
            val corruptedIndex = ArchiveFormat.FIXED_HEADER_SIZE + 2
            archiveBytes[corruptedIndex] = (archiveBytes[corruptedIndex].toInt() xor 0xFF).toByte()

            ArchiveFormat.openArchive(archiveBytes, dummyPassphrase)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
        }
    }

    @Test(expected = CorruptedArchiveException::class)
    fun testIntegration_HeaderAadTamperingRejection() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val payloadBytes = payload.serialize()
        var archiveBytes: ByteArray? = null

        try {
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            // Corrupt 1 byte in the header salt (part of AAD)
            archiveBytes[12] = (archiveBytes[12].toInt() xor 0xFF).toByte()

            ArchiveFormat.openArchive(archiveBytes, dummyPassphrase)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
        }
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testIntegration_TruncatedArchiveRejection() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val payloadBytes = payload.serialize()
        var archiveBytes: ByteArray? = null

        try {
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            val truncated = archiveBytes.copyOf(archiveBytes.size - 10)

            ArchiveFormat.openArchive(truncated, dummyPassphrase)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
        }
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testIntegration_TrailingBytesRejection() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val payloadBytes = payload.serialize()
        var archiveBytes: ByteArray? = null

        try {
            archiveBytes = ArchiveFormat.createArchive(payloadBytes, dummyPassphrase)
            val withTrailing = archiveBytes + byteArrayOf(0xDE.toByte(), 0xAD.toByte())

            ArchiveFormat.openArchive(withTrailing, dummyPassphrase)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
            if (archiveBytes != null) ArchiveCrypto.zeroize(archiveBytes)
        }
    }

    @Test
    fun testIntegration_RepositoryInMemoryStorageBridge() {
        var inMemoryStorage: ByteArray? = null

        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, passphrase ->
                val bytes = inMemoryStorage ?: return@ArchiveRepository LoadResult.NoArchiveFound
                try {
                    val decryptedPayloadBytes = ArchiveFormat.openArchive(bytes, passphrase)
                    LoadResult.Success(1, dummyUri, decryptedPayloadBytes)
                } catch (e: Exception) {
                    LoadResult.CorruptedArchive(1, dummyUri, e.localizedMessage ?: "Corrupted")
                }
            },
            saveArchiveFn = { _, _, payloadBytes, passphrase, iterations ->
                try {
                    val createdBytes = ArchiveFormat.createArchive(payloadBytes, passphrase, iterations)
                    inMemoryStorage = createdBytes
                    SaveResult.Success(1, dummyUri, promoted = true)
                } catch (e: Exception) {
                    SaveResult.SafError("Creation failed: ${e.localizedMessage}")
                }
            },
        )

        val mockContext = DummyContext()
        val records = listOf(
            ArchiveRecord.PrivateKeyRecord("master_01", "PRIV_KEY_DATA".toByteArray(Charsets.UTF_8)),
            ArchiveRecord.MetadataRecord("label", "Test Archive"),
        )

        // 1. Create new archive via Repository
        val saveResult = repository.createNewArchive(mockContext, dummyUri, dummyPassphrase, records)
        assertTrue(saveResult is RepositorySaveResult.Success)
        assertNotNull(inMemoryStorage)

        // 2. Open archive via Repository
        val loadResult = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(loadResult is RepositoryLoadResult.Success)

        val successLoad = loadResult as RepositoryLoadResult.Success
        assertEquals(1, successLoad.generationIndex)
        assertEquals(2, successLoad.payload.records.size)
        assertEquals(records[0], successLoad.payload.records[0])
        assertEquals(records[1], successLoad.payload.records[1])

        // 3. Open with wrong passphrase
        val wrongLoadResult = repository.openArchive(mockContext, dummyUri, wrongPassphrase)
        assertTrue(wrongLoadResult is RepositoryLoadResult.CorruptedArchive)

        inMemoryStorage?.let { ArchiveCrypto.zeroize(it) }
    }
}

class DummyContext : android.content.ContextWrapper(null)
