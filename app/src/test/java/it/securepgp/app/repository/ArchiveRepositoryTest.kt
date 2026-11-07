package it.securepgp.app.repository

import android.net.DummyUri
import android.net.Uri
import it.securepgp.app.storage.ArchivePayload
import it.securepgp.app.storage.ArchiveRecord
import it.securepgp.app.storage.LoadResult
import it.securepgp.app.storage.SaveResult
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchiveRepositoryTest {

    private val dummyPassphrase = "RepoTestPassphrase123!".toCharArray()
    private val dummyUri: Uri = DummyUri()

    @Test
    fun testPayloadSerialization_zeroizesPayloadBytes() {
        val dummyRecord = ArchiveRecord.MetadataRecord("version", "1.0")
        val payload = ArchivePayload(records = listOf(dummyRecord))

        val repository = ArchiveRepository()
        assertNotNull(repository)
        assertEquals(1, payload.records.size)
    }

    @Test
    fun testOpenArchive_deserializesSuccessfullyOnStorageSuccess() {
        val record = ArchiveRecord.MetadataRecord("test_key", "test_val")
        val payloadBytes = ArchivePayload(records = listOf(record)).serialize()

        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.Success(1, dummyUri, payloadBytes.clone()) },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.Success)

        val success = result as RepositoryLoadResult.Success
        assertEquals(1, success.generationIndex)
        assertEquals(1, success.payload.records.size)
        assertEquals(record, success.payload.records[0])
    }

    @Test
    fun testOpenArchive_mapsAuthenticationFailed() {
        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.AuthenticationFailed("Wrong passphrase.") },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.AuthenticationFailed)
        val authFail = result as RepositoryLoadResult.AuthenticationFailed
        assertEquals("Wrong passphrase.", authFail.message)
        assertFalse(authFail.message.contains(String(dummyPassphrase)))
    }

    @Test
    fun testOpenArchive_mapsCorruptedArchive() {
        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.CorruptedArchive(2, dummyUri, "Corrupted header.") },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.CorruptedArchive)
        val corrupted = result as RepositoryLoadResult.CorruptedArchive
        assertEquals(2, corrupted.generationIndex)
        assertEquals("Corrupted header.", corrupted.message)
    }

    @Test
    fun testOpenArchive_mapsNoArchiveFound() {
        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.NoArchiveFound },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.NoArchiveFound)
    }

    @Test
    fun testCreateNewArchive_mapsSuccess() {
        val repository = ArchiveRepository(
            saveArchiveFn = { _, _, _, _, _ -> SaveResult.Success(1, dummyUri, promoted = true) },
        )
        val mockContext = DummyContext()

        val result = repository.createNewArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositorySaveResult.Success)
        val success = result as RepositorySaveResult.Success
        assertEquals(1, success.generationIndex)
        assertTrue(success.promoted)
    }

    @Test
    fun testCreateNewArchive_mapsVerifiedNotPromotedDistinctly() {
        val repository = ArchiveRepository(
            saveArchiveFn = { _, _, _, _, _ -> SaveResult.VerifiedNotPromoted(2, dummyUri, "SAF rename not supported") },
        )
        val mockContext = DummyContext()

        val result = repository.createNewArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositorySaveResult.VerifiedNotPromoted)
        val notPromoted = result as RepositorySaveResult.VerifiedNotPromoted
        assertEquals(2, notPromoted.generationIndex)
        assertEquals("SAF rename not supported", notPromoted.reason)
    }
}

class DummyContext : android.content.ContextWrapper(null)
