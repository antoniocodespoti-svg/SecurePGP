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
        assertEquals(2, success.payload.records.size) // Record + auto-generated UserIdentityRecord
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

    @Test
    fun testCreateNewArchive_generatesUserIdentityRecordWithUsrUuidFormat() {
        var savedPayloadBytes: ByteArray? = null
        val repository = ArchiveRepository(
            saveArchiveFn = { _, _, bytes, _, _ ->
                savedPayloadBytes = bytes.clone()
                SaveResult.Success(1, dummyUri, promoted = true)
            },
        )
        val mockContext = DummyContext()

        val result = repository.createNewArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositorySaveResult.Success)

        assertNotNull(savedPayloadBytes)
        val deserialized = ArchivePayload.deserialize(savedPayloadBytes!!)
        val userIdRecord = deserialized.records.filterIsInstance<ArchiveRecord.UserIdentityRecord>().firstOrNull()

        assertNotNull(userIdRecord)
        assertTrue(ArchiveRepository.isUserIdentityIdValid(userIdRecord!!.userIdentityId))
    }

    @Test
    fun testCreateNewArchive_preservesExistingUserIdentityRecord() {
        val existingUserIdentity = ArchiveRecord.UserIdentityRecord("usr_12345678-1234-4234-8234-123456789abc")
        var savedPayloadBytes: ByteArray? = null

        val repository = ArchiveRepository(
            saveArchiveFn = { _, _, bytes, _, _ ->
                savedPayloadBytes = bytes.clone()
                SaveResult.Success(1, dummyUri, promoted = true)
            },
        )
        val mockContext = DummyContext()

        val result = repository.createNewArchive(
            mockContext, dummyUri, dummyPassphrase,
            initialRecords = listOf(existingUserIdentity),
        )
        assertTrue(result is RepositorySaveResult.Success)

        val deserialized = ArchivePayload.deserialize(savedPayloadBytes!!)
        val identityRecords = deserialized.records.filterIsInstance<ArchiveRecord.UserIdentityRecord>()

        assertEquals(1, identityRecords.size)
        assertEquals("usr_12345678-1234-4234-8234-123456789abc", identityRecords[0].userIdentityId)
    }

    @Test
    fun testOpenArchive_legacyPayloadGeneratesUserIdentityAndSetsWasModified() {
        val legacyRecord = ArchiveRecord.MetadataRecord("app", "legacy_v1")
        val legacyPayloadBytes = ArchivePayload(records = listOf(legacyRecord)).serialize()

        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.Success(1, dummyUri, legacyPayloadBytes) },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.Success)

        val success = result as RepositoryLoadResult.Success
        assertTrue(success.wasModified)

        val userIdRecord = success.payload.records.filterIsInstance<ArchiveRecord.UserIdentityRecord>().firstOrNull()
        assertNotNull(userIdRecord)
        assertTrue(ArchiveRepository.isUserIdentityIdValid(userIdRecord!!.userIdentityId))
    }

    @Test
    fun testOpenArchive_existingUserIdentityPreservedAndWasModifiedIsFalse() {
        val userIdRecord = ArchiveRecord.UserIdentityRecord("usr_11112222-3333-4444-8888-99990000aaaa")
        val payloadBytes = ArchivePayload(records = listOf(userIdRecord)).serialize()

        val repository = ArchiveRepository(
            loadArchiveFn = { _, _, _ -> LoadResult.Success(1, dummyUri, payloadBytes) },
        )
        val mockContext = DummyContext()

        val result = repository.openArchive(mockContext, dummyUri, dummyPassphrase)
        assertTrue(result is RepositoryLoadResult.Success)

        val success = result as RepositoryLoadResult.Success
        assertFalse(success.wasModified)

        val foundRecord = success.payload.records.filterIsInstance<ArchiveRecord.UserIdentityRecord>().firstOrNull()
        assertEquals(userIdRecord, foundRecord)
    }

    @Test
    fun testNormalizeUserIdentity_removesDuplicateUserIdentitiesKeepingFirst() {
        val user1 = ArchiveRecord.UserIdentityRecord("usr_11111111-1111-4111-8111-111111111111")
        val user2 = ArchiveRecord.UserIdentityRecord("usr_22222222-2222-4222-8222-222222222222")
        val meta = ArchiveRecord.MetadataRecord("k", "v")

        val records = listOf(meta, user1, user2)
        val (normalized, wasModified) = ArchiveRepository.normalizeUserIdentity(records)

        assertTrue(wasModified)
        val identityRecords = normalized.filterIsInstance<ArchiveRecord.UserIdentityRecord>()
        assertEquals(1, identityRecords.size)
        assertEquals("usr_11111111-1111-4111-8111-111111111111", identityRecords[0].userIdentityId)
    }
}

class DummyContext : android.content.ContextWrapper(null)
