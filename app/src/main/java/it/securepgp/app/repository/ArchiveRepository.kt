package it.securepgp.app.repository

import android.content.Context
import android.net.Uri
import it.securepgp.app.crypto.ArchiveCrypto
import it.securepgp.app.storage.ArchivePayload
import it.securepgp.app.storage.ArchiveRecord
import it.securepgp.app.storage.LoadResult
import it.securepgp.app.storage.SaveResult
import it.securepgp.app.storage.SdArchiveStorage
import java.util.UUID

sealed class RepositoryLoadResult {
    data class Success(
        val generationIndex: Int,
        val documentUri: Uri,
        val payload: ArchivePayload,
        val wasModified: Boolean = false,
    ) : RepositoryLoadResult()

    data object NoArchiveFound : RepositoryLoadResult()
    data class CorruptedArchive(val generationIndex: Int, val documentUri: Uri, val message: String) : RepositoryLoadResult()
    data class AuthenticationFailed(val message: String) : RepositoryLoadResult()
    data class Error(val message: String, val cause: Throwable? = null) : RepositoryLoadResult()
}

sealed class RepositorySaveResult {
    data class Success(
        val generationIndex: Int,
        val documentUri: Uri,
        val promoted: Boolean,
    ) : RepositorySaveResult()

    data class VerifiedNotPromoted(
        val generationIndex: Int,
        val tmpDocumentUri: Uri,
        val reason: String,
    ) : RepositorySaveResult()

    data class Error(val message: String, val cause: Throwable? = null) : RepositorySaveResult()
}

/**
 * Application coordinator for Archive operations, orchestrating ArchiveCrypto, ArchiveFormat,
 * ArchivePayload, and SdArchiveStorage.
 */
class ArchiveRepository(
    private val loadArchiveFn: (Context, Uri, CharArray) -> LoadResult = SdArchiveStorage::loadLatestArchive,
    private val saveArchiveFn: (Context, Uri, ByteArray, CharArray, Int) -> SaveResult = SdArchiveStorage::saveNewGeneration,
) {

    fun createNewArchive(
        context: Context,
        treeUri: Uri,
        passphrase: CharArray,
        initialRecords: List<ArchiveRecord> = emptyList(),
        iterations: Int = ArchiveCrypto.STANDARD_KDF_ITERATIONS,
    ): RepositorySaveResult {
        val (normalizedRecords, _) = normalizeUserIdentity(initialRecords)
        val payload = ArchivePayload(records = normalizedRecords)
        val payloadBytes = payload.serialize()

        return try {
            val saveRes = saveArchiveFn(context, treeUri, payloadBytes, passphrase, iterations)
            mapSaveResult(saveRes)
        } catch (e: Exception) {
            RepositorySaveResult.Error("Failed to create archive: ${e.localizedMessage ?: "Unknown error"}", e)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
        }
    }

    fun openArchive(
        context: Context,
        treeUri: Uri,
        passphrase: CharArray,
    ): RepositoryLoadResult {
        return when (val loadRes = loadArchiveFn(context, treeUri, passphrase)) {
            is LoadResult.Success -> {
                try {
                    val rawPayload = ArchivePayload.deserialize(loadRes.payloadBytes)
                    val (normalizedRecords, wasModified) = normalizeUserIdentity(rawPayload.records)
                    val finalPayload = if (wasModified) ArchivePayload(rawPayload.version, normalizedRecords) else rawPayload
                    RepositoryLoadResult.Success(
                        generationIndex = loadRes.generationIndex,
                        documentUri = loadRes.documentUri,
                        payload = finalPayload,
                        wasModified = wasModified,
                    )
                } catch (e: Exception) {
                    RepositoryLoadResult.CorruptedArchive(
                        generationIndex = loadRes.generationIndex,
                        documentUri = loadRes.documentUri,
                        message = "Payload deserialization failed: ${e.localizedMessage ?: "Malformed payload"}",
                    )
                } finally {
                    ArchiveCrypto.zeroize(loadRes.payloadBytes)
                }
            }
            is LoadResult.NoArchiveFound -> RepositoryLoadResult.NoArchiveFound
            is LoadResult.AuthenticationFailed -> RepositoryLoadResult.AuthenticationFailed(loadRes.message)
            is LoadResult.CorruptedArchive -> RepositoryLoadResult.CorruptedArchive(
                generationIndex = loadRes.generationIndex,
                documentUri = loadRes.documentUri,
                message = loadRes.message,
            )
            is LoadResult.SafError -> RepositoryLoadResult.Error(loadRes.message, loadRes.cause)
        }
    }

    fun saveArchivePayload(
        context: Context,
        treeUri: Uri,
        payload: ArchivePayload,
        passphrase: CharArray,
        iterations: Int = ArchiveCrypto.STANDARD_KDF_ITERATIONS,
    ): RepositorySaveResult {
        val (normalizedRecords, _) = normalizeUserIdentity(payload.records)
        val payloadToSave = ArchivePayload(payload.version, normalizedRecords)
        val payloadBytes = payloadToSave.serialize()
        return try {
            val saveRes = saveArchiveFn(context, treeUri, payloadBytes, passphrase, iterations)
            mapSaveResult(saveRes)
        } catch (e: Exception) {
            RepositorySaveResult.Error("Failed to save archive: ${e.localizedMessage ?: "Unknown error"}", e)
        } finally {
            ArchiveCrypto.zeroize(payloadBytes)
        }
    }

    private fun mapSaveResult(saveRes: SaveResult): RepositorySaveResult {
        return when (saveRes) {
            is SaveResult.Success -> RepositorySaveResult.Success(
                generationIndex = saveRes.generationIndex,
                documentUri = saveRes.documentUri,
                promoted = saveRes.promoted,
            )
            is SaveResult.VerifiedNotPromoted -> RepositorySaveResult.VerifiedNotPromoted(
                generationIndex = saveRes.generationIndex,
                tmpDocumentUri = saveRes.tmpDocumentUri,
                reason = saveRes.reason,
            )
            is SaveResult.AuthenticationFailed -> RepositorySaveResult.Error(saveRes.message)
            is SaveResult.CorruptedData -> RepositorySaveResult.Error(saveRes.message)
            is SaveResult.SafError -> RepositorySaveResult.Error(saveRes.message, saveRes.cause)
        }
    }

    companion object {
        private val USER_IDENTITY_REGEX = Regex("""^usr_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$""")

        fun generateUserIdentityId(): String {
            return "usr_" + UUID.randomUUID().toString()
        }

        fun isUserIdentityIdValid(id: String): Boolean {
            return USER_IDENTITY_REGEX.matches(id)
        }

        fun normalizeUserIdentity(records: List<ArchiveRecord>): Pair<List<ArchiveRecord>, Boolean> {
            val identityRecords = records.filterIsInstance<ArchiveRecord.UserIdentityRecord>()
            return when {
                identityRecords.isEmpty() -> {
                    val newRecord = ArchiveRecord.UserIdentityRecord(generateUserIdentityId())
                    Pair(records + newRecord, true)
                }
                identityRecords.size == 1 -> {
                    Pair(records, false)
                }
                else -> {
                    var keptFirst = false
                    val cleanedRecords = records.filterNot { record ->
                        if (record is ArchiveRecord.UserIdentityRecord) {
                            if (!keptFirst) {
                                keptFirst = true
                                false
                            } else {
                                true
                            }
                        } else {
                            false
                        }
                    }
                    Pair(cleanedRecords, true)
                }
            }
        }
    }
}
