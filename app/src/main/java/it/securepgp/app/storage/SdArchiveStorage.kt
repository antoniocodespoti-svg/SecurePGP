package it.securepgp.app.storage

import android.content.Context
import android.net.Uri
import android.provider.DocumentsContract
import it.securepgp.app.crypto.ArchiveCrypto
import it.securepgp.app.crypto.AuthenticationFailedException
import java.io.InputStream
import java.io.OutputStream

data class GenerationFileInfo(
    val generationIndex: Int,
    val displayName: String,
    val documentUri: Uri,
    val isTmp: Boolean,
)

sealed class SaveResult {
    data class Success(
        val generationIndex: Int,
        val documentUri: Uri,
        val promoted: Boolean,
    ) : SaveResult()

    data class VerifiedNotPromoted(
        val generationIndex: Int,
        val tmpDocumentUri: Uri,
        val reason: String,
    ) : SaveResult()

    data class SafError(val message: String, val cause: Throwable? = null) : SaveResult()
    data class CorruptedData(val message: String) : SaveResult()
    data class AuthenticationFailed(val message: String) : SaveResult()
}

sealed class LoadResult {
    data class Success(
        val generationIndex: Int,
        val documentUri: Uri,
        val payloadBytes: ByteArray,
    ) : LoadResult() {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is Success) return false
            if (generationIndex != other.generationIndex) return false
            if (documentUri != other.documentUri) return false
            return payloadBytes.contentEquals(other.payloadBytes)
        }

        override fun hashCode(): Int {
            var result = generationIndex
            result = (31 * result) + documentUri.hashCode()
            result = (31 * result) + payloadBytes.contentHashCode()
            return result
        }
    }

    data object NoArchiveFound : LoadResult()
    data class CorruptedArchive(val generationIndex: Int, val documentUri: Uri, val message: String) : LoadResult()
    data class AuthenticationFailed(val message: String) : LoadResult()
    data class SafError(val message: String, val cause: Throwable? = null) : LoadResult()
}

object SdArchiveStorage {

    private val GENERATION_FILE_REGEX = Regex("""^spgp_archive_g(\d{5})\.(dat|tmp)$""")
    const val MAX_GENERATION_INDEX = 99_999

    fun extractGenerationIndex(fileName: String): Int? {
        val match = GENERATION_FILE_REGEX.find(fileName) ?: return null
        val (indexStr, _) = match.destructured
        return indexStr.toIntOrNull()
    }

    fun isTmpFile(fileName: String): Boolean {
        return fileName.endsWith(".tmp", ignoreCase = true)
    }

    fun formatGenerationFileName(index: Int, isTmp: Boolean): String {
        require((index >= 1) && (index <= MAX_GENERATION_INDEX)) { "Generation index ($index) out of bounds [1..$MAX_GENERATION_INDEX]." }
        val ext = if (isTmp) "tmp" else "dat"
        return "spgp_archive_g%05d.%s".format(index, ext)
    }

    fun scanGenerations(context: Context, treeUri: Uri): List<GenerationFileInfo> {
        val results = mutableListOf<GenerationFileInfo>()
        try {
            val contentResolver = context.contentResolver
            val treeDocumentId = DocumentsContract.getTreeDocumentId(treeUri)
            val childrenUri = DocumentsContract.buildChildDocumentsUriUsingTree(treeUri, treeDocumentId)

            val cursor = contentResolver.query(
                childrenUri,
                arrayOf(
                    DocumentsContract.Document.COLUMN_DOCUMENT_ID,
                    DocumentsContract.Document.COLUMN_DISPLAY_NAME,
                ),
                null,
                null,
                null,
            )

            cursor?.use {
                val idIdx = it.getColumnIndex(DocumentsContract.Document.COLUMN_DOCUMENT_ID)
                val nameIdx = it.getColumnIndex(DocumentsContract.Document.COLUMN_DISPLAY_NAME)

                while (it.moveToNext()) {
                    val name = if (nameIdx != -1) it.getString(nameIdx) else null
                    val docId = if (idIdx != -1) it.getString(idIdx) else null

                    if (name != null && docId != null) {
                        val genIdx = extractGenerationIndex(name)
                        if (genIdx != null) {
                            val docUri = DocumentsContract.buildDocumentUriUsingTree(treeUri, docId)
                            results.add(
                                GenerationFileInfo(
                                    generationIndex = genIdx,
                                    displayName = name,
                                    documentUri = docUri,
                                    isTmp = isTmpFile(name),
                                ),
                            )
                        }
                    }
                }
            }
        } catch (_: SecurityException) {
            // Permission error or provider unreadable
        } catch (_: Exception) {
            // General SAF error
        }

        return results.sortedByDescending { it.generationIndex }
    }

    fun loadLatestArchive(
        context: Context,
        treeUri: Uri,
        passphrase: CharArray,
    ): LoadResult {
        if (!hasPersistedPermissions(context, treeUri)) {
            return LoadResult.SafError("Persisted SAF permissions for folder are missing or revoked.")
        }

        val generations = scanGenerations(context, treeUri)
        val validConfirmedGenerations = generations.filter { !it.isTmp }

        if (validConfirmedGenerations.isEmpty()) {
            return LoadResult.NoArchiveFound
        }

        val latest = validConfirmedGenerations.first()

        return try {
            val inputStream: InputStream = context.contentResolver.openInputStream(latest.documentUri)
                ?: return LoadResult.SafError("Unable to open input stream for document.")

            val archiveBytes = inputStream.use { it.readBytes() }
            val decryptedPayload = ArchiveFormat.openArchive(archiveBytes, passphrase)

            LoadResult.Success(
                generationIndex = latest.generationIndex,
                documentUri = latest.documentUri,
                payloadBytes = decryptedPayload,
            )
        } catch (e: CorruptedArchiveException) {
            if (e.cause is AuthenticationFailedException) {
                LoadResult.AuthenticationFailed("Authentication failed: wrong passphrase or tampered header/payload.")
            } else {
                LoadResult.CorruptedArchive(latest.generationIndex, latest.documentUri, e.localizedMessage ?: "Corrupted archive format.")
            }
        } catch (e: SecurityException) {
            LoadResult.SafError("Security exception reading archive: ${e.localizedMessage}")
        } catch (e: Exception) {
            LoadResult.SafError("SAF read error: ${e.localizedMessage}", e)
        }
    }

    fun saveNewGeneration(
        context: Context,
        treeUri: Uri,
        payloadBytes: ByteArray,
        passphrase: CharArray,
        iterations: Int = ArchiveCrypto.STANDARD_KDF_ITERATIONS,
    ): SaveResult {
        if (!hasPersistedPermissions(context, treeUri)) {
            return SaveResult.SafError("Persisted SAF permissions for folder are missing or revoked.")
        }

        val existingGenerations = scanGenerations(context, treeUri)
        val highestIndex = existingGenerations.firstOrNull()?.generationIndex ?: 0
        val newIndex = highestIndex + 1

        if (newIndex > MAX_GENERATION_INDEX) {
            return SaveResult.SafError("Maximum generation index limit ($MAX_GENERATION_INDEX) reached.")
        }

        val tmpFileName = formatGenerationFileName(newIndex, isTmp = true)
        val datFileName = formatGenerationFileName(newIndex, isTmp = false)

        val contentResolver = context.contentResolver
        val parentDocumentUri = DocumentsContract.buildDocumentUriUsingTree(
            treeUri,
            DocumentsContract.getTreeDocumentId(treeUri),
        )

        val tmpUri = try {
            DocumentsContract.createDocument(
                contentResolver,
                parentDocumentUri,
                "application/octet-stream",
                tmpFileName,
            ) ?: return SaveResult.SafError("SAF provider returned null when creating temporary document '$tmpFileName'.")
        } catch (e: Exception) {
            return SaveResult.SafError("Failed to create temporary document '$tmpFileName': ${e.localizedMessage}", e)
        }

        return try {
            val archiveBytes = ArchiveFormat.createArchive(payloadBytes, passphrase, iterations)

            val outputStream: OutputStream = contentResolver.openOutputStream(tmpUri, "w")
                ?: return SaveResult.SafError("Unable to open output stream for temporary document.")

            outputStream.use { out ->
                out.write(archiveBytes)
                out.flush()
            }

            // Re-open and verify complete readback & crypto authentication of written tmp file
            val inputStream: InputStream = contentResolver.openInputStream(tmpUri)
                ?: return SaveResult.SafError("Unable to re-open temporary document for verification.")

            val readBackBytes = inputStream.use { it.readBytes() }

            try {
                ArchiveFormat.openArchive(readBackBytes, passphrase)
            } catch (e: CorruptedArchiveException) {
                return SaveResult.CorruptedData("Verification of written temporary archive failed: ${e.localizedMessage}")
            }

            // Attempt promotion (rename .tmp -> .dat)
            val promotedUri = try {
                DocumentsContract.renameDocument(contentResolver, tmpUri, datFileName)
            } catch (_: Exception) {
                null
            }

            if (promotedUri != null) {
                SaveResult.Success(newIndex, promotedUri, promoted = true)
            } else {
                SaveResult.VerifiedNotPromoted(
                    generationIndex = newIndex,
                    tmpDocumentUri = tmpUri,
                    reason = "SAF provider does not support document renaming or rename failed. Verified temporary archive was preserved.",
                )
            }
        } catch (e: SecurityException) {
            SaveResult.SafError("Security exception during archive save: ${e.localizedMessage}", e)
        } catch (e: Exception) {
            SaveResult.SafError("Error during archive save: ${e.localizedMessage}", e)
        }
    }

    fun cleanOlderArchiveGenerations(
        context: Context,
        treeUri: Uri,
        currentGenerationIndex: Int,
    ): Boolean {
        if (!hasPersistedPermissions(context, treeUri)) {
            return false
        }

        val allGenerations = scanGenerations(context, treeUri)
        val targetsToDelete = allGenerations.filter { gen ->
            if (gen.isTmp) {
                gen.generationIndex <= currentGenerationIndex
            } else {
                gen.generationIndex < currentGenerationIndex
            }
        }

        if (targetsToDelete.isEmpty()) {
            return true
        }

        var allDeleted = true
        val contentResolver = context.contentResolver

        for (target in targetsToDelete) {
            try {
                val deleted = DocumentsContract.deleteDocument(contentResolver, target.documentUri)
                if (!deleted) {
                    allDeleted = false
                }
            } catch (_: Exception) {
                allDeleted = false
            }
        }

        return allDeleted
    }

    private fun hasPersistedPermissions(context: Context, treeUri: Uri): Boolean {
        val permissions = context.contentResolver.persistedUriPermissions
        return permissions.any { perm ->
            perm.uri == treeUri && (perm.isReadPermission || perm.isWritePermission)
        }
    }
}
