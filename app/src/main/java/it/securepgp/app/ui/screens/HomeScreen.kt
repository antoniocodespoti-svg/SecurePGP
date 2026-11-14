package it.securepgp.app.ui.screens

import android.net.Uri
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.RadioButton
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import it.securepgp.app.crypto.ArchiveCrypto
import it.securepgp.app.crypto.ParsedPgpKeyResult
import it.securepgp.app.crypto.PgpKeyGenerator
import it.securepgp.app.crypto.PgpKeyParser
import it.securepgp.app.crypto.PgpProfile
import it.securepgp.app.repository.ArchiveRepository
import it.securepgp.app.repository.RepositoryLoadResult
import it.securepgp.app.repository.RepositorySaveResult
import it.securepgp.app.storage.ArchivePayload
import it.securepgp.app.storage.ArchiveRecord
import it.securepgp.app.storage.FolderAccessResult
import it.securepgp.app.storage.SdArchiveStorage
import it.securepgp.app.storage.StorageHelper
import it.securepgp.app.storage.TestFileStorage
import it.securepgp.app.storage.TestResult
import it.securepgp.app.ui.components.SectionCard
import it.securepgp.app.ui.theme.SecurePGPTheme
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.UUID
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.bouncycastle.bcpg.ArmoredOutputStream

private enum class PendingArchiveDialogAction {
    CREATE_ARCHIVE,
    OPEN_ARCHIVE,
    SAVE_ARCHIVE
}

private enum class NewRecordType {
    PUBLIC_KEY,
    PRIVATE_KEY,
    METADATA
}

private enum class HomeNavigationTab {
    MY_KEYS,
    CONTACTS,
}

private val PREDEFINED_CATEGORIES = listOf("Amici", "Parenti", "Colleghi", "Lavoro", "Personale", "Altro")

fun getCompletePersonalKeypairIds(records: List<ArchiveRecord>): List<String> {
    val privateKeyIds = records.filterIsInstance<ArchiveRecord.PrivateKeyRecord>()
        .map { it.keyId }
        .toSet()

    val publicKeyIds = records.filterIsInstance<ArchiveRecord.PublicKeyRecord>()
        .map { it.keyId }
        .toSet()

    return privateKeyIds.intersect(publicKeyIds).toList()
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun HomeScreen() {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    val archiveRepository = remember { ArchiveRepository() }

    var folderStatus by remember { mutableStateOf("Verifica cartella in corso...") }
    var isFolderAccessible by remember { mutableStateOf(false) }
    var currentSavedUri by remember { mutableStateOf<Uri?>(null) }
    var archiveStatusMessage by remember { mutableStateOf("") }
    var loadedPayload by remember { mutableStateOf<ArchivePayload?>(null) }
    var hasUnsavedChanges by remember { mutableStateOf(false) }
    var isOperating by remember { mutableStateOf(false) }

    // Navigation State
    var activeTab by remember { mutableStateOf(HomeNavigationTab.MY_KEYS) }
    var selectedContactDetail by remember { mutableStateOf<ArchiveRecord.ContactRecord?>(null) }

    // Dialog state for Passphrase
    var pendingDialogAction by remember { mutableStateOf<PendingArchiveDialogAction?>(null) }
    var passphraseInput by remember { mutableStateOf("") }
    var passphraseConfirmInput by remember { mutableStateOf("") }
    var dialogError by remember { mutableStateOf("") }

    // Dialog state for Add Record
    var showAddRecordDialog by remember { mutableStateOf(false) }
    var selectedRecordType by remember { mutableStateOf(NewRecordType.PUBLIC_KEY) }
    var keyIdInput by remember { mutableStateOf("") }
    var keyDataInput by remember { mutableStateOf("") }
    var metadataKeyInput by remember { mutableStateOf("") }
    var metadataValueInput by remember { mutableStateOf("") }
    var addRecordError by remember { mutableStateOf("") }

    // Dialog state for Generate PGP Keypair
    var showGeneratePgpDialog by remember { mutableStateOf(false) }
    var genKeyNameInput by remember { mutableStateOf("") }
    var genUserIdInput by remember { mutableStateOf("") }
    var genSelectedCategory by remember { mutableStateOf("Personale") }
    var genCustomCategoryInput by remember { mutableStateOf("") }
    var genSelectedProfile by remember { mutableStateOf(PgpProfile.RSA_3072) }
    var genPassphraseInput by remember { mutableStateOf("") }
    var genPassphraseConfirmInput by remember { mutableStateOf("") }
    var generateDialogError by remember { mutableStateOf("") }

    // Dialog state for Add Contact
    var showAddContactDialog by remember { mutableStateOf(false) }
    var contactAliasInput by remember { mutableStateOf("") }
    var addContactError by remember { mutableStateOf("") }

    // State for Contact PGP Public Key Import
    var contactForPublicKeyImport by remember { mutableStateOf<ArchiveRecord.ContactRecord?>(null) }

    // State for Contact Personal Owner Key Assignment
    var contactForOwnerKeyAssignment by remember { mutableStateOf<ArchiveRecord.ContactRecord?>(null) }
    var selectedOwnerKeyIdOption by remember { mutableStateOf<String?>(null) }

    // State for Personal Keypair Category Picker
    var keyForCategoryPicker by remember { mutableStateOf<String?>(null) }
    var selectedCategoryOption by remember { mutableStateOf("Personale") }
    var customCategoryInput by remember { mutableStateOf("") }
    var categoryDialogError by remember { mutableStateOf("") }

    // State for Personal Keypair Name Picker
    var keyForNamePicker by remember { mutableStateOf<String?>(null) }
    var keyNameInput by remember { mutableStateOf("") }
    var keyNameDialogError by remember { mutableStateOf("") }

    // Dialog state for Record Delete Confirmation
    var recordToDeleteIndex by remember { mutableStateOf<Int?>(null) }

    // Dialog state for Personal Keypair Delete Confirmation
    var personalKeyToDeleteId by remember { mutableStateOf<String?>(null) }

    // Dialog state for Symmetric Key Delete Confirmation
    var symmetricKeyToDelete by remember { mutableStateOf<ArchiveRecord.ContactSymmetricKeyRecord?>(null) }

    // Dialog state for Close Confirmation with Unsaved Changes
    var showCloseConfirmationDialog by remember { mutableStateOf(false) }

    // Dialog state for Discard Confirmation before Open or Create Action
    var pendingActionForDiscardConfirmation by remember { mutableStateOf<PendingArchiveDialogAction?>(null) }

    // Dialog state for Discard Confirmation before SAF Folder Change
    var pendingSelectedFolderUri by remember { mutableStateOf<Uri?>(null) }

    // State for SAF Key Import Confirmation Dialog
    var pendingImportResult by remember { mutableStateOf<ParsedPgpKeyResult?>(null) }

    // State for SAF Public/Private Key Export
    var pendingExportRecord by remember { mutableStateOf<ArchiveRecord?>(null) }

    fun processPendingKeyDeletions(payload: ArchivePayload, folderUri: Uri): Pair<ArchivePayload, Boolean> {
        val pendingKeys = StorageHelper.getPendingDeletedKeyIds(context, folderUri)
        if (pendingKeys.isEmpty()) {
            return Pair(payload, false)
        }

        val filteredRecords = payload.records.filterNot { record ->
            record is ArchiveRecord.ContactSymmetricKeyRecord && pendingKeys.contains(record.symmetricKeyId)
        }

        val wasModified = filteredRecords.size != payload.records.size
        return Pair(ArchivePayload(records = filteredRecords), wasModified)
    }

    // SAF Import Document Launcher for Contacts
    val openContactPgpDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        val targetContact = contactForPublicKeyImport
        if (uri != null && targetContact != null) {
            val existingKey = loadedPayload?.records?.filterIsInstance<ArchiveRecord.ContactPublicKeyRecord>()
                ?.firstOrNull { it.contactId == targetContact.contactId }

            if (existingKey != null) {
                archiveStatusMessage = "Il contatto '${targetContact.alias}' ha già una chiave pubblica PGP associata (${existingKey.keyId}). La procedura di sostituzione verrà implementata successivamente."
                contactForPublicKeyImport = null
                return@rememberLauncherForActivityResult
            }

            isOperating = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val fileBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    if ((fileBytes == null) || fileBytes.isEmpty()) {
                        withContext(Dispatchers.Main) {
                            isOperating = false
                            contactForPublicKeyImport = null
                            archiveStatusMessage = "Errore importazione: file vuoto o non accessibile."
                        }
                        return@launch
                    }

                    val parseResult = PgpKeyParser.parseKeyData(fileBytes)
                    withContext(Dispatchers.Main) {
                        isOperating = false
                        contactForPublicKeyImport = null
                        when (parseResult) {
                            is ParsedPgpKeyResult.PublicKeyResult -> {
                                val newRecord = ArchiveRecord.ContactPublicKeyRecord(
                                    contactId = targetContact.contactId,
                                    keyId = parseResult.keyIdHex,
                                    keyData = fileBytes,
                                )
                                val currentRecords = loadedPayload?.records ?: emptyList()
                                loadedPayload = ArchivePayload(records = currentRecords + newRecord)
                                hasUnsavedChanges = true
                                archiveStatusMessage = "Chiave pubblica ${parseResult.keyIdHex} associata al contatto '${targetContact.alias}' (modifica pendente)."
                            }
                            is ParsedPgpKeyResult.PrivateKeyResult -> {
                                archiveStatusMessage = "Errore: il file selezionato contiene una chiave PRIVATA. È possibile associare ai contatti solo chiavi PUBBLICHE."
                            }
                            is ParsedPgpKeyResult.Error -> {
                                archiveStatusMessage = "Errore analisi chiave OpenPGP: ${parseResult.message}"
                            }
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        isOperating = false
                        contactForPublicKeyImport = null
                        archiveStatusMessage = "Errore lettura file SAF: ${e.localizedMessage ?: "errore sconosciuto"}"
                    }
                }
            }
        } else {
            contactForPublicKeyImport = null
        }
    }

    // SAF Import Document Launcher (User Personal Keys)
    val openPgpDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
    ) { uri ->
        if (uri != null) {
            isOperating = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val fileBytes = context.contentResolver.openInputStream(uri)?.use { it.readBytes() }
                    if ((fileBytes == null) || fileBytes.isEmpty()) {
                        withContext(Dispatchers.Main) {
                            isOperating = false
                            archiveStatusMessage = "Errore importazione: file vuoto o non accessibile."
                        }
                        return@launch
                    }

                    val parseResult = PgpKeyParser.parseKeyData(fileBytes)
                    withContext(Dispatchers.Main) {
                        isOperating = false
                        when (parseResult) {
                            is ParsedPgpKeyResult.Error -> {
                                archiveStatusMessage = "Errore importazione OpenPGP: ${parseResult.message}"
                            }
                            is ParsedPgpKeyResult.PublicKeyResult -> {
                                val isDuplicate = loadedPayload?.records?.any {
                                    it is ArchiveRecord.PublicKeyRecord && it.keyId == parseResult.keyIdHex
                                } ?: false

                                if (isDuplicate) {
                                    archiveStatusMessage = "Chiave pubblica con ID ${parseResult.keyIdHex} già presente nell'archivio."
                                } else {
                                    pendingImportResult = parseResult
                                }
                            }
                            is ParsedPgpKeyResult.PrivateKeyResult -> {
                                val isDuplicate = loadedPayload?.records?.any {
                                    it is ArchiveRecord.PrivateKeyRecord && it.keyId == parseResult.keyIdHex
                                } ?: false

                                if (isDuplicate) {
                                    archiveStatusMessage = "Chiave privata con ID ${parseResult.keyIdHex} già presente nell'archivio."
                                } else {
                                    pendingImportResult = parseResult
                                }
                            }
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        isOperating = false
                        archiveStatusMessage = "Errore lettura file SAF: ${e.localizedMessage ?: "errore sconosciuto"}"
                    }
                }
            }
        }
    }

    // SAF Export Document Launcher (Public or Private Key)
    val exportPgpDocumentLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.CreateDocument("application/pgp-keys"),
    ) { uri ->
        val recordToExport = pendingExportRecord
        if (uri != null && recordToExport != null) {
            isOperating = true
            coroutineScope.launch(Dispatchers.IO) {
                try {
                    val keyData = when (recordToExport) {
                        is ArchiveRecord.PublicKeyRecord -> recordToExport.keyData
                        is ArchiveRecord.PrivateKeyRecord -> recordToExport.keyData
                        else -> byteArrayOf()
                    }

                    val keyIdStr = when (recordToExport) {
                        is ArchiveRecord.PublicKeyRecord -> recordToExport.keyId
                        is ArchiveRecord.PrivateKeyRecord -> recordToExport.keyId
                        else -> ""
                    }

                    val isPublic = recordToExport is ArchiveRecord.PublicKeyRecord
                    val isAlreadyAsciiArmor = String(keyData, StandardCharsets.UTF_8).contains("-----BEGIN PGP")

                    val bytesToWrite = if (isAlreadyAsciiArmor) {
                        keyData
                    } else {
                        val armorOut = ByteArrayOutputStream()
                        ArmoredOutputStream(armorOut).use { it.write(keyData) }
                        armorOut.toByteArray()
                    }

                    context.contentResolver.openOutputStream(uri)?.use { out ->
                        out.write(bytesToWrite)
                        out.flush()
                    }

                    withContext(Dispatchers.Main) {
                        isOperating = false
                        pendingExportRecord = null
                        archiveStatusMessage = if (isPublic) {
                            "Chiave pubblica $keyIdStr esportata con successo in ASCII Armor (.asc)!"
                        } else {
                            "Chiave privata cifrata $keyIdStr esportata con successo in ASCII Armor (.asc)!"
                        }
                    }
                } catch (e: Exception) {
                    withContext(Dispatchers.Main) {
                        isOperating = false
                        pendingExportRecord = null
                        archiveStatusMessage = "Errore esportazione chiave: ${e.localizedMessage ?: "errore I/O"}"
                    }
                }
            }
        } else {
            pendingExportRecord = null
        }
    }

    // Ripristino e verifica asincrona all'avvio della schermata
    LaunchedEffect(Unit) {
        val savedUri = StorageHelper.getSavedFolderUri(context)
        currentSavedUri = savedUri
        if (savedUri == null) {
            folderStatus = "Nessuna cartella selezionata."
            isFolderAccessible = false
        } else {
            val result = StorageHelper.checkFolderAccessibility(context, savedUri)
            when (result) {
                is FolderAccessResult.Success -> {
                    folderStatus = "Cartella selezionata: '${result.folderName}'\n" +
                        "Lettura: ${if (result.canRead) "Concessa" else "Negata"} | " +
                        "Scrittura: ${if (result.canWrite) "Concessa" else "Negata"}"
                    isFolderAccessible = true
                }
                is FolderAccessResult.Error -> {
                    folderStatus = "Stato: ${result.message}"
                    isFolderAccessible = false
                }
                is FolderAccessResult.Cancelled -> {
                    folderStatus = "Nessuna cartella selezionata."
                    isFolderAccessible = false
                }
            }
        }
    }

    val folderPickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocumentTree(),
    ) { uri ->
        if (uri != null) {
            if (hasUnsavedChanges) {
                pendingSelectedFolderUri = uri
            } else {
                StorageHelper.saveSelectedFolder(context, uri)
                currentSavedUri = uri
                val result = StorageHelper.processSelectedFolder(context, uri)
                when (result) {
                    is FolderAccessResult.Success -> {
                        folderStatus = "Cartella selezionata: '${result.folderName}'\n" +
                            "Lettura: ${if (result.canRead) "Concessa" else "Negata"} | " +
                            "Scrittura: ${if (result.canWrite) "Concessa" else "Negata"}"
                        isFolderAccessible = true
                    }
                    is FolderAccessResult.Error -> {
                        folderStatus = "Stato: ${result.message}"
                        isFolderAccessible = false
                    }
                    is FolderAccessResult.Cancelled -> {
                        folderStatus = "Selezione annullata dall'utente."
                        isFolderAccessible = false
                    }
                }
                archiveStatusMessage = ""
                loadedPayload = null
                selectedContactDetail = null
                hasUnsavedChanges = false
            }
        } else {
            folderStatus = "Selezione annullata dall'utente."
        }
    }

    // Confirmation Dialog for SAF OpenPGP Key Import
    if (pendingImportResult != null) {
        val importRes = pendingImportResult!!
        val isPublic = (importRes is ParsedPgpKeyResult.PublicKeyResult)
        val keyIdHex = when (importRes) {
            is ParsedPgpKeyResult.PublicKeyResult -> importRes.keyIdHex
            is ParsedPgpKeyResult.PrivateKeyResult -> importRes.keyIdHex
            is ParsedPgpKeyResult.Error -> ""
        }
        val userIdStr = when (importRes) {
            is ParsedPgpKeyResult.PublicKeyResult -> importRes.userId
            is ParsedPgpKeyResult.PrivateKeyResult -> importRes.userId
            is ParsedPgpKeyResult.Error -> null
        }
        val fpHex = when (importRes) {
            is ParsedPgpKeyResult.PublicKeyResult -> importRes.fingerprintHex
            is ParsedPgpKeyResult.PrivateKeyResult -> importRes.fingerprintHex
            is ParsedPgpKeyResult.Error -> ""
        }
        val rawData = when (importRes) {
            is ParsedPgpKeyResult.PublicKeyResult -> importRes.rawKeyData
            is ParsedPgpKeyResult.PrivateKeyResult -> importRes.rawKeyData
            is ParsedPgpKeyResult.Error -> byteArrayOf()
        }

        AlertDialog(
            onDismissRequest = { pendingImportResult = null },
            title = { Text(if (isPublic) "Conferma Importazione Chiave Pubblica" else "Conferma Importazione Chiave Privata") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Dati estrapolati dal pacchetto OpenPGP:", style = MaterialTheme.typography.bodyMedium)
                    Text("• Key ID: $keyIdHex", style = MaterialTheme.typography.bodySmall, fontWeight = FontWeight.Bold)
                    Text("• User ID: ${userIdStr ?: "Nessun User ID"}", style = MaterialTheme.typography.bodySmall)
                    Text("• Fingerprint: $fpHex", style = MaterialTheme.typography.bodySmall)
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        if (isPublic) {
                            "La chiave pubblica verrà aggiunta all'archivio in memoria."
                        } else {
                            "La chiave privata ed la relativa chiave pubblica estratta verranno aggiunte all'archivio in memoria."
                        },
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
                    )
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val currentRecords = loadedPayload?.records ?: emptyList()
                        val newRecords = mutableListOf<ArchiveRecord>()

                        if (importRes is ParsedPgpKeyResult.PublicKeyResult) {
                            val hasPublic = currentRecords.any {
                                it is ArchiveRecord.PublicKeyRecord && it.keyId == keyIdHex
                            }
                            if (!hasPublic) {
                                newRecords.add(ArchiveRecord.PublicKeyRecord(keyIdHex, rawData))
                            }
                        } else if (importRes is ParsedPgpKeyResult.PrivateKeyResult) {
                            val hasPrivate = currentRecords.any {
                                it is ArchiveRecord.PrivateKeyRecord && it.keyId == keyIdHex
                            }
                            if (!hasPrivate) {
                                newRecords.add(ArchiveRecord.PrivateKeyRecord(keyIdHex, rawData))
                            }

                            val pubBytes = importRes.rawPublicKeyData
                            if (pubBytes != null && pubBytes.isNotEmpty()) {
                                val hasPublic = currentRecords.any {
                                    it is ArchiveRecord.PublicKeyRecord && it.keyId == keyIdHex
                                }
                                if (!hasPublic) {
                                    newRecords.add(ArchiveRecord.PublicKeyRecord(keyIdHex, pubBytes))
                                }
                            }
                        }

                        if (newRecords.isNotEmpty()) {
                            loadedPayload = ArchivePayload(records = currentRecords + newRecords)
                            hasUnsavedChanges = true
                            archiveStatusMessage = if (!isPublic && newRecords.size > 1) {
                                "Chiave privata e relativa chiave pubblica ($keyIdHex) importate nell'archivio in memoria (modifica pendente)."
                            } else {
                                "Chiave $keyIdHex importata nell'archivio in memoria (modifica pendente)."
                            }
                        } else {
                            archiveStatusMessage = "Chiave $keyIdHex già totalmente presente nell'archivio."
                        }
                        pendingImportResult = null
                    },
                ) {
                    Text("Importa Chiave")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingImportResult = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Dialog for Personal Key Name Assignment
    if (keyForNamePicker != null) {
        val targetKeyId = keyForNamePicker!!
        AlertDialog(
            onDismissRequest = {
                keyForNamePicker = null
                keyNameDialogError = ""
            },
            title = { Text("Assegna Nome a Chiave Personale ($targetKeyId)") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Inserisci un nome o alias identificativo per questa chiave:", style = MaterialTheme.typography.bodyMedium)
                    OutlinedTextField(
                        value = keyNameInput,
                        onValueChange = { keyNameInput = it },
                        label = { Text("Nome della chiave (es. Lavoro Principale)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (keyNameDialogError.isNotEmpty()) {
                        Text(
                            text = keyNameDialogError,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val trimmedName = keyNameInput.trim()
                        if (trimmedName.isEmpty()) {
                            keyNameDialogError = "Inserisci un nome per la chiave."
                        } else {
                            val currentRecords = loadedPayload?.records?.filterNot {
                                it is ArchiveRecord.KeyNameRecord && it.keyId == targetKeyId
                            } ?: emptyList()

                            val newNameRecord = ArchiveRecord.KeyNameRecord(
                                keyId = targetKeyId,
                                name = trimmedName,
                            )

                            loadedPayload = ArchivePayload(records = currentRecords + newNameRecord)
                            hasUnsavedChanges = true
                            archiveStatusMessage = "Nome '$trimmedName' assegnato alla chiave $targetKeyId (modifica pendente)."
                            keyForNamePicker = null
                            keyNameInput = ""
                            keyNameDialogError = ""
                        }
                    },
                ) {
                    Text("Salva Nome")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        keyForNamePicker = null
                        keyNameDialogError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Dialog for Personal Key Category Selection
    if (keyForCategoryPicker != null) {
        val targetKeyId = keyForCategoryPicker!!
        AlertDialog(
            onDismissRequest = {
                keyForCategoryPicker = null
                categoryDialogError = ""
            },
            title = { Text("Seleziona Categoria per Chiave Personale ($targetKeyId)") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Scegli la categoria da associare a questa coppia di chiavi:", style = MaterialTheme.typography.bodyMedium)

                    PREDEFINED_CATEGORIES.forEach { categoryOption ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = selectedCategoryOption == categoryOption,
                                onClick = { selectedCategoryOption = categoryOption },
                            )
                            Text(categoryOption)
                        }
                    }

                    if (selectedCategoryOption == "Altro") {
                        OutlinedTextField(
                            value = customCategoryInput,
                            onValueChange = { customCategoryInput = it },
                            label = { Text("Nome categoria personalizzata") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    if (categoryDialogError.isNotEmpty()) {
                        Text(
                            text = categoryDialogError,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val finalCategory = if (selectedCategoryOption == "Altro") {
                            customCategoryInput.trim()
                        } else {
                            selectedCategoryOption
                        }

                        if (finalCategory.isEmpty()) {
                            categoryDialogError = "Inserisci un nome per la categoria personalizzata."
                        } else {
                            val currentRecords = loadedPayload?.records?.filterNot {
                                it is ArchiveRecord.KeyCategoryRecord && it.keyId == targetKeyId
                            } ?: emptyList()

                            val newCategoryRecord = ArchiveRecord.KeyCategoryRecord(
                                keyId = targetKeyId,
                                category = finalCategory,
                            )

                            loadedPayload = ArchivePayload(records = currentRecords + newCategoryRecord)
                            hasUnsavedChanges = true
                            archiveStatusMessage = "Categoria '$finalCategory' associata alla chiave $targetKeyId (modifica pendente)."
                            keyForCategoryPicker = null
                            customCategoryInput = ""
                            categoryDialogError = ""
                        }
                    },
                ) {
                    Text("Salva Categoria")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        keyForCategoryPicker = null
                        categoryDialogError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Dialog for Generating a New PGP Keypair
    if (showGeneratePgpDialog) {
        AlertDialog(
            onDismissRequest = {
                if (!isOperating) {
                    showGeneratePgpDialog = false
                    generateDialogError = ""
                }
            },
            title = { Text("Genera Nuova Coppia PGP On-Device") },
            text = {
                Column(
                    modifier = Modifier.verticalScroll(rememberScrollState()),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("Imposta i dati per la nuova identità PGP:", style = MaterialTheme.typography.bodyMedium)

                    OutlinedTextField(
                        value = genKeyNameInput,
                        onValueChange = { genKeyNameInput = it },
                        label = { Text("Nome della chiave (es. Lavoro Principale)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isOperating,
                    )

                    OutlinedTextField(
                        value = genUserIdInput,
                        onValueChange = { genUserIdInput = it },
                        label = { Text("User ID PGP (es. Mario Rossi <mario@example.com>)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isOperating,
                    )

                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Categoria:", style = MaterialTheme.typography.labelMedium)
                    PREDEFINED_CATEGORIES.forEach { categoryOption ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = genSelectedCategory == categoryOption,
                                onClick = { genSelectedCategory = categoryOption },
                                enabled = !isOperating,
                            )
                            Text(categoryOption)
                        }
                    }

                    if (genSelectedCategory == "Altro") {
                        OutlinedTextField(
                            value = genCustomCategoryInput,
                            onValueChange = { genCustomCategoryInput = it },
                            label = { Text("Nome categoria personalizzata") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !isOperating,
                        )
                    }

                    Spacer(modifier = Modifier.height(4.dp))
                    Text("Profilo Crittografico:", style = MaterialTheme.typography.labelMedium)
                    PgpProfile.entries.forEach { profile ->
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            RadioButton(
                                selected = genSelectedProfile == profile,
                                onClick = { genSelectedProfile = profile },
                                enabled = !isOperating,
                            )
                            Column {
                                Text(profile.label, fontWeight = FontWeight.Bold)
                                Text(profile.description, style = MaterialTheme.typography.bodySmall)
                            }
                        }
                    }

                    if (genSelectedProfile.isV6) {
                        Surface(
                            color = MaterialTheme.colorScheme.errorContainer.copy(alpha = 0.5f),
                            shape = MaterialTheme.shapes.extraSmall,
                        ) {
                            Text(
                                text = "⚠️ Avviso: Il formato OpenPGP v6 (RFC 9580) offre la massima modernità, ma ha compatibilità limitata con vecchi software esterni (es. OpenKeychain).",
                                modifier = Modifier.padding(6.dp),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                            )
                        }
                    }

                    Spacer(modifier = Modifier.height(4.dp))
                    OutlinedTextField(
                        value = genPassphraseInput,
                        onValueChange = { genPassphraseInput = it },
                        label = { Text("Passphrase di protezione chiave privata") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isOperating,
                    )

                    OutlinedTextField(
                        value = genPassphraseConfirmInput,
                        onValueChange = { genPassphraseConfirmInput = it },
                        label = { Text("Conferma Passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isOperating,
                    )

                    if (generateDialogError.isNotEmpty()) {
                        Text(
                            text = generateDialogError,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    if (isOperating) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(modifier = Modifier.height(24.dp))
                            Text("Generazione coppia PGP in corso sul dispositivo...", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    enabled = !isOperating,
                    onClick = {
                        val nameTrim = genKeyNameInput.trim()
                        val userIdTrim = genUserIdInput.trim()
                        val categoryTrim = if (genSelectedCategory == "Altro") genCustomCategoryInput.trim() else genSelectedCategory

                        if (nameTrim.isEmpty()) {
                            generateDialogError = "Il nome della chiave è obbligatorio."
                            return@Button
                        }
                        if (userIdTrim.isEmpty()) {
                            generateDialogError = "L'User ID PGP è obbligatorio."
                            return@Button
                        }
                        if (categoryTrim.isEmpty()) {
                            generateDialogError = "La categoria è obbligatoria."
                            return@Button
                        }
                        if (genPassphraseInput.isEmpty()) {
                            generateDialogError = "La passphrase è obbligatoria per proteggere la chiave privata."
                            return@Button
                        }
                        if (genPassphraseInput != genPassphraseConfirmInput) {
                            generateDialogError = "Le due passphrase inserite non coincidono."
                            return@Button
                        }

                        isOperating = true
                        generateDialogError = ""

                        val passChars = genPassphraseInput.toCharArray()
                        genPassphraseInput = ""
                        genPassphraseConfirmInput = ""

                        coroutineScope.launch(Dispatchers.IO) {
                            try {
                                val genRes = PgpKeyGenerator.generateKeypair(
                                    userId = userIdTrim,
                                    passphrase = passChars,
                                    profile = genSelectedProfile,
                                )

                                withContext(Dispatchers.Main) {
                                    val currentRecords = loadedPayload?.records ?: emptyList()
                                    val keyId = genRes.keyIdHex

                                    val newPriv = ArchiveRecord.PrivateKeyRecord(keyId, genRes.privateKeyAsciiArmor)
                                    val newPub = ArchiveRecord.PublicKeyRecord(keyId, genRes.publicKeyAsciiArmor)
                                    val newName = ArchiveRecord.KeyNameRecord(keyId, nameTrim)
                                    val newCat = ArchiveRecord.KeyCategoryRecord(keyId, categoryTrim)

                                    loadedPayload = ArchivePayload(records = currentRecords + listOf(newPriv, newPub, newName, newCat))
                                    hasUnsavedChanges = true
                                    archiveStatusMessage = "Nuova coppia PGP '$nameTrim' ($keyId) generata con successo nell'archivio in memoria (modifica pendente)."
                                    isOperating = false
                                    showGeneratePgpDialog = false
                                }
                            } catch (e: Exception) {
                                withContext(Dispatchers.Main) {
                                    isOperating = false
                                    generateDialogError = "Errore durante la generazione PGP: ${e.localizedMessage ?: "Errore sconosciuto"}"
                                }
                            } finally {
                                ArchiveCrypto.zeroize(passChars)
                            }
                        }
                    },
                ) {
                    Text("Genera Chiave")
                }
            },
            dismissButton = {
                TextButton(
                    enabled = !isOperating,
                    onClick = {
                        showGeneratePgpDialog = false
                        generateDialogError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Dialog for Assigning Personal Keypair to a Contact
    if (contactForOwnerKeyAssignment != null) {
        val targetContact = contactForOwnerKeyAssignment!!
        val availablePersonalKeyIds = loadedPayload?.records?.let { getCompletePersonalKeypairIds(it) } ?: emptyList()

        AlertDialog(
            onDismissRequest = {
                contactForOwnerKeyAssignment = null
                selectedOwnerKeyIdOption = null
            },
            title = { Text("Associa Chiave Personale a '${targetContact.alias}'") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    if (availablePersonalKeyIds.isEmpty()) {
                        Text(
                            text = "Nessuna chiave PGP personale completa (privata + pubblica) trovata nell'archivio.\nImporta o crea prima una chiave personale completa.",
                            style = MaterialTheme.typography.bodyMedium,
                            color = MaterialTheme.colorScheme.error,
                        )
                    } else {
                        Text(
                            text = "Seleziona la coppia di chiavi personali dell'utente da associare a questo contatto:",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                        availablePersonalKeyIds.forEach { keyId ->
                            val keyName = loadedPayload?.records
                                ?.filterIsInstance<ArchiveRecord.KeyNameRecord>()
                                ?.firstOrNull { it.keyId == keyId }?.name
                            val cat = loadedPayload?.records
                                ?.filterIsInstance<ArchiveRecord.KeyCategoryRecord>()
                                ?.firstOrNull { it.keyId == keyId }?.category ?: "Personale"

                            val labelStr = if (keyName != null) {
                                "$keyName ($keyId - 🏷️ $cat)"
                            } else {
                                "Key ID: $keyId (🏷️ $cat)"
                            }

                            Row(verticalAlignment = Alignment.CenterVertically) {
                                RadioButton(
                                    selected = selectedOwnerKeyIdOption == keyId,
                                    onClick = { selectedOwnerKeyIdOption = keyId },
                                )
                                Text(labelStr)
                            }
                        }
                    }
                }
            },
            confirmButton = {
                if (availablePersonalKeyIds.isNotEmpty()) {
                    Button(
                        enabled = selectedOwnerKeyIdOption != null,
                        onClick = {
                            val chosenOwnerKeyId = selectedOwnerKeyIdOption!!
                            val filteredRecords = loadedPayload?.records?.filterNot {
                                it is ArchiveRecord.ContactOwnerKeyRecord && it.contactId == targetContact.contactId
                            } ?: emptyList()

                            val newBindingRecord = ArchiveRecord.ContactOwnerKeyRecord(
                                contactId = targetContact.contactId,
                                ownerKeyId = chosenOwnerKeyId,
                            )

                            loadedPayload = ArchivePayload(records = filteredRecords + newBindingRecord)
                            hasUnsavedChanges = true
                            archiveStatusMessage = "Chiave personale $chosenOwnerKeyId associata al contatto '${targetContact.alias}' (modifica pendente)."
                            contactForOwnerKeyAssignment = null
                            selectedOwnerKeyIdOption = null
                        },
                    ) {
                        Text("Associa Chiave")
                    }
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        contactForOwnerKeyAssignment = null
                        selectedOwnerKeyIdOption = null
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Personal Keypair Delete Confirmation Dialog
    if (personalKeyToDeleteId != null) {
        val targetKeyId = personalKeyToDeleteId!!
        AlertDialog(
            onDismissRequest = { personalKeyToDeleteId = null },
            title = { Text("Conferma Eliminazione Chiave Personale") },
            text = {
                Text(
                    "Sei sicuro di voler eliminare la chiave personale (Key ID: $targetKeyId) dall'archivio in memoria?\n" +
                        "Verranno rimosse la componente privata, la componente pubblica e i relativi metadati (nome e categoria).",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        val currentRecords = loadedPayload?.records?.toMutableList() ?: mutableListOf()
                        currentRecords.removeAll { record ->
                            when (record) {
                                is ArchiveRecord.PrivateKeyRecord -> record.keyId == targetKeyId
                                is ArchiveRecord.PublicKeyRecord -> record.keyId == targetKeyId
                                is ArchiveRecord.KeyNameRecord -> record.keyId == targetKeyId
                                is ArchiveRecord.KeyCategoryRecord -> record.keyId == targetKeyId
                                is ArchiveRecord.ContactOwnerKeyRecord -> record.ownerKeyId == targetKeyId
                                else -> false
                            }
                        }
                        loadedPayload = ArchivePayload(records = currentRecords)
                        hasUnsavedChanges = true
                        archiveStatusMessage = "Chiave personale $targetKeyId eliminata dall'archivio in memoria (modifica pendente)."
                        personalKeyToDeleteId = null
                    },
                ) {
                    Text("Elimina Chiave", color = MaterialTheme.colorScheme.error)
                }
            },
            dismissButton = {
                TextButton(onClick = { personalKeyToDeleteId = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Confirmation Dialog for Symmetric Key Deletion
    if (symmetricKeyToDelete != null) {
        val symKey = symmetricKeyToDelete!!
        AlertDialog(
            onDismissRequest = { symmetricKeyToDelete = null },
            title = { Text("Conferma Eliminazione Chiave Simmetrica") },
            text = {
                Text(
                    "Sei sicuro di voler eliminare la chiave simmetrica (ID: ${symKey.symmetricKeyId})?\n" +
                        "I vecchi messaggi ed i file cifrati con questa chiave potrebbero non essere più decifrabili.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        val targetUri = currentSavedUri ?: StorageHelper.getSavedFolderUri(context)
                        if (targetUri != null) {
                            val ok = StorageHelper.addPendingDeletedKeyId(context, targetUri, symKey.symmetricKeyId)
                            if (ok) {
                                val currentRecords = loadedPayload?.records?.toMutableList() ?: mutableListOf()
                                currentRecords.remove(symKey)
                                loadedPayload = ArchivePayload(records = currentRecords)
                                hasUnsavedChanges = true
                                archiveStatusMessage = "Chiave simmetrica ${symKey.symmetricKeyId} eliminata in memoria (modifica pendente)."
                                symmetricKeyToDelete = null
                            } else {
                                archiveStatusMessage = "Errore durante la registrazione della richiesta pendente di eliminazione."
                            }
                        } else {
                            archiveStatusMessage = "Nessuna cartella SAF selezionata per registrare l'eliminazione."
                        }
                    },
                ) {
                    Text("Elimina Chiave")
                }
            },
            dismissButton = {
                TextButton(onClick = { symmetricKeyToDelete = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Dialog for Adding a New Contact
    if (showAddContactDialog) {
        AlertDialog(
            onDismissRequest = {
                showAddContactDialog = false
                contactAliasInput = ""
                addContactError = ""
            },
            title = { Text("Aggiungi Nuovo Contatto") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = "Inserisci l'alias locale con cui identificare il contatto:",
                        style = MaterialTheme.typography.bodyMedium,
                    )
                    OutlinedTextField(
                        value = contactAliasInput,
                        onValueChange = { contactAliasInput = it },
                        label = { Text("Alias contatto (es. Marco)") },
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    if (addContactError.isNotEmpty()) {
                        Text(
                            text = addContactError,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val trimmedAlias = contactAliasInput.trim()
                        if (trimmedAlias.isEmpty()) {
                            addContactError = "L'alias del contatto è obbligatorio."
                        } else {
                            val generatedContactId = "cnt_" + UUID.randomUUID().toString()
                            val newContactRecord = ArchiveRecord.ContactRecord(
                                contactId = generatedContactId,
                                alias = trimmedAlias,
                            )
                            val currentRecords = loadedPayload?.records ?: emptyList()
                            loadedPayload = ArchivePayload(records = currentRecords + newContactRecord)
                            hasUnsavedChanges = true
                            archiveStatusMessage = "Contatto '$trimmedAlias' ($generatedContactId) aggiunto in memoria (modifica pendente)."
                            showAddContactDialog = false
                            contactAliasInput = ""
                            addContactError = ""
                        }
                    },
                ) {
                    Text("Salva Contatto")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showAddContactDialog = false
                        contactAliasInput = ""
                        addContactError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Confirmation Dialog before switching SAF folder with unsaved changes
    if (pendingSelectedFolderUri != null) {
        val newUri = pendingSelectedFolderUri!!
        AlertDialog(
            onDismissRequest = { pendingSelectedFolderUri = null },
            title = { Text("Modifiche Non Salvate") },
            text = {
                Text(
                    "L'archivio aperto contiene modifiche non salvate.\n" +
                        "Se selezioni una nuova cartella, le modifiche in memoria andranno perse.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        pendingSelectedFolderUri = null
                        StorageHelper.saveSelectedFolder(context, newUri)
                        currentSavedUri = newUri
                        val result = StorageHelper.processSelectedFolder(context, newUri)
                        when (result) {
                            is FolderAccessResult.Success -> {
                                folderStatus = "Cartella selezionata: '${result.folderName}'\n" +
                                    "Lettura: ${if (result.canRead) "Concessa" else "Negata"} | " +
                                    "Scrittura: ${if (result.canWrite) "Concessa" else "Negata"}"
                                isFolderAccessible = true
                            }
                            is FolderAccessResult.Error -> {
                                folderStatus = "Stato: ${result.message}"
                                isFolderAccessible = false
                            }
                            is FolderAccessResult.Cancelled -> {
                                folderStatus = "Selezione annullata dall'utente."
                                isFolderAccessible = false
                            }
                        }
                        archiveStatusMessage = ""
                        loadedPayload = null
                        selectedContactDetail = null
                        hasUnsavedChanges = false
                    },
                ) {
                    Text("Cambia Cartella Senza Salvare")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingSelectedFolderUri = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Confirmation Dialog before Open or Create Action with unsaved changes
    if (pendingActionForDiscardConfirmation != null) {
        val targetAction = pendingActionForDiscardConfirmation!!
        AlertDialog(
            onDismissRequest = { pendingActionForDiscardConfirmation = null },
            title = { Text("Modifiche Non Salvate") },
            text = {
                Text(
                    "L'archivio aperto contiene modifiche non salvate sulla scheda SD.\n" +
                        "Se prosegui con questa operazione, le modifiche pendenti andranno perse.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        pendingActionForDiscardConfirmation = null
                        passphraseInput = ""
                        passphraseConfirmInput = ""
                        dialogError = ""
                        pendingDialogAction = targetAction
                    },
                ) {
                    Text("Prosegui Senza Salvare")
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingActionForDiscardConfirmation = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Passphrase Dialog
    if (pendingDialogAction != null) {
        val action = pendingDialogAction!!
        val isCreating = (action == PendingArchiveDialogAction.CREATE_ARCHIVE)

        AlertDialog(
            onDismissRequest = {
                if (!isOperating) {
                    pendingDialogAction = null
                    passphraseInput = ""
                    passphraseConfirmInput = ""
                    dialogError = ""
                }
            },
            title = {
                Text(
                    text = when (action) {
                        PendingArchiveDialogAction.CREATE_ARCHIVE -> "Crea Nuovo Archivio Cifrato"
                        PendingArchiveDialogAction.OPEN_ARCHIVE -> "Apri Archivio Cifrato"
                        PendingArchiveDialogAction.SAVE_ARCHIVE -> "Salva Archivio Cifrato"
                    },
                )
            },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text(
                        text = when (action) {
                            PendingArchiveDialogAction.CREATE_ARCHIVE ->
                                "Immetti una passphrase sicura per cifrare il nuovo archivio sulla scheda SD."
                            PendingArchiveDialogAction.OPEN_ARCHIVE ->
                                "Inserisci la passphrase utilizzata per proteggere l'archivio."
                            PendingArchiveDialogAction.SAVE_ARCHIVE ->
                                "Inserisci la passphrase per cifrare la nuova generazione dell'archivio."
                        },
                        style = MaterialTheme.typography.bodyMedium,
                    )

                    OutlinedTextField(
                        value = passphraseInput,
                        onValueChange = { passphraseInput = it },
                        label = { Text("Passphrase") },
                        visualTransformation = PasswordVisualTransformation(),
                        singleLine = true,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !isOperating,
                    )

                    if (isCreating) {
                        OutlinedTextField(
                            value = passphraseConfirmInput,
                            onValueChange = { passphraseConfirmInput = it },
                            label = { Text("Conferma Passphrase") },
                            visualTransformation = PasswordVisualTransformation(),
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                            enabled = !isOperating,
                        )
                    }

                    if (dialogError.isNotEmpty()) {
                        Text(
                            text = dialogError,
                            color = MaterialTheme.colorScheme.error,
                            style = MaterialTheme.typography.bodySmall,
                        )
                    }

                    if (isOperating) {
                        Row(
                            horizontalArrangement = Arrangement.spacedBy(8.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            CircularProgressIndicator(modifier = Modifier.height(24.dp))
                            Text("Operazione crittografica in corso...", style = MaterialTheme.typography.bodySmall)
                        }
                    }
                }
            },
            confirmButton = {
                Button(
                    enabled = !isOperating && passphraseInput.isNotEmpty(),
                    onClick = {
                        val targetUri = currentSavedUri
                        if (targetUri == null) {
                            dialogError = "Nessuna cartella selezionata."
                            return@Button
                        }

                        if (isCreating && (passphraseInput != passphraseConfirmInput)) {
                            dialogError = "Le due passphrase inserite non coincidono."
                            return@Button
                        }

                        isOperating = true
                        dialogError = ""

                        val passphraseChars = passphraseInput.toCharArray()
                        passphraseInput = ""
                        passphraseConfirmInput = ""

                        coroutineScope.launch(Dispatchers.IO) {
                            try {
                                when (action) {
                                    PendingArchiveDialogAction.CREATE_ARCHIVE -> {
                                        val initialRecords = listOf(
                                            ArchiveRecord.MetadataRecord("created_by", "SecurePGP"),
                                            ArchiveRecord.MetadataRecord("archive_status", "Initialized"),
                                        )
                                        val saveRes = archiveRepository.createNewArchive(
                                            context = context,
                                            treeUri = targetUri,
                                            passphrase = passphraseChars,
                                            initialRecords = initialRecords,
                                        )
                                        withContext(Dispatchers.Main) {
                                            isOperating = false
                                            pendingDialogAction = null
                                            archiveStatusMessage = when (saveRes) {
                                                is RepositorySaveResult.Success -> {
                                                    loadedPayload = ArchivePayload(records = initialRecords)
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = false
                                                    "Archivio creato con successo! (Generazione g${saveRes.generationIndex})"
                                                }
                                                is RepositorySaveResult.VerifiedNotPromoted -> {
                                                    loadedPayload = ArchivePayload(records = initialRecords)
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = true
                                                    "⚠️ ERRORE SALVATAGGIO: Il provider SAF di questa cartella non supporta la rinomina dei file. L'archivio g${saveRes.generationIndex} non potrà essere ricaricato alla riapertura dell'app. Seleziona un'altra cartella o memoria."
                                                }
                                                is RepositorySaveResult.Error -> "Errore durante la creazione: ${saveRes.message}"
                                            }
                                        }
                                    }
                                    PendingArchiveDialogAction.OPEN_ARCHIVE -> {
                                        val loadRes = archiveRepository.openArchive(
                                            context = context,
                                            treeUri = targetUri,
                                            passphrase = passphraseChars,
                                        )
                                        withContext(Dispatchers.Main) {
                                            isOperating = false
                                            pendingDialogAction = null
                                            archiveStatusMessage = when (loadRes) {
                                                is RepositoryLoadResult.Success -> {
                                                    val (adjustedPayload, modified) = processPendingKeyDeletions(loadRes.payload, targetUri)
                                                    loadedPayload = adjustedPayload
                                                    selectedContactDetail = null
                                                    if (modified) {
                                                        hasUnsavedChanges = true
                                                        "Archivio aperto: applicata la rimozione pendente della chiave simmetrica. Salva l'archivio per completare la pulizia SAF."
                                                    } else {
                                                        hasUnsavedChanges = false
                                                        "Archivio aperto con successo!\n" +
                                                            "・ Generazione attiva: g${loadRes.generationIndex}\n" +
                                                            "・ Record carichi: ${adjustedPayload.records.size}"
                                                    }
                                                }
                                                is RepositoryLoadResult.NoArchiveFound -> {
                                                    loadedPayload = null
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = false
                                                    "Nessun archivio cifrato trovato nella cartella selezionata."
                                                }
                                                is RepositoryLoadResult.AuthenticationFailed -> {
                                                    loadedPayload = null
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = false
                                                    "Passphrase errata o archivio alterato/manomesso."
                                                }
                                                is RepositoryLoadResult.CorruptedArchive -> {
                                                    loadedPayload = null
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = false
                                                    "Archivio danneggiato o malformato: ${loadRes.message}"
                                                }
                                                is RepositoryLoadResult.Error -> {
                                                    loadedPayload = null
                                                    selectedContactDetail = null
                                                    hasUnsavedChanges = false
                                                    "Errore di lettura storage SAF: ${loadRes.message}"
                                                }
                                            }
                                        }
                                    }
                                    PendingArchiveDialogAction.SAVE_ARCHIVE -> {
                                        val payloadToSave = loadedPayload ?: ArchivePayload(records = emptyList())
                                        val saveRes = archiveRepository.saveArchivePayload(
                                            context = context,
                                            treeUri = targetUri,
                                            payload = payloadToSave,
                                            passphrase = passphraseChars,
                                        )
                                        withContext(Dispatchers.Main) {
                                            isOperating = false
                                            pendingDialogAction = null
                                            when (saveRes) {
                                                is RepositorySaveResult.Success -> {
                                                    hasUnsavedChanges = false
                                                    val pendingKeys = StorageHelper.getPendingDeletedKeyIds(context, targetUri)
                                                    if (pendingKeys.isNotEmpty()) {
                                                        val isKeyAbsent = payloadToSave.records.none {
                                                            it is ArchiveRecord.ContactSymmetricKeyRecord && pendingKeys.contains(it.symmetricKeyId)
                                                        }
                                                        if (isKeyAbsent) {
                                                            val cleaned = SdArchiveStorage.cleanOlderArchiveGenerations(
                                                                context,
                                                                targetUri,
                                                                saveRes.generationIndex,
                                                            )
                                                            if (cleaned) {
                                                                StorageHelper.clearPendingDeletedKeyIds(context, targetUri)
                                                                archiveStatusMessage = "Archivio salvato con successo (g${saveRes.generationIndex}) e vecchie generazioni eliminate dallo storage SAF."
                                                            } else {
                                                                archiveStatusMessage = "Archivio salvato con successo (g${saveRes.generationIndex}), ma la pulizia SAF è fallita (verrà ritentata)."
                                                            }
                                                        } else {
                                                            archiveStatusMessage = "Archivio salvato con successo (g${saveRes.generationIndex}). La pulizia SAF è stata sospesa perché la chiave risulta ancora presente nel payload."
                                                        }
                                                    } else {
                                                        archiveStatusMessage = "Archivio salvato con successo! (Nuova generazione: g${saveRes.generationIndex})"
                                                    }
                                                }
                                                is RepositorySaveResult.VerifiedNotPromoted -> {
                                                    hasUnsavedChanges = true
                                                    archiveStatusMessage = "⚠️ ERRORE SALVATAGGIO: Il provider SAF di questa cartella non supporta la rinomina dei file. Le modifiche pendenti rimangono in memoria ma NON saranno recuperabili alla riapertura dell'app (g${saveRes.generationIndex}). Seleziona un'altra cartella o memoria."
                                                }
                                                is RepositorySaveResult.Error -> {
                                                    archiveStatusMessage = "Errore durante il salvataggio: ${saveRes.message}"
                                                }
                                            }
                                        }
                                    }
                                }
                            } finally {
                                ArchiveCrypto.zeroize(passphraseChars)
                            }
                        }
                    },
                ) {
                    Text("Conferma")
                }
            },
            dismissButton = {
                TextButton(
                    enabled = !isOperating,
                    onClick = {
                        pendingDialogAction = null
                        passphraseInput = ""
                        passphraseConfirmInput = ""
                        dialogError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Add Record Dialog
    if (showAddRecordDialog) {
        AlertDialog(
            onDismissRequest = {
                showAddRecordDialog = false
                addRecordError = ""
            },
            title = { Text("Aggiungi Nuovo Record all'Archivio") },
            text = {
                Column(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    Text("Seleziona il tipo di record da aggiungere:", style = MaterialTheme.typography.bodyMedium)

                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = selectedRecordType == NewRecordType.PUBLIC_KEY,
                            onClick = { selectedRecordType = NewRecordType.PUBLIC_KEY },
                        )
                        Text("Chiave Pubblica PGP")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = selectedRecordType == NewRecordType.PRIVATE_KEY,
                            onClick = { selectedRecordType = NewRecordType.PRIVATE_KEY },
                        )
                        Text("Chiave Privata PGP")
                    }
                    Row(verticalAlignment = Alignment.CenterVertically) {
                        RadioButton(
                            selected = selectedRecordType == NewRecordType.METADATA,
                            onClick = { selectedRecordType = NewRecordType.METADATA },
                        )
                        Text("Metadato (Chiave/Valore)")
                    }

                    if ((selectedRecordType == NewRecordType.PUBLIC_KEY) || (selectedRecordType == NewRecordType.PRIVATE_KEY)) {
                        OutlinedTextField(
                            value = keyIdInput,
                            onValueChange = { keyIdInput = it },
                            label = { Text("Identificativo Chiave (Key ID)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = keyDataInput,
                            onValueChange = { keyDataInput = it },
                            label = { Text("Dati della chiave (Testo ASCII / Armor)") },
                            modifier = Modifier.fillMaxWidth().height(100.dp),
                        )
                    } else {
                        OutlinedTextField(
                            value = metadataKeyInput,
                            onValueChange = { metadataKeyInput = it },
                            label = { Text("Nome Metadato (Chiave)") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth(),
                        )
                        OutlinedTextField(
                            value = metadataValueInput,
                            onValueChange = { metadataValueInput = it },
                            label = { Text("Valore Metadato") },
                            modifier = Modifier.fillMaxWidth(),
                        )
                    }

                    if (addRecordError.isNotEmpty()) {
                        Text(text = addRecordError, color = MaterialTheme.colorScheme.error, style = MaterialTheme.typography.bodySmall)
                    }
                }
            },
            confirmButton = {
                Button(
                    onClick = {
                        val currentRecords = loadedPayload?.records ?: emptyList()
                        val newRecord: ArchiveRecord? = when (selectedRecordType) {
                            NewRecordType.PUBLIC_KEY -> {
                                if (keyIdInput.trim().isEmpty() || keyDataInput.trim().isEmpty()) {
                                    addRecordError = "Identificativo e dati della chiave sono obbligatori."
                                    null
                                } else {
                                    ArchiveRecord.PublicKeyRecord(
                                        keyId = keyIdInput.trim(),
                                        keyData = keyDataInput.toByteArray(StandardCharsets.UTF_8),
                                    )
                                }
                            }
                            NewRecordType.PRIVATE_KEY -> {
                                if (keyIdInput.trim().isEmpty() || keyDataInput.trim().isEmpty()) {
                                    addRecordError = "Identificativo e dati della chiave sono obbligatori."
                                    null
                                } else {
                                    ArchiveRecord.PrivateKeyRecord(
                                        keyId = keyIdInput.trim(),
                                        keyData = keyDataInput.toByteArray(StandardCharsets.UTF_8),
                                    )
                                }
                            }
                            NewRecordType.METADATA -> {
                                if (metadataKeyInput.trim().isEmpty()) {
                                    addRecordError = "La chiave del metadato è obbligatoria."
                                    null
                                } else {
                                    ArchiveRecord.MetadataRecord(
                                        key = metadataKeyInput.trim(),
                                        value = metadataValueInput.trim(),
                                    )
                                }
                            }
                        }

                        if (newRecord != null) {
                            loadedPayload = ArchivePayload(records = currentRecords + newRecord)
                            hasUnsavedChanges = true
                            showAddRecordDialog = false
                            keyIdInput = ""
                            keyDataInput = ""
                            metadataKeyInput = ""
                            metadataValueInput = ""
                            addRecordError = ""
                        }
                    },
                ) {
                    Text("Aggiungi")
                }
            },
            dismissButton = {
                TextButton(
                    onClick = {
                        showAddRecordDialog = false
                        addRecordError = ""
                    },
                ) {
                    Text("Annulla")
                }
            },
        )
    }

    // Delete Record Confirmation Dialog
    if (recordToDeleteIndex != null) {
        val targetIndex = recordToDeleteIndex!!
        AlertDialog(
            onDismissRequest = { recordToDeleteIndex = null },
            title = { Text("Conferma Rimozione Record") },
            text = {
                Text(
                    "Sei sicuro di voler rimuovere questo record dall'archivio in memoria?\n" +
                        "La modifica diventerà permanente sulla scheda SD soltanto dopo aver salvato l'archivio.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        val currentRecords = loadedPayload?.records?.toMutableList() ?: mutableListOf()
                        if (targetIndex in currentRecords.indices) {
                            currentRecords.removeAt(targetIndex)
                            loadedPayload = ArchivePayload(records = currentRecords)
                            hasUnsavedChanges = true
                        }
                        recordToDeleteIndex = null
                    },
                ) {
                    Text("Rimuovi")
                }
            },
            dismissButton = {
                TextButton(onClick = { recordToDeleteIndex = null }) {
                    Text("Annulla")
                }
            },
        )
    }

    // Close Confirmation Dialog when Unsaved Changes exist
    if (showCloseConfirmationDialog) {
        AlertDialog(
            onDismissRequest = { showCloseConfirmationDialog = false },
            title = { Text("Modifiche Non Salvate") },
            text = {
                Text(
                    "L'archivio contiene modifiche non salvate sulla scheda SD.\n" +
                        "Se chiudi l'archivio ora, le modifiche apportate in memoria andranno perse.",
                )
            },
            confirmButton = {
                Button(
                    onClick = {
                        loadedPayload = null
                        selectedContactDetail = null
                        hasUnsavedChanges = false
                        archiveStatusMessage = "Archivio chiuso (modifiche non salvate scartate)."
                        showCloseConfirmationDialog = false
                    },
                ) {
                    Text("Chiudi Senza Salvare")
                }
            },
            dismissButton = {
                TextButton(onClick = { showCloseConfirmationDialog = false }) {
                    Text("Annulla")
                }
            },
        )
    }

    Scaffold(
        modifier = Modifier.fillMaxSize(),
        topBar = {
            TopAppBar(
                title = {
                    Text(
                        text = "SecurePGP",
                        fontWeight = FontWeight.Bold,
                    )
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.primaryContainer,
                    titleContentColor = MaterialTheme.colorScheme.onPrimaryContainer,
                ),
            )
        },
    ) { innerPadding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(innerPadding)
                .verticalScroll(rememberScrollState())
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp),
        ) {
            // Avviso di versione iniziale
            Surface(
                modifier = Modifier.fillMaxWidth(),
                color = MaterialTheme.colorScheme.secondaryContainer,
                shape = MaterialTheme.shapes.medium,
            ) {
                Text(
                    text = "Versione iniziale — funzioni in sviluppo",
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp),
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                    fontWeight = FontWeight.Medium,
                )
            }

            // Sezione 1: Crittografia e decifratura
            SectionCard(
                title = "Crittografia e decifratura",
                description = "Sezione pianificata per cifrare e decifrare messaggi e file. La logica di protezione sarà implementata nelle prossime fasi.",
            )

            // Sezione 2: Archivio su scheda SD (Intestazione globale controlli)
            Card(
                modifier = Modifier.fillMaxWidth(),
                elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant,
                ),
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                ) {
                    Text(
                        text = "Archivio su scheda SD",
                        style = MaterialTheme.typography.titleMedium,
                        fontWeight = FontWeight.Bold,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "Gestione del salvataggio dell'archivio cifrato su memoria esterna rimovibile.",
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.8f),
                    )
                    Spacer(modifier = Modifier.height(12.dp))

                    // Pulsante 1: Seleziona cartella
                    Button(
                        onClick = { folderPickerLauncher.launch(null) },
                        enabled = !isOperating,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(text = "Seleziona cartella")
                    }
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = folderStatus,
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        fontWeight = FontWeight.Medium,
                    )

                    Spacer(modifier = Modifier.height(12.dp))

                    // Pulsante 2: Crea Archivio
                    Button(
                        onClick = {
                            passphraseInput = ""
                            passphraseConfirmInput = ""
                            dialogError = ""
                            if (hasUnsavedChanges) {
                                pendingActionForDiscardConfirmation = PendingArchiveDialogAction.CREATE_ARCHIVE
                            } else {
                                pendingDialogAction = PendingArchiveDialogAction.CREATE_ARCHIVE
                            }
                        },
                        enabled = isFolderAccessible && (currentSavedUri != null) && !isOperating,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(text = "Crea nuovo archivio")
                    }

                    Spacer(modifier = Modifier.height(8.dp))

                    // Pulsante 3: Apri Archivio
                    Button(
                        onClick = {
                            passphraseInput = ""
                            passphraseConfirmInput = ""
                            dialogError = ""
                            if (hasUnsavedChanges) {
                                pendingActionForDiscardConfirmation = PendingArchiveDialogAction.OPEN_ARCHIVE
                            } else {
                                pendingDialogAction = PendingArchiveDialogAction.OPEN_ARCHIVE
                            }
                        },
                        enabled = isFolderAccessible && (currentSavedUri != null) && !isOperating,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(text = "Apri archivio cifrato")
                    }

                    if (loadedPayload != null) {
                        Spacer(modifier = Modifier.height(8.dp))

                        // Pulsante 4: Salva Archivio
                        Button(
                            onClick = {
                                passphraseInput = ""
                                passphraseConfirmInput = ""
                                dialogError = ""
                                pendingDialogAction = PendingArchiveDialogAction.SAVE_ARCHIVE
                            },
                            enabled = isFolderAccessible && (currentSavedUri != null) && !isOperating,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(text = if (hasUnsavedChanges) "Salva archivio (modifiche pendenti)" else "Salva archivio")
                        }
                    }

                    Spacer(modifier = Modifier.height(12.dp))

                    // Pulsante 5: Test I/O fittizio di supporto
                    Button(
                        onClick = {
                            val savedUri = currentSavedUri ?: StorageHelper.getSavedFolderUri(context)
                            val res = TestFileStorage.runIoTest(context, savedUri)
                            archiveStatusMessage = when (res) {
                                is TestResult.NoFolderSelected -> "Nessuna cartella selezionata."
                                is TestResult.FileAlreadyExists -> "Conflitto: il file '${res.fileName}' è già presente nella cartella. Test annullato per sicurezza."
                                is TestResult.Success -> {
                                    "Test I/O completato con successo!\n" +
                                        "・ Scrittura: OK\n" +
                                        "・ Rilettura e confronto: OK\n" +
                                        "・ Cancellazione file di test: ${if (res.fileDeleted) "Eseguita (cartella pulita)" else "Non eseguita (file conservato)"}"
                                }
                                is TestResult.Failure -> "Errore durante il test: ${res.message}"
                            }
                        },
                        enabled = isFolderAccessible && (currentSavedUri != null) && !isOperating,
                        modifier = Modifier.fillMaxWidth(),
                    ) {
                        Text(text = "Esegui test lettura/scrittura fittizio")
                    }

                    if (archiveStatusMessage.isNotEmpty()) {
                        Spacer(modifier = Modifier.height(8.dp))
                        Text(
                            text = archiveStatusMessage,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            fontWeight = FontWeight.Medium,
                        )
                    }
                }
            }

            // CONTENUTO DELL'ARCHIVIO APERTO
            if (loadedPayload != null) {
                val payload = loadedPayload!!
                val contactRecords = payload.records.filterIsInstance<ArchiveRecord.ContactRecord>()

                val personalKeyIds = payload.records.filter {
                    it is ArchiveRecord.PrivateKeyRecord || it is ArchiveRecord.PublicKeyRecord
                }.map {
                    when (it) {
                        is ArchiveRecord.PrivateKeyRecord -> it.keyId
                        is ArchiveRecord.PublicKeyRecord -> it.keyId
                        else -> ""
                    }
                }.filter { it.isNotEmpty() }.distinct()

                // SCHERMATA DETTAGLIO CONTATTO (Se un contatto è selezionato)
                if (selectedContactDetail != null) {
                    val contact = selectedContactDetail!!
                    val associatedOwnerKeyRecord = payload.records.filterIsInstance<ArchiveRecord.ContactOwnerKeyRecord>()
                        .firstOrNull { it.contactId == contact.contactId }
                    val associatedPubKey = payload.records.filterIsInstance<ArchiveRecord.ContactPublicKeyRecord>()
                        .firstOrNull { it.contactId == contact.contactId }
                    val associatedSymKey = payload.records.filterIsInstance<ArchiveRecord.ContactSymmetricKeyRecord>()
                        .firstOrNull { it.contactId == contact.contactId }

                    Card(
                        modifier = Modifier.fillMaxWidth(),
                        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp),
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.3f),
                        ),
                    ) {
                        Column(
                            modifier = Modifier.padding(16.dp),
                            verticalArrangement = Arrangement.spacedBy(12.dp),
                        ) {
                            // Pulsante Indietro + Titolo Contatto
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween,
                            ) {
                                TextButton(
                                    onClick = { selectedContactDetail = null },
                                    enabled = !isOperating,
                                ) {
                                    Text("← Torna ai Contatti")
                                }

                                Text(
                                    text = "👤 ${contact.alias}",
                                    style = MaterialTheme.typography.titleMedium,
                                    fontWeight = FontWeight.Bold,
                                    color = MaterialTheme.colorScheme.primary,
                                )
                            }

                            Text(
                                text = "Contact ID: ${contact.contactId}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                            )

                            // SEZIONE A: LA MIA CHIAVE PERSONALE PER QUESTO CONTATTO
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surface,
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        text = "A. La Mia Chiave Personale per questo Contatto",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                    Text(
                                        text = "Seleziona la tua coppia di chiavi PGP personale da utilizzare per firmare ed identificarti verso questo contatto.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))

                                    if (associatedOwnerKeyRecord != null) {
                                        val ownerKeyName = payload.records.filterIsInstance<ArchiveRecord.KeyNameRecord>()
                                            .firstOrNull { it.keyId == associatedOwnerKeyRecord.ownerKeyId }?.name
                                        val ownerCategory = payload.records.filterIsInstance<ArchiveRecord.KeyCategoryRecord>()
                                            .firstOrNull { it.keyId == associatedOwnerKeyRecord.ownerKeyId }?.category ?: "Personale"

                                        val ownerLabel = if (ownerKeyName != null) {
                                            "$ownerKeyName (${associatedOwnerKeyRecord.ownerKeyId})"
                                        } else {
                                            associatedOwnerKeyRecord.ownerKeyId
                                        }

                                        Text(
                                            text = "🔒 Chiave Personale: $ownerLabel",
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.secondary,
                                        )
                                        Text(
                                            text = "🏷️ Categoria: $ownerCategory",
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    } else {
                                        Text(
                                            text = "🔒 Nessuna chiave personale associata.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                        )
                                    }

                                    Button(
                                        onClick = {
                                            val availableKeyIds = getCompletePersonalKeypairIds(payload.records)
                                            contactForOwnerKeyAssignment = contact
                                            selectedOwnerKeyIdOption = associatedOwnerKeyRecord?.ownerKeyId ?: availableKeyIds.firstOrNull()
                                        },
                                        enabled = !isOperating,
                                        modifier = Modifier.fillMaxWidth(),
                                    ) {
                                        Text(if (associatedOwnerKeyRecord == null) "Associa chiave personale" else "Cambia chiave personale")
                                    }
                                }
                            }

                            // SEZIONE B: CHIAVE PUBBLICA DEL CONTATTO
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surface,
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        text = "B. Chiave Pubblica del Contatto",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                    Text(
                                        text = "Chiave pubblica OpenPGP appartenente a questo contatto per la cifratura asimmetrica.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))

                                    if (associatedPubKey != null) {
                                        val parsedInfo = PgpKeyParser.parseKeyData(associatedPubKey.keyData)
                                        val fpHex = if (parsedInfo is ParsedPgpKeyResult.PublicKeyResult) parsedInfo.fingerprintHex else "N/A"

                                        Text(
                                            text = "🔑 Key ID: ${associatedPubKey.keyId}",
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.primary,
                                        )
                                        Text(
                                            text = "Fingerprint: $fpHex",
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                    } else {
                                        Text(
                                            text = "Nessuna chiave pubblica del contatto importata.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                        )
                                        Button(
                                            onClick = {
                                                contactForPublicKeyImport = contact
                                                openContactPgpDocumentLauncher.launch(
                                                    arrayOf(
                                                        "application/pgp-keys",
                                                        "application/pgp-signature",
                                                        "application/pgp-encrypted",
                                                        "text/plain",
                                                        "application/octet-stream",
                                                        "*/*",
                                                    ),
                                                )
                                            },
                                            enabled = !isOperating,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) {
                                            Text("Importa chiave pubblica del contatto")
                                        }
                                    }
                                }
                            }

                            // SEZIONE C: CHIAVE SIMMETRICA CONDIVISA
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surface,
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        text = "C. Chiave Simmetrica Condivisa",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                    Text(
                                        text = "Chiave simmetrica AES-256 condivisa con questo contatto per comunicazioni cifrate ad alta velocità.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))

                                    if (associatedSymKey != null) {
                                        Text(
                                            text = "⚡ Key ID: ${associatedSymKey.symmetricKeyId}",
                                            style = MaterialTheme.typography.bodySmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.tertiary,
                                        )
                                        Text(
                                            text = "Versione: v${associatedSymKey.keyVersion}",
                                            style = MaterialTheme.typography.bodySmall,
                                        )
                                        Button(
                                            onClick = { symmetricKeyToDelete = associatedSymKey },
                                            enabled = !isOperating,
                                            modifier = Modifier.fillMaxWidth(),
                                        ) {
                                            Text("Elimina chiave simmetrica", color = MaterialTheme.colorScheme.error)
                                        }
                                    } else {
                                        Text(
                                            text = "Nessuna chiave simmetrica configurata per questo contatto.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                        )
                                    }
                                }
                            }

                            // SEZIONE D: MODALITÀ DI COMUNICAZIONE
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                elevation = CardDefaults.cardElevation(defaultElevation = 1.dp),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surface,
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(6.dp),
                                ) {
                                    Text(
                                        text = "D. Modalità di Comunicazione",
                                        style = MaterialTheme.typography.titleSmall,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                    Text(
                                        text = "Stato della modalità di comunicazione disponibile basato sulle chiavi attualmente memorizzate.",
                                        style = MaterialTheme.typography.bodySmall,
                                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    )
                                    Spacer(modifier = Modifier.height(2.dp))

                                    val modeLabel = when {
                                        associatedPubKey != null && associatedSymKey != null -> "Ibrida (Asimmetrica PGP + Simmetrica AES-256)"
                                        associatedPubKey != null -> "Asimmetrica (OpenPGP)"
                                        associatedSymKey != null -> "Simmetrica (AES-256)"
                                        else -> "Non configurata (Richiede chiave pubblica o simmetrica)"
                                    }

                                    Text(
                                        text = "• Modalità attiva: $modeLabel",
                                        style = MaterialTheme.typography.bodyMedium,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.primary,
                                    )
                                }
                            }
                        }
                    }
                } else {
                    // SCHERMATE PRINCIPALI CON TAB (LE MIE CHIAVI | CONTATTI)
                    Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                        // Header informazioni e salvataggio dell'archivio
                        Card(
                            modifier = Modifier.fillMaxWidth(),
                            colors = CardDefaults.cardColors(
                                containerColor = MaterialTheme.colorScheme.primaryContainer.copy(alpha = 0.3f),
                            ),
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(12.dp),
                                horizontalArrangement = Arrangement.SpaceBetween,
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = "Record totali: ${payload.records.size} | Payload: v${payload.version}",
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.Medium,
                                    )
                                    if (hasUnsavedChanges) {
                                        Text(
                                            text = "⚠️ Modifiche pendenti non salvate su scheda SD",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.error,
                                            fontWeight = FontWeight.Bold,
                                        )
                                    } else {
                                        Text(
                                            text = "✓ Sincronizzato con scheda SD",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.primary,
                                            fontWeight = FontWeight.Medium,
                                        )
                                    }
                                }

                                TextButton(
                                    onClick = {
                                        if (hasUnsavedChanges) {
                                            showCloseConfirmationDialog = true
                                        } else {
                                            loadedPayload = null
                                            selectedContactDetail = null
                                            archiveStatusMessage = "Archivio chiuso."
                                        }
                                    },
                                    enabled = !isOperating,
                                ) {
                                    Text("Chiudi archivio")
                                }
                            }
                        }

                        // BARRA DELLE SCHEDE (TAB ROW)
                        TabRow(
                            selectedTabIndex = activeTab.ordinal,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Tab(
                                selected = activeTab == HomeNavigationTab.MY_KEYS,
                                onClick = { activeTab = HomeNavigationTab.MY_KEYS },
                                text = { Text("🔑 Le Mie Chiavi (${personalKeyIds.size})") },
                            )
                            Tab(
                                selected = activeTab == HomeNavigationTab.CONTACTS,
                                onClick = { activeTab = HomeNavigationTab.CONTACTS },
                                text = { Text("👥 Contatti (${contactRecords.size})") },
                            )
                        }

                        // PAGINA 1: LE MIE CHIAVI
                        if (activeTab == HomeNavigationTab.MY_KEYS) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f),
                                ),
                            ) {
                                Column(
                                    modifier = Modifier.padding(12.dp),
                                    verticalArrangement = Arrangement.spacedBy(12.dp),
                                ) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.spacedBy(8.dp),
                                    ) {
                                        Button(
                                            onClick = {
                                                genKeyNameInput = ""
                                                genUserIdInput = ""
                                                genSelectedCategory = "Personale"
                                                genCustomCategoryInput = ""
                                                genSelectedProfile = PgpProfile.RSA_3072
                                                genPassphraseInput = ""
                                                genPassphraseConfirmInput = ""
                                                generateDialogError = ""
                                                showGeneratePgpDialog = true
                                            },
                                            enabled = !isOperating,
                                            modifier = Modifier.weight(1f),
                                        ) {
                                            Text("Genera coppia PGP", maxLines = 1, softWrap = false)
                                        }

                                        Button(
                                            onClick = {
                                                openPgpDocumentLauncher.launch(
                                                    arrayOf(
                                                        "application/pgp-keys",
                                                        "application/pgp-signature",
                                                        "application/pgp-encrypted",
                                                        "text/plain",
                                                        "application/octet-stream",
                                                        "*/*",
                                                    ),
                                                )
                                            },
                                            enabled = !isOperating,
                                            modifier = Modifier.weight(1f),
                                        ) {
                                            Text("Importa file .asc", maxLines = 1, softWrap = false)
                                        }
                                    }

                                    if (personalKeyIds.isEmpty()) {
                                        Text(
                                            text = "Nessuna chiave PGP personale trovata nell'archivio.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                        )
                                    } else {
                                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                            personalKeyIds.forEach { keyId ->
                                                val privRec = payload.records.filterIsInstance<ArchiveRecord.PrivateKeyRecord>()
                                                    .firstOrNull { it.keyId == keyId }
                                                val pubRec = payload.records.filterIsInstance<ArchiveRecord.PublicKeyRecord>()
                                                    .firstOrNull { it.keyId == keyId }
                                                val nameRec = payload.records.filterIsInstance<ArchiveRecord.KeyNameRecord>()
                                                    .firstOrNull { it.keyId == keyId }
                                                val catRec = payload.records.filterIsInstance<ArchiveRecord.KeyCategoryRecord>()
                                                    .firstOrNull { it.keyId == keyId }

                                                val displayName = nameRec?.name ?: "Coppia PGP $keyId"
                                                val displayCategory = catRec?.category ?: "Personale"
                                                val statusLabel = when {
                                                    privRec != null && pubRec != null -> "🔒 Privata + 🔑 Pubblica"
                                                    privRec != null -> "🔒 Solo Privata"
                                                    else -> "🔑 Solo Pubblica"
                                                }

                                                Surface(
                                                    modifier = Modifier.fillMaxWidth(),
                                                    color = MaterialTheme.colorScheme.surface,
                                                    shape = MaterialTheme.shapes.small,
                                                    tonalElevation = 1.dp,
                                                ) {
                                                    Column(
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .padding(8.dp),
                                                        verticalArrangement = Arrangement.spacedBy(4.dp),
                                                    ) {
                                                        Row(
                                                            modifier = Modifier.fillMaxWidth(),
                                                            horizontalArrangement = Arrangement.SpaceBetween,
                                                            verticalAlignment = Alignment.CenterVertically,
                                                        ) {
                                                            Text(
                                                                text = displayName,
                                                                style = MaterialTheme.typography.labelMedium,
                                                                fontWeight = FontWeight.Bold,
                                                                color = MaterialTheme.colorScheme.primary,
                                                            )
                                                            Surface(
                                                                color = MaterialTheme.colorScheme.secondaryContainer,
                                                                shape = MaterialTheme.shapes.extraSmall,
                                                            ) {
                                                                Text(
                                                                    text = "🏷️ $displayCategory",
                                                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                                                    style = MaterialTheme.typography.labelSmall,
                                                                    color = MaterialTheme.colorScheme.onSecondaryContainer,
                                                                    fontWeight = FontWeight.Bold,
                                                                )
                                                            }
                                                        }

                                                        Text(
                                                            text = "Key ID: $keyId",
                                                            style = MaterialTheme.typography.bodyMedium,
                                                            fontWeight = FontWeight.SemiBold,
                                                        )

                                                        Text(
                                                            text = "Stato componenti: $statusLabel",
                                                            style = MaterialTheme.typography.bodySmall,
                                                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                        )

                                                        if (privRec != null) {
                                                            Text(
                                                                text = "・ Dati Privati: ${privRec.keyData.size} byte",
                                                                style = MaterialTheme.typography.bodySmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            )
                                                        }

                                                        if (pubRec != null) {
                                                            Text(
                                                                text = "・ Dati Pubblici: ${pubRec.keyData.size} byte",
                                                                style = MaterialTheme.typography.bodySmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            )
                                                        }

                                                        Column(
                                                            modifier = Modifier.fillMaxWidth(),
                                                            verticalArrangement = Arrangement.spacedBy(2.dp),
                                                        ) {
                                                            Row(
                                                                modifier = Modifier.fillMaxWidth(),
                                                                horizontalArrangement = Arrangement.spacedBy(2.dp, Alignment.End),
                                                                verticalAlignment = Alignment.CenterVertically,
                                                            ) {
                                                                TextButton(
                                                                    onClick = {
                                                                        keyNameInput = nameRec?.name ?: ""
                                                                        keyNameDialogError = ""
                                                                        keyForNamePicker = keyId
                                                                    },
                                                                    enabled = !isOperating,
                                                                ) {
                                                                    Text("Nome", maxLines = 1, softWrap = false)
                                                                }

                                                                TextButton(
                                                                    onClick = {
                                                                        selectedCategoryOption = if (PREDEFINED_CATEGORIES.contains(displayCategory)) displayCategory else "Altro"
                                                                        customCategoryInput = if (!PREDEFINED_CATEGORIES.contains(displayCategory)) displayCategory else ""
                                                                        categoryDialogError = ""
                                                                        keyForCategoryPicker = keyId
                                                                    },
                                                                    enabled = !isOperating,
                                                                ) {
                                                                    Text("Categoria", maxLines = 1, softWrap = false)
                                                                }
                                                            }

                                                            Row(
                                                                modifier = Modifier.fillMaxWidth(),
                                                                horizontalArrangement = Arrangement.spacedBy(2.dp, Alignment.End),
                                                                verticalAlignment = Alignment.CenterVertically,
                                                            ) {
                                                                if (pubRec != null) {
                                                                    TextButton(
                                                                        onClick = {
                                                                            pendingExportRecord = pubRec
                                                                            val rawName = nameRec?.name ?: "coppia-${keyId}"
                                                                            val sanitized = rawName.lowercase().replace(Regex("[^a-z0-9_-]"), "_")
                                                                            exportPgpDocumentLauncher.launch("$sanitized-public.asc")
                                                                        },
                                                                        enabled = !isOperating,
                                                                    ) {
                                                                        Text("Esporta pubblica (.asc)", maxLines = 1, softWrap = false)
                                                                    }
                                                                }

                                                                if (privRec != null) {
                                                                    TextButton(
                                                                        onClick = {
                                                                            pendingExportRecord = privRec
                                                                            val rawName = nameRec?.name ?: "coppia-${keyId}"
                                                                            val sanitized = rawName.lowercase().replace(Regex("[^a-z0-9_-]"), "_")
                                                                            exportPgpDocumentLauncher.launch("$sanitized-private.asc")
                                                                        },
                                                                        enabled = !isOperating,
                                                                    ) {
                                                                        Text("Esporta privata (.asc)", maxLines = 1, softWrap = false)
                                                                    }
                                                                }
                                                            }

                                                            Row(
                                                                modifier = Modifier.fillMaxWidth(),
                                                                horizontalArrangement = Arrangement.End,
                                                                verticalAlignment = Alignment.CenterVertically,
                                                            ) {
                                                                TextButton(
                                                                    onClick = { personalKeyToDeleteId = keyId },
                                                                    enabled = !isOperating,
                                                                ) {
                                                                    Text(
                                                                        "Elimina",
                                                                        color = MaterialTheme.colorScheme.error,
                                                                        fontWeight = FontWeight.Bold,
                                                                        maxLines = 1,
                                                                        softWrap = false,
                                                                    )
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // PAGINA 2: CONTATTI (ELENCO COMPATTO)
                        if (activeTab == HomeNavigationTab.CONTACTS) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.secondaryContainer.copy(alpha = 0.4f),
                                ),
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Row(
                                        modifier = Modifier.fillMaxWidth(),
                                        horizontalArrangement = Arrangement.SpaceBetween,
                                        verticalAlignment = Alignment.CenterVertically,
                                    ) {
                                        Text(
                                            text = "Elenco Contatti (${contactRecords.size})",
                                            style = MaterialTheme.typography.titleSmall,
                                            fontWeight = FontWeight.Bold,
                                            color = MaterialTheme.colorScheme.secondary,
                                        )
                                        Button(
                                            onClick = {
                                                contactAliasInput = ""
                                                addContactError = ""
                                                showAddContactDialog = true
                                            },
                                            enabled = !isOperating,
                                        ) {
                                            Text("Aggiungi contatto")
                                        }
                                    }

                                    Spacer(modifier = Modifier.height(8.dp))

                                    if (contactRecords.isEmpty()) {
                                        Text(
                                            text = "Nessun contatto presente nell'archivio.",
                                            style = MaterialTheme.typography.bodySmall,
                                            color = MaterialTheme.colorScheme.onSurfaceVariant.copy(alpha = 0.7f),
                                        )
                                    } else {
                                        Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                            contactRecords.forEach { contact ->
                                                val associatedPubKey = payload.records.filterIsInstance<ArchiveRecord.ContactPublicKeyRecord>()
                                                    .firstOrNull { it.contactId == contact.contactId }

                                                val associatedOwnerKeyRecord = payload.records.filterIsInstance<ArchiveRecord.ContactOwnerKeyRecord>()
                                                    .firstOrNull { it.contactId == contact.contactId }

                                                val associatedSymKey = payload.records.filterIsInstance<ArchiveRecord.ContactSymmetricKeyRecord>()
                                                    .firstOrNull { it.contactId == contact.contactId }

                                                Surface(
                                                    modifier = Modifier
                                                        .fillMaxWidth()
                                                        .clickable { selectedContactDetail = contact },
                                                    color = MaterialTheme.colorScheme.surface,
                                                    shape = MaterialTheme.shapes.small,
                                                    tonalElevation = 1.dp,
                                                ) {
                                                    Row(
                                                        modifier = Modifier
                                                            .fillMaxWidth()
                                                            .padding(10.dp),
                                                        horizontalArrangement = Arrangement.SpaceBetween,
                                                        verticalAlignment = Alignment.CenterVertically,
                                                    ) {
                                                        Column(modifier = Modifier.weight(1f)) {
                                                            Text(
                                                                text = "👤 ${contact.alias}",
                                                                style = MaterialTheme.typography.labelLarge,
                                                                fontWeight = FontWeight.Bold,
                                                                color = MaterialTheme.colorScheme.primary,
                                                            )
                                                            Text(
                                                                text = "ID: ${contact.contactId}",
                                                                style = MaterialTheme.typography.bodySmall,
                                                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                                            )
                                                            Row(
                                                                horizontalArrangement = Arrangement.spacedBy(6.dp),
                                                                modifier = Modifier.padding(top = 4.dp),
                                                            ) {
                                                                Surface(
                                                                    color = if (associatedOwnerKeyRecord != null) MaterialTheme.colorScheme.primaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                                                                    shape = MaterialTheme.shapes.extraSmall,
                                                                ) {
                                                                    Text(
                                                                        text = if (associatedOwnerKeyRecord != null) "🔒 Chiave Personale" else "🔒 No Chiave Personale",
                                                                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                                                                        style = MaterialTheme.typography.labelSmall,
                                                                    )
                                                                }

                                                                Surface(
                                                                    color = if (associatedPubKey != null) MaterialTheme.colorScheme.secondaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                                                                    shape = MaterialTheme.shapes.extraSmall,
                                                                ) {
                                                                    Text(
                                                                        text = if (associatedPubKey != null) "🔑 Pubblica OK" else "🔑 No Pubblica",
                                                                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                                                                        style = MaterialTheme.typography.labelSmall,
                                                                    )
                                                                }

                                                                Surface(
                                                                    color = if (associatedSymKey != null) MaterialTheme.colorScheme.tertiaryContainer else MaterialTheme.colorScheme.surfaceVariant,
                                                                    shape = MaterialTheme.shapes.extraSmall,
                                                                ) {
                                                                    Text(
                                                                        text = if (associatedSymKey != null) "⚡ Simmetrica" else "⚡ No Simmetrica",
                                                                        modifier = Modifier.padding(horizontal = 4.dp, vertical = 2.dp),
                                                                        style = MaterialTheme.typography.labelSmall,
                                                                    )
                                                                }
                                                            }
                                                        }

                                                        TextButton(
                                                            onClick = { selectedContactDetail = contact },
                                                            enabled = !isOperating,
                                                        ) {
                                                            Text("Dettaglio →")
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // RECORD METADATI GENERALI
                        val otherRecords = payload.records.filterNot {
                            it is ArchiveRecord.PrivateKeyRecord ||
                                it is ArchiveRecord.PublicKeyRecord ||
                                it is ArchiveRecord.KeyCategoryRecord ||
                                it is ArchiveRecord.KeyNameRecord ||
                                it is ArchiveRecord.ContactRecord ||
                                it is ArchiveRecord.ContactPublicKeyRecord ||
                                it is ArchiveRecord.ContactOwnerKeyRecord
                        }

                        if (otherRecords.isNotEmpty()) {
                            Card(
                                modifier = Modifier.fillMaxWidth(),
                                colors = CardDefaults.cardColors(
                                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.3f),
                                ),
                            ) {
                                Column(modifier = Modifier.padding(12.dp)) {
                                    Text(
                                        text = "Altri Record nell'Archivio (${otherRecords.size})",
                                        style = MaterialTheme.typography.labelLarge,
                                        fontWeight = FontWeight.Bold,
                                        color = MaterialTheme.colorScheme.secondary,
                                    )
                                    Spacer(modifier = Modifier.height(6.dp))
                                    Column(verticalArrangement = Arrangement.spacedBy(6.dp)) {
                                        otherRecords.forEach { record ->
                                            val realIndex = payload.records.indexOf(record)
                                            Surface(
                                                modifier = Modifier.fillMaxWidth(),
                                                color = MaterialTheme.colorScheme.surface,
                                                shape = MaterialTheme.shapes.small,
                                                tonalElevation = 1.dp,
                                            ) {
                                                Column(
                                                    modifier = Modifier
                                                        .fillMaxWidth()
                                                        .padding(8.dp),
                                                    verticalArrangement = Arrangement.spacedBy(4.dp),
                                                ) {
                                                    when (record) {
                                                        is ArchiveRecord.MetadataRecord -> {
                                                            Text(
                                                                text = "ℹ️ Metadato",
                                                                style = MaterialTheme.typography.labelMedium,
                                                                fontWeight = FontWeight.Bold,
                                                                color = MaterialTheme.colorScheme.tertiary,
                                                            )
                                                            Text(
                                                                text = "${record.key}: ${record.value}",
                                                                style = MaterialTheme.typography.bodySmall,
                                                            )
                                                        }
                                                        is ArchiveRecord.ContactSymmetricKeyRecord -> {
                                                            Text(
                                                                text = "🔑 Chiave Simmetrica Contatto",
                                                                style = MaterialTheme.typography.labelMedium,
                                                                fontWeight = FontWeight.Bold,
                                                                color = MaterialTheme.colorScheme.secondary,
                                                            )
                                                            Text(
                                                                text = "KeyID: ${record.symmetricKeyId} | ContactID: ${record.contactId} | v${record.keyVersion}",
                                                                style = MaterialTheme.typography.bodySmall,
                                                            )
                                                        }
                                                        else -> {
                                                            Text(
                                                                text = "Record #${realIndex + 1} (Tipo ${record.typeId})",
                                                                style = MaterialTheme.typography.bodySmall,
                                                            )
                                                        }
                                                    }

                                                    Row(
                                                        modifier = Modifier.fillMaxWidth(),
                                                        horizontalArrangement = Arrangement.End,
                                                    ) {
                                                        if (record is ArchiveRecord.ContactSymmetricKeyRecord) {
                                                            TextButton(
                                                                onClick = { symmetricKeyToDelete = record },
                                                                enabled = !isOperating,
                                                            ) {
                                                                Text("Elimina chiave", color = MaterialTheme.colorScheme.error, maxLines = 1, softWrap = false)
                                                            }
                                                        } else {
                                                            TextButton(
                                                                onClick = { recordToDeleteIndex = realIndex },
                                                                enabled = !isOperating,
                                                            ) {
                                                                Text("Rimuovi", color = MaterialTheme.colorScheme.error, maxLines = 1, softWrap = false)
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // Sezione 4: Crediti e ricariche offline
            SectionCard(
                title = "Crediti e ricariche offline",
                description = "Sezione pianificata per la consultazione dei crediti e la gestione delle ricariche in modalità offline.",
            )
        }
    }
}

@Preview(showBackground = true)
@Composable
fun HomeScreenPreview() {
    SecurePGPTheme {
        HomeScreen()
    }
}
