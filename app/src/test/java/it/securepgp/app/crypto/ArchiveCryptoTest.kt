package it.securepgp.app.crypto

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchiveCryptoTest {

    private val dummyPassphrase = "TestPassphrase123!".toCharArray()
    private val wrongPassphrase = "WrongPassphrase999!".toCharArray()
    private val dummyAad = "SPGP_HEADER_AAD_V1".toByteArray(Charsets.UTF_8)
    private val dummyPayload = "DummyOpenPgpKeyPayloadDataForTesting".toByteArray(Charsets.UTF_8)

    @Test
    fun testGenerateDek_correctSize() {
        val dek = ArchiveCrypto.generateDek()
        assertNotNull(dek)
        assertEquals(ArchiveCrypto.KEY_BYTE_SIZE, dek.size)
    }

    @Test
    fun testDekRoundTrip() {
        val salt = ArchiveCrypto.generateSalt()
        val nonce = ArchiveCrypto.generateNonce()
        val dek = ArchiveCrypto.generateDek()

        val kek = ArchiveCrypto.deriveKek(dummyPassphrase, salt)
        val encryptedDek = ArchiveCrypto.encryptDek(dek, kek, nonce, dummyAad)

        val decryptedDek = ArchiveCrypto.decryptDek(encryptedDek, kek, nonce, dummyAad)

        assertArrayEquals(dek, decryptedDek)

        ArchiveCrypto.zeroize(dek)
        ArchiveCrypto.zeroize(kek)
        ArchiveCrypto.zeroize(decryptedDek)
    }

    @Test
    fun testPayloadRoundTrip() {
        val dek = ArchiveCrypto.generateDek()
        val nonce = ArchiveCrypto.generateNonce()

        val ciphertext = ArchiveCrypto.encryptPayload(dummyPayload, dek, nonce, dummyAad)
        val decryptedPayload = ArchiveCrypto.decryptPayload(ciphertext, dek, nonce, dummyAad)

        assertArrayEquals(dummyPayload, decryptedPayload)

        ArchiveCrypto.zeroize(dek)
    }

    @Test(expected = AuthenticationFailedException::class)
    fun testFailureWithWrongPassphrase() {
        val salt = ArchiveCrypto.generateSalt()
        val nonce = ArchiveCrypto.generateNonce()
        val dek = ArchiveCrypto.generateDek()

        val correctKek = ArchiveCrypto.deriveKek(dummyPassphrase, salt)
        val encryptedDek = ArchiveCrypto.encryptDek(dek, correctKek, nonce, dummyAad)

        val wrongKek = ArchiveCrypto.deriveKek(wrongPassphrase, salt)
        try {
            // Must throw AuthenticationFailedException
            ArchiveCrypto.decryptDek(encryptedDek, wrongKek, nonce, dummyAad)
        } finally {
            ArchiveCrypto.zeroize(correctKek)
            ArchiveCrypto.zeroize(wrongKek)
            ArchiveCrypto.zeroize(dek)
        }
    }

    @Test(expected = AuthenticationFailedException::class)
    fun testFailureWhenCiphertextAltered() {
        val dek = ArchiveCrypto.generateDek()
        val nonce = ArchiveCrypto.generateNonce()

        val ciphertext = ArchiveCrypto.encryptPayload(dummyPayload, dek, nonce, dummyAad)

        // Alter 1 byte of the ciphertext
        ciphertext[0] = (ciphertext[0].toInt() xor 0xFF).toByte()

        try {
            // Must throw AuthenticationFailedException
            ArchiveCrypto.decryptPayload(ciphertext, dek, nonce, dummyAad)
        } finally {
            ArchiveCrypto.zeroize(dek)
        }
    }

    @Test(expected = AuthenticationFailedException::class)
    fun testFailureWhenAadAltered() {
        val dek = ArchiveCrypto.generateDek()
        val nonce = ArchiveCrypto.generateNonce()

        val ciphertext = ArchiveCrypto.encryptPayload(dummyPayload, dek, nonce, dummyAad)

        val alteredAad = dummyAad.clone()
        alteredAad[0] = (alteredAad[0].toInt() xor 0xFF).toByte()

        try {
            // Must throw AuthenticationFailedException
            ArchiveCrypto.decryptPayload(ciphertext, dek, nonce, alteredAad)
        } finally {
            ArchiveCrypto.zeroize(dek)
        }
    }

    @Test(expected = InvalidKdfParamsException::class)
    fun testRejectionLowIterationsBeforeDerivation() {
        val salt = ArchiveCrypto.generateSalt()
        val lowIterations = 99_999 // Below MIN_KDF_ITERATIONS (100_000)
        ArchiveCrypto.deriveKek(dummyPassphrase, salt, lowIterations)
    }

    @Test(expected = InvalidKdfParamsException::class)
    fun testRejectionHighIterationsBeforeDerivation() {
        val salt = ArchiveCrypto.generateSalt()
        val highIterations = 2_000_001 // Above MAX_KDF_ITERATIONS (2_000_000)
        ArchiveCrypto.deriveKek(dummyPassphrase, salt, highIterations)
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionInvalidSaltLength() {
        val invalidSalt = ByteArray(16) // Should be 32
        ArchiveCrypto.deriveKek(dummyPassphrase, invalidSalt)
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionInvalidNonceLength() {
        val dek = ArchiveCrypto.generateDek()
        val invalidNonce = ByteArray(16) // Should be 12
        try {
            ArchiveCrypto.encryptPayload(dummyPayload, dek, invalidNonce)
        } finally {
            ArchiveCrypto.zeroize(dek)
        }
    }

    @Test
    fun testDistinctNoncesGenerated() {
        val nonce1 = ArchiveCrypto.generateNonce()
        val nonce2 = ArchiveCrypto.generateNonce()

        assertFalse("Consecutive nonces must be distinct", nonce1.contentEquals(nonce2))
        assertEquals(ArchiveCrypto.NONCE_BYTE_SIZE, nonce1.size)
        assertEquals(ArchiveCrypto.NONCE_BYTE_SIZE, nonce2.size)
    }

    @Test
    fun testPassphraseChange_reencryptsDekOnly_payloadUnchanged() {
        val initialSalt = ArchiveCrypto.generateSalt()
        val dek = ArchiveCrypto.generateDek()

        // 1. Cifra il payload con la DEK
        val contentNonce = ArchiveCrypto.generateNonce()
        val encryptedPayload = ArchiveCrypto.encryptPayload(dummyPayload, dek, contentNonce, dummyAad)

        // 2. Cifra la DEK con la prima KEK (Passphrase 1)
        val kek1Nonce = ArchiveCrypto.generateNonce()
        val kek1 = ArchiveCrypto.deriveKek(dummyPassphrase, initialSalt)
        val encryptedDek1 = ArchiveCrypto.encryptDek(dek, kek1, kek1Nonce, dummyAad)
        assertTrue(encryptedDek1.isNotEmpty())

        // 3. CAMBIO PASSPHRASE: Si deriva una nuova KEK2 da newPassphrase (con nuovo salt)
        val newPassphrase = "NewSecretPassphrase456!".toCharArray()
        val newSalt = ArchiveCrypto.generateSalt()
        val kek2Nonce = ArchiveCrypto.generateNonce()
        val kek2 = ArchiveCrypto.deriveKek(newPassphrase, newSalt)

        // Ricifra SOLTANTO la DEK con kek2
        val encryptedDek2 = ArchiveCrypto.encryptDek(dek, kek2, kek2Nonce, dummyAad)

        // 4. VERIFICA: Decifra la DEK con kek2 (Nuova Passphrase)
        val decryptedDek2 = ArchiveCrypto.decryptDek(encryptedDek2, kek2, kek2Nonce, dummyAad)
        assertArrayEquals(dek, decryptedDek2)

        // Decifra il payload originale usando decryptedDek2 SENZA aver toccato encryptedPayload
        val decryptedPayload = ArchiveCrypto.decryptPayload(encryptedPayload, decryptedDek2, contentNonce, dummyAad)
        assertArrayEquals(dummyPayload, decryptedPayload)

        // Pulizia memoria
        ArchiveCrypto.zeroize(dek)
        ArchiveCrypto.zeroize(kek1)
        ArchiveCrypto.zeroize(kek2)
        ArchiveCrypto.zeroize(decryptedDek2)
        ArchiveCrypto.zeroize(newPassphrase)
    }
}
