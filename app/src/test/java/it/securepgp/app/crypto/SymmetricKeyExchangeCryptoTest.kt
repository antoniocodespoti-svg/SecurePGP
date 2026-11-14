package it.securepgp.app.crypto

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class SymmetricKeyExchangeCryptoTest {

    private val userA = "usr_alice_1234"
    private val fpA = ByteArray(20) { (it + 1).toByte() }

    private val userB = "usr_bob_5678"
    private val fpB = ByteArray(32) { (it + 10).toByte() }

    private val symKeyId = "sym_key_999_uuid"
    private val rawAesKey = ByteArray(32) { (it * 3).toByte() }
    private val exchangeNonce = ByteArray(16) { (it + 5).toByte() }

    @Test
    fun testExchangeNonceGenerationSize() {
        val nonce = ArchiveCrypto.generateExchangeNonce()
        assertNotNull(nonce)
        assertEquals(16, nonce.size)
    }

    @Test
    fun testExchangeNonceGenerationRandomness() {
        val nonce1 = ArchiveCrypto.generateExchangeNonce()
        val nonce2 = ArchiveCrypto.generateExchangeNonce()
        assertFalse(nonce1.contentEquals(nonce2))
    }

    @Test
    fun testAntiReplayHashOutputSizes() {
        val keyIdHash = SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, fpA, userB, fpB, symKeyId,
        )
        val nonceHash = SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userA, fpA, userB, fpB, exchangeNonce,
        )

        assertEquals(32, keyIdHash.size)
        assertEquals(32, nonceHash.size)
    }

    @Test
    fun testCanonicalOrdering_SwappedInputsProduceIdenticalHashes() {
        val hashForwardKey = SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, fpA, userB, fpB, symKeyId,
        )
        val hashReverseKey = SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userB, fpB, userA, fpA, symKeyId,
        )
        assertTrue(hashForwardKey.contentEquals(hashReverseKey))

        val hashForwardNonce = SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userA, fpA, userB, fpB, exchangeNonce,
        )
        val hashReverseNonce = SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userB, fpB, userA, fpA, exchangeNonce,
        )
        assertTrue(hashForwardNonce.contentEquals(hashReverseNonce))
    }

    @Test
    fun testDifferentKeyIdProducesDifferentHash() {
        val hash1 = SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, fpA, userB, fpB, "sym_key_1",
        )
        val hash2 = SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, fpA, userB, fpB, "sym_key_2",
        )
        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun testDifferentExchangeNonceProducesDifferentHash() {
        val nonce1 = ByteArray(16) { 1 }
        val nonce2 = ByteArray(16) { 2 }

        val hash1 = SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userA, fpA, userB, fpB, nonce1,
        )
        val hash2 = SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userA, fpA, userB, fpB, nonce2,
        )
        assertFalse(hash1.contentEquals(hash2))
    }

    @Test
    fun testCanonicalOrdering_SwappedInputsProduceIdenticalSasCode() {
        val sasForward = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userA, fpA, userB, fpB, symKeyId, exchangeNonce,
        )
        val sasReverse = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userB, fpB, userA, fpA, symKeyId, exchangeNonce,
        )

        assertEquals(sasForward, sasReverse)
    }

    @Test
    fun testSasCodeFormat() {
        val sasCode = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userA, fpA, userB, fpB, symKeyId, exchangeNonce,
        )

        assertEquals(9, sasCode.length)
        assertTrue(sasCode.matches(Regex("""^\d{4}-\d{4}$""")))
    }

    @Test
    fun testSasCodeSensitivityToInputs() {
        val baseSas = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userA, fpA, userB, fpB, symKeyId, exchangeNonce,
        )

        // Modified Key
        val altKey = rawAesKey.copyOf()
        altKey[0] = (altKey[0] + 1).toByte()
        val altKeySas = SymmetricKeyExchangeCrypto.calculateSasCode(
            altKey, userA, fpA, userB, fpB, symKeyId, exchangeNonce,
        )
        assertFalse(baseSas == altKeySas)

        // Modified Nonce
        val altNonce = exchangeNonce.copyOf()
        altNonce[0] = (altNonce[0] + 1).toByte()
        val altNonceSas = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userA, fpA, userB, fpB, symKeyId, altNonce,
        )
        assertFalse(baseSas == altNonceSas)

        // Modified KeyId
        val altKeyIdSas = SymmetricKeyExchangeCrypto.calculateSasCode(
            rawAesKey, userA, fpA, userB, fpB, "sym_alt_key", exchangeNonce,
        )
        assertFalse(baseSas == altKeyIdSas)
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionInvalidKeySize() {
        val badKey = ByteArray(31)
        SymmetricKeyExchangeCrypto.calculateSasCode(
            badKey, userA, fpA, userB, fpB, symKeyId, exchangeNonce,
        )
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionInvalidNonceSize() {
        val badNonce = ByteArray(12)
        SymmetricKeyExchangeCrypto.calculateExchangeNonceHash(
            userA, fpA, userB, fpB, badNonce,
        )
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionInvalidFingerprintSize() {
        val badFp = ByteArray(25)
        SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, badFp, userB, fpB, symKeyId,
        )
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionEmptyUserIdentity() {
        SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            "", fpA, userB, fpB, symKeyId,
        )
    }

    @Test(expected = InvalidInputException::class)
    fun testRejectionEmptySymmetricKeyId() {
        SymmetricKeyExchangeCrypto.calculateSymmetricKeyIdHash(
            userA, fpA, userB, fpB, "",
        )
    }

    @Test
    fun testHotpDynamicTruncationReferenceVector() {
        // Construct a deterministic 32-byte HMAC mock result
        // Last byte = 0x05 -> offset = 5
        // Bytes at offset 5..8 = 0x12, 0x34, 0x56, 0x78
        // binaryCode = (0x12345678 & 0x7FFFFFFF) = 305419896
        // mod 100_000_000 = 5419896 -> part1 = 541, part2 = 9896 -> "0541-9896"
        val mockHmac = ByteArray(32) { 0 }
        mockHmac[31] = 0x05.toByte() // Offset 5
        mockHmac[5] = 0x12.toByte()
        mockHmac[6] = 0x34.toByte()
        mockHmac[7] = 0x56.toByte()
        mockHmac[8] = 0x78.toByte()

        val sasCode = SymmetricKeyExchangeCrypto.truncateHmacToSasCode(mockHmac)
        assertEquals("0541-9896", sasCode)
    }
}
