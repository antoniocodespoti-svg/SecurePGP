package it.securepgp.app.storage

import it.securepgp.app.ui.screens.getCompletePersonalKeypairIds
import java.nio.charset.StandardCharsets
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class ArchivePayloadTest {

    @Test
    fun testPayloadSerializationRoundTrip() {
        val dummyPrivateKey = "DUMMY_OPENPGP_PRIVATE_KEY_BYTES_123456789".toByteArray(StandardCharsets.UTF_8)
        val dummyPublicKey = "DUMMY_OPENPGP_PUBLIC_KEY_BYTES_987654321".toByteArray(StandardCharsets.UTF_8)

        val records = listOf(
            ArchiveRecord.PrivateKeyRecord("key_001", dummyPrivateKey),
            ArchiveRecord.PublicKeyRecord("pub_001", dummyPublicKey),
            ArchiveRecord.MetadataRecord("app_version", "1.0"),
        )

        val payload = ArchivePayload(records = records)
        val serializedBytes = payload.serialize()
        assertNotNull(serializedBytes)

        val deserializedPayload = ArchivePayload.deserialize(serializedBytes)
        assertEquals(ArchivePayload.CURRENT_PAYLOAD_VERSION, deserializedPayload.version)
        assertEquals(3, deserializedPayload.records.size)
        assertEquals(records[0], deserializedPayload.records[0])
        assertEquals(records[1], deserializedPayload.records[1])
        assertEquals(records[2], deserializedPayload.records[2])
    }

    @Test
    fun testContactRecordRoundTrip() {
        val contactRecord = ArchiveRecord.ContactRecord(
            contactId = "cnt_12345_uuid",
            alias = "Alice Lavoro",
        )

        val payload = ArchivePayload(records = listOf(contactRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(contactRecord, deserialized.records[0])
    }

    @Test
    fun testContactPublicKeyRecordRoundTrip() {
        val dummyKeyData = "DUMMY_CONTACT_PUBLIC_KEY_BYTES_555".toByteArray(StandardCharsets.UTF_8)
        val contactPubKeyRecord = ArchiveRecord.ContactPublicKeyRecord(
            contactId = "cnt_12345_uuid",
            keyId = "0x12345678ABCD1234",
            keyData = dummyKeyData,
        )

        val payload = ArchivePayload(records = listOf(contactPubKeyRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(contactPubKeyRecord, deserialized.records[0])
    }

    @Test
    fun testContactSymmetricKeyRecordRoundTrip() {
        val dummy32ByteKey = ByteArray(32) { it.toByte() }
        val symKeyRecord = ArchiveRecord.ContactSymmetricKeyRecord(
            symmetricKeyId = "sym_98765_uuid",
            contactId = "cnt_12345_uuid",
            rawSymmetricKeyData = dummy32ByteKey,
            keyVersion = 1,
        )

        val payload = ArchivePayload(records = listOf(symKeyRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(symKeyRecord, deserialized.records[0])
    }

    @Test
    fun testKeyCategoryRecordRoundTrip() {
        val categoryRecord = ArchiveRecord.KeyCategoryRecord(
            keyId = "key_001",
            category = "Lavoro",
        )

        val payload = ArchivePayload(records = listOf(categoryRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(categoryRecord, deserialized.records[0])
    }

    @Test
    fun testContactOwnerKeyRecordRoundTrip() {
        val ownerKeyRecord = ArchiveRecord.ContactOwnerKeyRecord(
            contactId = "cnt_12345_uuid",
            ownerKeyId = "0xFF402940965C3F7D",
        )

        val payload = ArchivePayload(records = listOf(ownerKeyRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(ownerKeyRecord, deserialized.records[0])
    }

    @Test
    fun testKeyNameRecordRoundTrip() {
        val nameRecord = ArchiveRecord.KeyNameRecord(
            keyId = "0xFF402940965C3F7D",
            name = "Lavoro Principale",
        )

        val payload = ArchivePayload(records = listOf(nameRecord))
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(1, deserialized.records.size)
        assertEquals(nameRecord, deserialized.records[0])
    }

    @Test
    fun testConsumedExchangeRecordRoundTrip() {
        val dummyKeyHash = ByteArray(32) { (it + 1).toByte() }
        val dummyNonceHash = ByteArray(32) { (it + 10).toByte() }

        val record = ArchiveRecord.ConsumedExchangeRecord(dummyKeyHash, dummyNonceHash)
        val payload = ArchivePayload(records = listOf(record))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(1, deserialized.records.size)
        assertEquals(record, deserialized.records[0])
    }

    @Test
    fun testContactKeyVersionRecordRoundTrip() {
        val record = ArchiveRecord.ContactKeyVersionRecord("cnt_100", 3)
        val payload = ArchivePayload(records = listOf(record))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(1, deserialized.records.size)
        assertEquals(record, deserialized.records[0])
    }

    @Test
    fun testUserIdentityRecordRoundTrip() {
        val record = ArchiveRecord.UserIdentityRecord("usr_12345678_uuid")
        val payload = ArchivePayload(records = listOf(record))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(1, deserialized.records.size)
        assertEquals(record, deserialized.records[0])
    }

    @Test
    fun testContactIdentityRecordRoundTrip() {
        val record = ArchiveRecord.ContactIdentityRecord("cnt_100", "usr_87654321_uuid")
        val payload = ArchivePayload(records = listOf(record))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(1, deserialized.records.size)
        assertEquals(record, deserialized.records[0])
    }

    @Test
    fun testContactKeyVerificationRecordRoundTrip() {
        val v4Fp = ByteArray(20) { (it + 5).toByte() }
        val v6Fp = ByteArray(32) { (it + 7).toByte() }

        val recordV4 = ArchiveRecord.ContactKeyVerificationRecord("cnt_100", v4Fp, true)
        val recordV6 = ArchiveRecord.ContactKeyVerificationRecord("cnt_200", v6Fp, false)

        val payload = ArchivePayload(records = listOf(recordV4, recordV6))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(2, deserialized.records.size)
        assertEquals(recordV4, deserialized.records[0])
        assertEquals(recordV6, deserialized.records[1])
    }

    @Test
    fun testConsumedExchangeRecordEqualsAndHashCode() {
        val hashA1 = ByteArray(32) { 1 }
        val hashA2 = ByteArray(32) { 1 }
        val hashB = ByteArray(32) { 2 }

        val rec1 = ArchiveRecord.ConsumedExchangeRecord(hashA1, hashB)
        val rec2 = ArchiveRecord.ConsumedExchangeRecord(hashA2, hashB)

        assertEquals(rec1, rec2)
        assertEquals(rec1.hashCode(), rec2.hashCode())
    }

    @Test
    fun testContactKeyVerificationRecordEqualsAndHashCode() {
        val fp1 = ByteArray(20) { 5 }
        val fp2 = ByteArray(20) { 5 }

        val rec1 = ArchiveRecord.ContactKeyVerificationRecord("cnt_1", fp1, true)
        val rec2 = ArchiveRecord.ContactKeyVerificationRecord("cnt_1", fp2, true)

        assertEquals(rec1, rec2)
        assertEquals(rec1.hashCode(), rec2.hashCode())
    }

    @Test(expected = IllegalArgumentException::class)
    fun testContactKeyVerificationFingerprintValidationInvalidSize() {
        val invalid25ByteFp = ByteArray(25)
        ArchiveRecord.ContactKeyVerificationRecord("cnt_1", invalid25ByteFp, true)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testConsumedExchangeHashValidationInvalidSize() {
        val invalid31ByteHash = ByteArray(31)
        val valid32ByteHash = ByteArray(32)
        ArchiveRecord.ConsumedExchangeRecord(invalid31ByteHash, valid32ByteHash)
    }

    @Test(expected = IllegalArgumentException::class)
    fun testContactKeyVersionNegativeRejection() {
        ArchiveRecord.ContactKeyVersionRecord("cnt_1", -1)
    }

    @Test
    fun testPhase2RecordsAllTogetherRoundTrip() {
        val hash32A = ByteArray(32) { 10 }
        val hash32B = ByteArray(32) { 20 }
        val fp20 = ByteArray(20) { 30 }

        val consumed = ArchiveRecord.ConsumedExchangeRecord(hash32A, hash32B)
        val keyVersion = ArchiveRecord.ContactKeyVersionRecord("cnt_999", 2)
        val userId = ArchiveRecord.UserIdentityRecord("usr_owner_uuid")
        val contactId = ArchiveRecord.ContactIdentityRecord("cnt_999", "usr_remote_uuid")
        val keyVerification = ArchiveRecord.ContactKeyVerificationRecord("cnt_999", fp20, true)

        val payload = ArchivePayload(records = listOf(consumed, keyVersion, userId, contactId, keyVerification))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        assertEquals(5, deserialized.records.size)
        assertEquals(5, deserialized.records.size)
        assertEquals(consumed, deserialized.records[0])
        assertEquals(keyVersion, deserialized.records[1])
        assertEquals(userId, deserialized.records[2])
        assertEquals(contactId, deserialized.records[3])
        assertEquals(keyVerification, deserialized.records[4])
    }

    @Test
    fun testKeyNameUpdateWithoutDuplicates() {
        val keyId = "0xFF402940965C3F7D"
        val initialNameRecord = ArchiveRecord.KeyNameRecord(keyId, "Vecchio Nome")
        val updatedNameRecord = ArchiveRecord.KeyNameRecord(keyId, "Nuovo Nome")

        val initialPayload = ArchivePayload(records = listOf(initialNameRecord))

        val updatedRecords = initialPayload.records.filterNot {
            it is ArchiveRecord.KeyNameRecord && it.keyId == keyId
        } + updatedNameRecord

        val finalPayload = ArchivePayload(records = updatedRecords)
        val deserialized = ArchivePayload.deserialize(finalPayload.serialize())

        assertEquals(1, deserialized.records.size)
        assertEquals(updatedNameRecord, deserialized.records[0])
    }

    @Test
    fun testPersonalKeypairIdentification() {
        val keyId = "0xFF402940965C3F7D"
        val dummyPrivKey = "DUMMY_PRIV".toByteArray(StandardCharsets.UTF_8)
        val dummyPubKey = "DUMMY_PUB".toByteArray(StandardCharsets.UTF_8)

        val privRecord = ArchiveRecord.PrivateKeyRecord(keyId, dummyPrivKey)
        val pubRecord = ArchiveRecord.PublicKeyRecord(keyId, dummyPubKey)
        val nameRecord = ArchiveRecord.KeyNameRecord(keyId, "Identità Personale")
        val categoryRecord = ArchiveRecord.KeyCategoryRecord(keyId, "Lavoro")

        val payload = ArchivePayload(records = listOf(privRecord, pubRecord, nameRecord, categoryRecord))
        val deserialized = ArchivePayload.deserialize(payload.serialize())

        val personalKeyIds = deserialized.records.filter {
            it is ArchiveRecord.PrivateKeyRecord || it is ArchiveRecord.PublicKeyRecord
        }.map {
            when (it) {
                is ArchiveRecord.PrivateKeyRecord -> it.keyId
                is ArchiveRecord.PublicKeyRecord -> it.keyId
                else -> ""
            }
        }.filter { it.isNotEmpty() }.distinct()

        assertEquals(1, personalKeyIds.size)
        assertEquals(keyId, personalKeyIds[0])

        val hasPriv = deserialized.records.any { it is ArchiveRecord.PrivateKeyRecord && it.keyId == keyId }
        val hasPub = deserialized.records.any { it is ArchiveRecord.PublicKeyRecord && it.keyId == keyId }
        val foundName = deserialized.records.filterIsInstance<ArchiveRecord.KeyNameRecord>().firstOrNull { it.keyId == keyId }?.name
        val foundCat = deserialized.records.filterIsInstance<ArchiveRecord.KeyCategoryRecord>().firstOrNull { it.keyId == keyId }?.category

        assertTrue(hasPriv)
        assertTrue(hasPub)
        assertEquals("Identità Personale", foundName)
        assertEquals("Lavoro", foundCat)
    }

    @Test
    fun testCompletePersonalKeypairSelectorFiltering() {
        val dummyBytes = "DUMMY_KEY_BYTES".toByteArray(StandardCharsets.UTF_8)

        // Complete keypair 1
        val priv1 = ArchiveRecord.PrivateKeyRecord("0xKEY001", dummyBytes)
        val pub1 = ArchiveRecord.PublicKeyRecord("0xKEY001", dummyBytes)

        // Complete keypair 2
        val priv2 = ArchiveRecord.PrivateKeyRecord("0xKEY002", dummyBytes)
        val pub2 = ArchiveRecord.PublicKeyRecord("0xKEY002", dummyBytes)

        // Private-only key (must be excluded)
        val privOnly = ArchiveRecord.PrivateKeyRecord("0xPRIV_ONLY", dummyBytes)

        // Public-only key (must be excluded)
        val pubOnly = ArchiveRecord.PublicKeyRecord("0xPUB_ONLY", dummyBytes)

        // Contact Public Key (must be excluded)
        val contactPubKey = ArchiveRecord.ContactPublicKeyRecord("cnt_100", "0xCONTACT_PUB", dummyBytes)

        val records = listOf(priv1, pub1, priv2, pub2, privOnly, pubOnly, contactPubKey)

        val result = getCompletePersonalKeypairIds(records)

        // Verify exactly 2 complete keypairs are returned
        assertEquals(2, result.size)
        assertTrue(result.contains("0xKEY001"))
        assertTrue(result.contains("0xKEY002"))

        // Verify incomplete or contact keys are excluded
        assertTrue(!result.contains("0xPRIV_ONLY"))
        assertTrue(!result.contains("0xPUB_ONLY"))
        assertTrue(!result.contains("0xCONTACT_PUB"))
    }

    @Test(expected = IllegalArgumentException::class)
    fun testContactSymmetricKeyRejectionInvalidSize() {
        val invalid31ByteKey = ByteArray(31)
        ArchiveRecord.ContactSymmetricKeyRecord(
            symmetricKeyId = "sym_bad",
            contactId = "cnt_12345_uuid",
            rawSymmetricKeyData = invalid31ByteKey,
            keyVersion = 1,
        )
    }

    @Test
    fun testV1RecordsCompatibilityWithNewRecords() {
        val dummyPrivateKey = "DUMMY_PRIVATE_KEY".toByteArray(StandardCharsets.UTF_8)
        val dummyPublicKey = "DUMMY_PUBLIC_KEY".toByteArray(StandardCharsets.UTF_8)
        val dummy32ByteKey = ByteArray(32) { (it * 2).toByte() }
        val dummyContactPubKey = "DUMMY_CONTACT_PUB_KEY".toByteArray(StandardCharsets.UTF_8)

        val mixedRecords = listOf(
            ArchiveRecord.PrivateKeyRecord("priv_001", dummyPrivateKey),
            ArchiveRecord.PublicKeyRecord("pub_001", dummyPublicKey),
            ArchiveRecord.MetadataRecord("created_by", "SecurePGP"),
            ArchiveRecord.ContactRecord("cnt_100", "Bob"),
            ArchiveRecord.ContactPublicKeyRecord("cnt_100", "0xABC123", dummyContactPubKey),
            ArchiveRecord.ContactSymmetricKeyRecord("sym_100", "cnt_100", dummy32ByteKey, 2),
            ArchiveRecord.KeyCategoryRecord("priv_001", "Amici"),
            ArchiveRecord.ContactOwnerKeyRecord("cnt_100", "priv_001"),
            ArchiveRecord.KeyNameRecord("priv_001", "Chiave Personale Bob"),
        )

        val payload = ArchivePayload(records = mixedRecords)
        val serializedBytes = payload.serialize()
        val deserialized = ArchivePayload.deserialize(serializedBytes)

        assertEquals(9, deserialized.records.size)
        assertEquals(mixedRecords[0], deserialized.records[0])
        assertEquals(mixedRecords[1], deserialized.records[1])
        assertEquals(mixedRecords[2], deserialized.records[2])
        assertEquals(mixedRecords[3], deserialized.records[3])
        assertEquals(mixedRecords[4], deserialized.records[4])
        assertEquals(mixedRecords[5], deserialized.records[5])
        assertEquals(mixedRecords[6], deserialized.records[6])
        assertEquals(mixedRecords[7], deserialized.records[7])
        assertEquals(mixedRecords[8], deserialized.records[8])
    }

    @Test(expected = UnsupportedArchiveVersionException::class)
    fun testPayloadRejectionUnknownVersion() {
        val payload = ArchivePayload(version = 0x02, records = emptyList())
        val serializedBytes = payload.serialize()

        ArchivePayload.deserialize(serializedBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testPayloadRejectionEmptyBytes() {
        ArchivePayload.deserialize(ByteArray(0))
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testPayloadRejectionUnknownRecordType() {
        val badBytes = byteArrayOf(
            0x01, // Payload version 1
            0x00, 0x00, 0x00, 0x01, // 1 record
            0x99.toByte(), // Unknown record type ID 0x99
        )
        ArchivePayload.deserialize(badBytes)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testPayloadRejectionTruncatedRecord() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val serialized = payload.serialize()
        val truncated = serialized.copyOf(serialized.size - 2)

        ArchivePayload.deserialize(truncated)
    }

    @Test(expected = InvalidArchiveFormatException::class)
    fun testPayloadRejectionTrailingBytes() {
        val payload = ArchivePayload(records = listOf(ArchiveRecord.MetadataRecord("k", "v")))
        val serialized = payload.serialize()
        val withTrailing = serialized + byteArrayOf(0x00)

        ArchivePayload.deserialize(withTrailing)
    }
}
