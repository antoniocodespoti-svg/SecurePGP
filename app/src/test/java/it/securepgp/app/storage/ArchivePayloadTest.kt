package it.securepgp.app.storage

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
