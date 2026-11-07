package it.securepgp.app.storage

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.EOFException
import java.io.IOException
import java.nio.charset.StandardCharsets

sealed class ArchiveRecord(val typeId: Byte) {

    data class PrivateKeyRecord(
        val keyId: String,
        val keyData: ByteArray,
    ) : ArchiveRecord(TYPE_PRIVATE_KEY) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PrivateKeyRecord) return false
            if (keyId != other.keyId) return false
            return keyData.contentEquals(other.keyData)
        }

        override fun hashCode(): Int {
            var result = keyId.hashCode()
            result = (31 * result) + keyData.contentHashCode()
            return result
        }
    }

    data class PublicKeyRecord(
        val keyId: String,
        val keyData: ByteArray,
    ) : ArchiveRecord(TYPE_PUBLIC_KEY) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is PublicKeyRecord) return false
            if (keyId != other.keyId) return false
            return keyData.contentEquals(other.keyData)
        }

        override fun hashCode(): Int {
            var result = keyId.hashCode()
            result = (31 * result) + keyData.contentHashCode()
            return result
        }
    }

    data class MetadataRecord(
        val key: String,
        val value: String,
    ) : ArchiveRecord(TYPE_METADATA)

    data class ContactRecord(
        val contactId: String,
        val alias: String,
    ) : ArchiveRecord(TYPE_CONTACT)

    data class ContactPublicKeyRecord(
        val contactId: String,
        val keyId: String,
        val keyData: ByteArray,
    ) : ArchiveRecord(TYPE_CONTACT_PUBLIC_KEY) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ContactPublicKeyRecord) return false
            if (contactId != other.contactId) return false
            if (keyId != other.keyId) return false
            return keyData.contentEquals(other.keyData)
        }

        override fun hashCode(): Int {
            var result = contactId.hashCode()
            result = (31 * result) + keyId.hashCode()
            result = (31 * result) + keyData.contentHashCode()
            return result
        }
    }

    data class ContactSymmetricKeyRecord(
        val symmetricKeyId: String,
        val contactId: String,
        val rawSymmetricKeyData: ByteArray,
        val keyVersion: Int = 1,
    ) : ArchiveRecord(TYPE_CONTACT_SYMMETRIC_KEY) {
        init {
            require(rawSymmetricKeyData.size == 32) {
                "Symmetric key data must be exactly 32 bytes (AES-256), got ${rawSymmetricKeyData.size} bytes."
            }
        }

        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ContactSymmetricKeyRecord) return false
            if (symmetricKeyId != other.symmetricKeyId) return false
            if (contactId != other.contactId) return false
            if (keyVersion != other.keyVersion) return false
            return rawSymmetricKeyData.contentEquals(other.rawSymmetricKeyData)
        }

        override fun hashCode(): Int {
            var result = symmetricKeyId.hashCode()
            result = (31 * result) + contactId.hashCode()
            result = (31 * result) + keyVersion
            result = (31 * result) + rawSymmetricKeyData.contentHashCode()
            return result
        }
    }

    data class KeyCategoryRecord(
        val keyId: String,
        val category: String,
    ) : ArchiveRecord(TYPE_KEY_CATEGORY)

    data class ContactOwnerKeyRecord(
        val contactId: String,
        val ownerKeyId: String,
    ) : ArchiveRecord(TYPE_CONTACT_OWNER_KEY)

    data class KeyNameRecord(
        val keyId: String,
        val name: String,
    ) : ArchiveRecord(TYPE_KEY_NAME)

    companion object {
        const val TYPE_PRIVATE_KEY: Byte = 0x01
        const val TYPE_PUBLIC_KEY: Byte = 0x02
        const val TYPE_METADATA: Byte = 0x03
        const val TYPE_CONTACT: Byte = 0x05
        const val TYPE_CONTACT_PUBLIC_KEY: Byte = 0x06
        const val TYPE_CONTACT_SYMMETRIC_KEY: Byte = 0x07
        const val TYPE_KEY_CATEGORY: Byte = 0x08
        const val TYPE_CONTACT_OWNER_KEY: Byte = 0x09
        const val TYPE_KEY_NAME: Byte = 0x0A
    }
}

/**
 * Logical versioned payload container holding serialized ArchiveRecords.
 */
data class ArchivePayload(
    val version: Byte = CURRENT_PAYLOAD_VERSION,
    val records: List<ArchiveRecord>,
) {
    fun serialize(): ByteArray {
        val out = ByteArrayOutputStream()
        val data = DataOutputStream(out)

        data.writeByte(version.toInt())
        data.writeInt(records.size)

        for (record in records) {
            data.writeByte(record.typeId.toInt())
            when (record) {
                is ArchiveRecord.PrivateKeyRecord -> {
                    val keyIdBytes = record.keyId.toByteArray(StandardCharsets.UTF_8)
                    require(keyIdBytes.size <= 255) { "KeyId string too long." }
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeInt(record.keyData.size)
                    data.write(record.keyData)
                }
                is ArchiveRecord.PublicKeyRecord -> {
                    val keyIdBytes = record.keyId.toByteArray(StandardCharsets.UTF_8)
                    require(keyIdBytes.size <= 255) { "KeyId string too long." }
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeInt(record.keyData.size)
                    data.write(record.keyData)
                }
                is ArchiveRecord.MetadataRecord -> {
                    val keyBytes = record.key.toByteArray(StandardCharsets.UTF_8)
                    val valBytes = record.value.toByteArray(StandardCharsets.UTF_8)
                    require(keyBytes.size <= 255) { "Metadata key string too long." }
                    require(valBytes.size <= 65535) { "Metadata value string too long." }
                    data.writeByte(keyBytes.size)
                    data.write(keyBytes)
                    data.writeShort(valBytes.size)
                    data.write(valBytes)
                }
                is ArchiveRecord.ContactRecord -> {
                    val contactIdBytes = record.contactId.toByteArray(StandardCharsets.UTF_8)
                    val aliasBytes = record.alias.toByteArray(StandardCharsets.UTF_8)
                    require(contactIdBytes.size <= 255) { "ContactId string too long." }
                    require(aliasBytes.size <= 65535) { "Alias string too long." }
                    data.writeByte(contactIdBytes.size)
                    data.write(contactIdBytes)
                    data.writeShort(aliasBytes.size)
                    data.write(aliasBytes)
                }
                is ArchiveRecord.ContactPublicKeyRecord -> {
                    val contactIdBytes = record.contactId.toByteArray(StandardCharsets.UTF_8)
                    val keyIdBytes = record.keyId.toByteArray(StandardCharsets.UTF_8)
                    require(contactIdBytes.size <= 255) { "ContactId string too long." }
                    require(keyIdBytes.size <= 255) { "KeyId string too long." }
                    data.writeByte(contactIdBytes.size)
                    data.write(contactIdBytes)
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeInt(record.keyData.size)
                    data.write(record.keyData)
                }
                is ArchiveRecord.ContactSymmetricKeyRecord -> {
                    val keyIdBytes = record.symmetricKeyId.toByteArray(StandardCharsets.UTF_8)
                    val contactIdBytes = record.contactId.toByteArray(StandardCharsets.UTF_8)
                    require(keyIdBytes.size <= 255) { "SymmetricKeyId string too long." }
                    require(contactIdBytes.size <= 255) { "ContactId string too long." }
                    require(record.rawSymmetricKeyData.size == 32) { "RawSymmetricKeyData must be 32 bytes." }
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeByte(contactIdBytes.size)
                    data.write(contactIdBytes)
                    data.writeInt(record.keyVersion)
                    data.write(record.rawSymmetricKeyData)
                }
                is ArchiveRecord.KeyCategoryRecord -> {
                    val keyIdBytes = record.keyId.toByteArray(StandardCharsets.UTF_8)
                    val categoryBytes = record.category.toByteArray(StandardCharsets.UTF_8)
                    require(keyIdBytes.size <= 255) { "KeyId string too long." }
                    require(categoryBytes.size <= 255) { "Category string too long." }
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeByte(categoryBytes.size)
                    data.write(categoryBytes)
                }
                is ArchiveRecord.ContactOwnerKeyRecord -> {
                    val contactIdBytes = record.contactId.toByteArray(StandardCharsets.UTF_8)
                    val ownerKeyIdBytes = record.ownerKeyId.toByteArray(StandardCharsets.UTF_8)
                    require(contactIdBytes.size <= 255) { "ContactId string too long." }
                    require(ownerKeyIdBytes.size <= 255) { "OwnerKeyId string too long." }
                    data.writeByte(contactIdBytes.size)
                    data.write(contactIdBytes)
                    data.writeByte(ownerKeyIdBytes.size)
                    data.write(ownerKeyIdBytes)
                }
                is ArchiveRecord.KeyNameRecord -> {
                    val keyIdBytes = record.keyId.toByteArray(StandardCharsets.UTF_8)
                    val nameBytes = record.name.toByteArray(StandardCharsets.UTF_8)
                    require(keyIdBytes.size <= 255) { "KeyId string too long." }
                    require(nameBytes.size <= 255) { "Name string too long." }
                    data.writeByte(keyIdBytes.size)
                    data.write(keyIdBytes)
                    data.writeByte(nameBytes.size)
                    data.write(nameBytes)
                }
            }
        }
        data.flush()
        return out.toByteArray()
    }

    companion object {
        const val CURRENT_PAYLOAD_VERSION: Byte = 0x01
        const val MAX_RECORDS = 10_000
        const val MAX_RECORD_SIZE = 5 * 1024 * 1024 // 5 MB per record

        fun deserialize(bytes: ByteArray): ArchivePayload {
            if (bytes.isEmpty()) {
                throw InvalidArchiveFormatException("Payload is empty.")
            }

            return try {
                val data = DataInputStream(ByteArrayInputStream(bytes))

                val version = data.readByte()
                if (version != CURRENT_PAYLOAD_VERSION) {
                    throw UnsupportedArchiveVersionException("Unsupported payload version $version (expected $CURRENT_PAYLOAD_VERSION).")
                }

                val recordCount = data.readInt()
                if ((recordCount < 0) || (recordCount > MAX_RECORDS)) {
                    throw InvalidArchiveFormatException("Invalid payload record count ($recordCount).")
                }

                val records = ArrayList<ArchiveRecord>(recordCount)

                for (i in 0 until recordCount) {
                    if (data.available() <= 0) {
                        throw InvalidArchiveFormatException("Truncated payload at record $i.")
                    }

                    when (val typeId = data.readByte()) {
                        ArchiveRecord.TYPE_PRIVATE_KEY -> {
                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val dataLen = data.readInt()
                            if ((dataLen < 0) || (dataLen > MAX_RECORD_SIZE)) {
                                throw InvalidArchiveFormatException("Invalid private key data length ($dataLen).")
                            }
                            val keyData = ByteArray(dataLen)
                            data.readFully(keyData)

                            records.add(ArchiveRecord.PrivateKeyRecord(keyId, keyData))
                        }
                        ArchiveRecord.TYPE_PUBLIC_KEY -> {
                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val dataLen = data.readInt()
                            if ((dataLen < 0) || (dataLen > MAX_RECORD_SIZE)) {
                                throw InvalidArchiveFormatException("Invalid public key data length ($dataLen).")
                            }
                            val keyData = ByteArray(dataLen)
                            data.readFully(keyData)

                            records.add(ArchiveRecord.PublicKeyRecord(keyId, keyData))
                        }
                        ArchiveRecord.TYPE_METADATA -> {
                            val keyLen = data.readUnsignedByte()
                            val keyBytes = ByteArray(keyLen)
                            data.readFully(keyBytes)
                            val key = String(keyBytes, StandardCharsets.UTF_8)

                            val valLen = data.readUnsignedShort()
                            val valBytes = ByteArray(valLen)
                            data.readFully(valBytes)
                            val value = String(valBytes, StandardCharsets.UTF_8)

                            records.add(ArchiveRecord.MetadataRecord(key, value))
                        }
                        ArchiveRecord.TYPE_CONTACT -> {
                            val contactIdLen = data.readUnsignedByte()
                            val contactIdBytes = ByteArray(contactIdLen)
                            data.readFully(contactIdBytes)
                            val contactId = String(contactIdBytes, StandardCharsets.UTF_8)

                            val aliasLen = data.readUnsignedShort()
                            val aliasBytes = ByteArray(aliasLen)
                            data.readFully(aliasBytes)
                            val alias = String(aliasBytes, StandardCharsets.UTF_8)

                            records.add(ArchiveRecord.ContactRecord(contactId, alias))
                        }
                        ArchiveRecord.TYPE_CONTACT_PUBLIC_KEY -> {
                            val contactIdLen = data.readUnsignedByte()
                            val contactIdBytes = ByteArray(contactIdLen)
                            data.readFully(contactIdBytes)
                            val contactId = String(contactIdBytes, StandardCharsets.UTF_8)

                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val dataLen = data.readInt()
                            if ((dataLen < 0) || (dataLen > MAX_RECORD_SIZE)) {
                                throw InvalidArchiveFormatException("Invalid contact public key data length ($dataLen).")
                            }
                            val keyData = ByteArray(dataLen)
                            data.readFully(keyData)

                            records.add(ArchiveRecord.ContactPublicKeyRecord(contactId, keyId, keyData))
                        }
                        ArchiveRecord.TYPE_CONTACT_SYMMETRIC_KEY -> {
                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val contactIdLen = data.readUnsignedByte()
                            val contactIdBytes = ByteArray(contactIdLen)
                            data.readFully(contactIdBytes)
                            val contactId = String(contactIdBytes, StandardCharsets.UTF_8)

                            val version = data.readInt()

                            val keyData = ByteArray(32)
                            data.readFully(keyData)

                            records.add(ArchiveRecord.ContactSymmetricKeyRecord(keyId, contactId, keyData, version))
                        }
                        ArchiveRecord.TYPE_KEY_CATEGORY -> {
                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val categoryLen = data.readUnsignedByte()
                            val categoryBytes = ByteArray(categoryLen)
                            data.readFully(categoryBytes)
                            val category = String(categoryBytes, StandardCharsets.UTF_8)

                            records.add(ArchiveRecord.KeyCategoryRecord(keyId, category))
                        }
                        ArchiveRecord.TYPE_CONTACT_OWNER_KEY -> {
                            val contactIdLen = data.readUnsignedByte()
                            val contactIdBytes = ByteArray(contactIdLen)
                            data.readFully(contactIdBytes)
                            val contactId = String(contactIdBytes, StandardCharsets.UTF_8)

                            val ownerKeyIdLen = data.readUnsignedByte()
                            val ownerKeyIdBytes = ByteArray(ownerKeyIdLen)
                            data.readFully(ownerKeyIdBytes)
                            val ownerKeyId = String(ownerKeyIdBytes, StandardCharsets.UTF_8)

                            records.add(ArchiveRecord.ContactOwnerKeyRecord(contactId, ownerKeyId))
                        }
                        ArchiveRecord.TYPE_KEY_NAME -> {
                            val keyIdLen = data.readUnsignedByte()
                            val keyIdBytes = ByteArray(keyIdLen)
                            data.readFully(keyIdBytes)
                            val keyId = String(keyIdBytes, StandardCharsets.UTF_8)

                            val nameLen = data.readUnsignedByte()
                            val nameBytes = ByteArray(nameLen)
                            data.readFully(nameBytes)
                            val name = String(nameBytes, StandardCharsets.UTF_8)

                            records.add(ArchiveRecord.KeyNameRecord(keyId, name))
                        }
                        else -> {
                            throw InvalidArchiveFormatException("Unknown payload record type ID $typeId.")
                        }
                    }
                }

                if (data.available() > 0) {
                    throw InvalidArchiveFormatException("Unexpected trailing bytes in payload.")
                }

                ArchivePayload(version, records)
            } catch (e: EOFException) {
                throw InvalidArchiveFormatException("Truncated payload record.", e)
            } catch (e: IOException) {
                throw InvalidArchiveFormatException("IO error during payload deserialization: ${e.localizedMessage}", e)
            }
        }
    }
}
