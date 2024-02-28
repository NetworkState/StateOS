
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

#include "X509_defs.h"

using enum ASN_TAG;

struct ASN_DATA
{
    ASN_TAG tag = ASN_INVALID;
    BUFFER data;
};

struct X509_OPS;
extern X509_OPS X509;

struct X509_SUBJECT
{
    BUFFER name;
    BUFFER keyId;
    STRINGBUFFER altNames;
    BUFFER publicKey;
};

struct X509_AUTHORITY
{
    BUFFER name;
    BUFFER keyId;
};

struct X509_STATUS
{
    UINT32 keyUsage = 0;
    bool isCA = false;
    UINT64 expiresAt = 0;
    BUFFER serialNumber;
};

constexpr UINT32 KEYUSAGE_DIGITAL_SIGNATURE = BIT32(31);
constexpr UINT32 KEYUSAGE_NON_REPUDIATE = BIT32(30);
constexpr UINT32 KEYUSAGE_KEY_ENCIPHERMENT = BIT32(29);
constexpr UINT32 KEYUSAGE_DATA_ENCIPHERMENT = BIT32(28);
constexpr UINT32 KEYUSAGE_KEY_AGREEMENT = BIT32(27);
constexpr UINT32 KEYUSAGE_KEY_CERTSIGN = BIT32(26);
constexpr UINT32 KEYUSAGE_CRL_SIGN = BIT32(25);
constexpr UINT32 KEYUSAGE_ENCIPHER_ONLY = BIT32(24);
constexpr UINT32 KEYUSAGE_DECIPHER_ONLY = BIT32(23);

constexpr UINT32 CERT_KEYUSAGE = KEYUSAGE_DIGITAL_SIGNATURE | KEYUSAGE_NON_REPUDIATE | KEYUSAGE_KEY_ENCIPHERMENT | KEYUSAGE_DATA_ENCIPHERMENT;
constexpr UINT32 CA_KEYUSAGE = KEYUSAGE_KEY_CERTSIGN | KEYUSAGE_CRL_SIGN;

struct X509_OPS
{
    template <typename FUNC>
    static void WriteASNData(BYTESTREAM& outStream, ASN_TAG tag, FUNC&& func, auto&& ... args)
    {
        outStream.writeEnumBE(tag);
        auto lengthOffset = outStream.saveOffset(1);
        if (tag == ASN_BITSTRING)
        {
            auto partialBitsOffset = outStream.mark();
            outStream.writeByte(0);
            func(outStream, args ...);
            outStream.writeByteAt(partialBitsOffset, UINT8(_tzcnt_u32(outStream.last())));
        }
        else
        {
            func(outStream, args ...);
        }
        lengthOffset.writeASNlength();
    }

    static void WriteASNData(BYTESTREAM& outStream, ASN_TAG tag, BUFFER data)
    {
        ASSERT(tag != ASN_INTEGER);
        WriteASNData(outStream, tag, [](BYTESTREAM& outStream, BUFFER data)
            {
                outStream.writeBytes(data);
            }, data);
    }

    static void WriteASNoid(BYTESTREAM& outStream, BUFFER oid)
    {
        ASSERT(oid.length() < 0x80);
        outStream.writeEnumBE(ASN_OID);
        outStream.writeByte(oid.length());
        outStream.writeBytes(oid);
    }

    static void WriteASNbitString(BYTESTREAM& outStream, UINT32 value)
    {
        ASSERT(value != 0);
        WriteASNData(outStream, ASN_BITSTRING, [](BYTESTREAM& outStream, UINT32 value)
            {
                auto zeroBytes = _tzcnt_u32(value) / 8;
                outStream.beWriteU32(value);
                outStream.shrink(zeroBytes);
            }, value);
    }

    static void WriteASNbitString(BYTESTREAM& outStream, UINT8 value)
    {
        WriteASNbitString(outStream, UINT32(value) << 24);
    }

    static void WriteASNbitString(BYTESTREAM& outStream, UINT16 value)
    {
        WriteASNbitString(outStream, UINT32(value) << 16);
    }

    static void WriteASNtime(BYTESTREAM& outStream, UINT64 time)
    {
        outStream.writeEnumBE(ASN_UTCTIME);
        auto lengthOffset = outStream.saveOffset(1);
        String.foraatASNtime(outStream, time);
        lengthOffset.writeASNlength();
    }

    static void WriteASNInteger(BYTESTREAM& outStream, BUFFER numberBytes)
    {
        outStream.writeEnumBE(ASN_INTEGER);
        auto lengthOffset = outStream.saveOffset(1);

        if (numberBytes[0] & 0x80) outStream.writeByte(0);

        outStream.writeBytes(numberBytes);
        lengthOffset.writeASNlength();
    }

    static void WriteASNInteger(BYTESTREAM& outStream, UINT64 value)
    {
        auto byteCount = BYTECOUNT(value);
        value = _byteswap_uint64(value);
        auto address = ((PUINT8)&value) + (8 - byteCount);
        WriteASNInteger(outStream, BUFFER(address, byteCount));
    }

    static void WriteASNboolean(BYTESTREAM& outStream, bool value)
    {
        outStream.writeEnumBE(ASN_BOOLEAN);
        outStream.writeByte(1);
        outStream.writeByte(value ? 0xFF : 0);
    }

    static ASN_DATA ReadASNData(BUFFER& docBytes)
    {
        ASN_DATA property{ ASN_INVALID, NULL_STRING };
        do
        {
            if (docBytes.length() > 0)
            {
                auto type = docBytes.readByte();
                UINT32 length = 0;

                if (type == 0 && docBytes.readByte() == 0)
                    break;

                auto lengthByte = docBytes.readByte();
                if (lengthByte & 0x80)
                {
                    auto byteCount = (UINT8)(lengthByte & 0x7F);
                    if (byteCount > 0)
                    {
                        for (UINT8 i = byteCount; i > 0; i--)
                        {
                            UINT32 in = docBytes.readByte();
                            length |= (in << (i - 1) * 8);
                        }
                    }
                    else length = 0;
                }
                else
                {
                    length = lengthByte & 0x7F;
                }

                property.tag = (ASN_TAG)type;
                property.data = docBytes.readBytes(length);

                if (property.tag == ASN_BITSTRING)
                {
                    if (auto unusedBits = property.data.read())
                    {
                        UINT8 mask = (UINT8)MASK(unusedBits);
                        auto data = property.data.toRWBuffer();
                        data.last() &= ~mask;
                    }
                }
                else if (property.tag == ASN_INTEGER)
                {
                    auto& data = property.data;
                    if (data.length() >= 2 && data.at(0) == 0 && data.at(1) & 0x80)
                        data.shift();
                }
            }
        } while (false);
        return property;
    }

    static ASN_DATA ReadASNData(BUFFER& docBytes, BUFFER& asnBytes)
    {
        auto startOffset = docBytes.savePosition();
        auto asnData = ReadASNData(docBytes);
        asnBytes = docBytes.diffPosition(startOffset);
        return asnData;
    }

    BUFFER ParsePrivateKey(BUFFER keyBytes, BUFFER& publicKey)
    {
        // RFC 5915
        BUFFER privateKey;
        auto isValid = false;
        auto keySequence = ReadASNData(keyBytes);
        if (keySequence.tag == ASN_SEQUENCE)
        {
            auto version = ReadASNData(keySequence.data);
            ASSERT(version.tag == ASN_INTEGER);
            ASSERT(version.data.at(0) == 1);

            auto privateKeyBytes = ReadASNData(keySequence.data);
            ASSERT(privateKeyBytes.tag == ASN_OCTETSTRING);

            privateKey = privateKeyBytes.data;

            auto ecParamsBytes = ReadASNData(keySequence.data);
            if (ecParamsBytes.tag == ASN_CTX_CTAG_0)
            {
                auto curveNameBytes = ReadASNData(ecParamsBytes.data);
                if (curveNameBytes.tag == ASN_OID && curveNameBytes.data == OID_secp256r1)
                {
                    isValid = true;
                }
            }
            else DBGBREAK();

            auto publicKeyBytes = ReadASNData(keySequence.data);
            if (publicKeyBytes.tag == ASN_CTX_CTAG_1)
            {
                publicKeyBytes = ReadASNData(publicKeyBytes.data);
                ASSERT(publicKeyBytes.tag == ASN_BITSTRING);
            }
            else DBGBREAK();

            publicKey = publicKeyBytes.data;
            auto mode = publicKey.readByte();
            ASSERT(mode == 0x04);
        }
        else DBGBREAK();
        ASSERT(isValid);
        return privateKey;
    }

    void FormatECCpublicKey(BYTESTREAM& outStream, BUFFER publicKey)
    {
        WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream)
            {
                WriteASNoid(outStream, OID_EC_public_key);
                WriteASNoid(outStream, OID_secp256r1);
            });

        WriteASNData(outStream, ASN_BITSTRING, [](BYTESTREAM& outStream, BUFFER publicKey)
            {
                outStream.writeByte(0x04); // no compression
                outStream.writeBytes(publicKey);
            }, publicKey);
    }

    BUFFER FormatECDSAP256Signature(BYTESTREAM& outStream, BUFFER signature)
    {
        auto savedPosition = outStream.getPosition();
        WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER signature)
            {
                WriteASNInteger(outStream, signature.readBytes(32));
                WriteASNInteger(outStream, signature.readBytes(32));
                ASSERT(!signature);
            }, signature);
        return savedPosition.toBuffer();
    }

    void FormatECDSAsignature(BYTESTREAM& outStream, BUFFER signature)
    {
        WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream)
            {
                WriteASNoid(outStream, OID_ecdsa_with_SHA256);
            });

        WriteASNData(outStream, ASN_BITSTRING, [](BYTESTREAM& outStream, BUFFER signature)
            {
                X509.FormatECDSAP256Signature(outStream, signature);
            }, signature);
    }

    BUFFER ParsePublicKey(ASN_DATA keySequence)
    {
        BUFFER publicKey;
        auto algorithm = ReadASNData(keySequence.data);

        if (algorithm.tag == ASN_SEQUENCE)
        {
            auto algorithmClass = ReadASNData(algorithm.data);
            auto algorithmType = ReadASNData(algorithm.data);

            if (algorithmClass.tag == ASN_OID)
            {
                if (algorithmClass.data == OID_EC_public_key)
                {
                    if (algorithmType.tag == ASN_OID && algorithmType.data == OID_secp256r1)
                    {
                        auto keyData = ReadASNData(keySequence.data);
                        if (keyData.tag == ASN_BITSTRING)
                        {
                            auto asnData = keyData.data;
                            auto modeByte = asnData.readByte();
                            ASSERT(modeByte == 0x04); // uncompressed

                            publicKey = asnData;
                        }
                        else DBGBREAK();
                    }
                    else DBGBREAK();

                }
                else if (algorithmClass.data == OID_RSAEncryption)
                {
                    auto keyData = ReadASNData(keySequence.data);
                    if (keyData.tag == ASN_BITSTRING)
                    {
                        auto keySequence = ReadASNData(keyData.data);
                        ASSERT(keySequence.tag == ASN_SEQUENCE);

                        auto modulus = ReadASNData(keySequence.data);
                        ASSERT(modulus.tag == ASN_INTEGER);

                        auto exponent = ReadASNData(keySequence.data);
                        ASSERT(exponent.tag == ASN_INTEGER);

                        publicKey = modulus.data;
                    }
                    else DBGBREAK();
                }
                else DBGBREAK();
            }
            else DBGBREAK();
        }
        else DBGBREAK();
        return publicKey;
    }

    BUFFER ParseECDSASignature(BUFFER input, BYTESTREAM&& outStream, UINT32 blockSize = 32)
    {
        auto startPosition = outStream.mark();
        ASSERT(outStream.spaceLeft() >= blockSize * 2);

        auto sequence = ReadASNData(input);
        ASSERT(sequence.tag == ASN_SEQUENCE);

        {
            auto fieldR = ReadASNData(sequence.data);
            ASSERT(fieldR.tag == ASN_INTEGER);
            ASSERT(fieldR.data.length() == blockSize);
            outStream.writeBytes(fieldR.data);
        }
        {
            auto fieldS = ReadASNData(sequence.data);
            ASSERT(fieldS.tag == ASN_INTEGER);
            ASSERT(fieldS.data.length() == blockSize);
            outStream.writeBytes(fieldS.data);
        }

        return outStream.toBuffer(startPosition);
    }

    static USTRING ParseName(BUFFER rdnData)
    {
        USTRING name;
        while (rdnData)
        {
            auto set = ReadASNData(rdnData);
            if (set.tag == ASN_SET)
            {
                auto sequence = ReadASNData(set.data);
                auto oid = ReadASNData(sequence.data);
                if (oid.tag == ASN_OID)
                {
                    auto value = ReadASNData(sequence.data);
                    if (oid.data == OID_id_at_commonName)
                    {
                        ASSERT(value.tag == ASN_PRINTSTRING || value.tag == ASN_UTF8STRING);
                        name = value.data;
                        //break;
                    }
                }
                else DBGBREAK();
            }
            else DBGBREAK();
        }
        return name;
    }

    bool ParseTBS(BUFFER tbsData, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
    {
        auto result = false;
        auto topSequence = ReadASNData(tbsData);
        ASSERT(topSequence.tag == ASN_SEQUENCE);
        tbsData = topSequence.data;

        auto version = ReadASNData(tbsData);
        ASSERT(version.tag == ASN_CTX_CTAG_0);

        auto versionNumber = ReadASNData(version.data);
        ASSERT(versionNumber.tag == ASN_INTEGER);

        ASSERT(versionNumber.data.at(0) == 2);

        auto serialNumber = ReadASNData(tbsData);
        ASSERT(serialNumber.tag == ASN_INTEGER && serialNumber.data);
        status.serialNumber = serialNumber.data;

        auto algorithmLevel = ReadASNData(tbsData);

        auto issuedBy = ReadASNData(tbsData);
        ASSERT(issuedBy.tag == ASN_SEQUENCE);
        authority.name = ParseName(issuedBy.data);

        auto validity = ReadASNData(tbsData);
        ASSERT(validity.tag == ASN_SEQUENCE);

        auto validityFrom = ReadASNData(validity.data);
        ASSERT(validityFrom.tag == ASN_UTCTIME);
        auto fromTime = String.parseASNtime(validityFrom.data);

        auto validityTo = ReadASNData(validity.data);
        ASSERT(validityTo.tag == ASN_UTCTIME);
        auto toTime = String.parseASNtime(validityTo.data);

        status.expiresAt = fromTime < GetTimeS() ? toTime : GetTimeS() - SEC_PER_DAY;

        auto subjectSeq = ReadASNData(tbsData);
        ASSERT(subjectSeq.tag == ASN_SEQUENCE);
        subject.name = ParseName(subjectSeq.data);

        auto keySequence = ReadASNData(tbsData);
        subject.publicKey = X509.ParsePublicKey(keySequence);

        auto extension = ReadASNData(tbsData);
        if (extension.tag == ASN_CTX_CTAG_3)
        {
            extension = ReadASNData(extension.data);
            ASSERT(extension.tag == ASN_SEQUENCE);
            while (extension.data)
            {
                auto extSequence = ReadASNData(extension.data);
                if (extSequence.tag == ASN_SEQUENCE)
                {
                    auto name = ReadASNData(extSequence.data);
                    auto value = ReadASNData(extSequence.data);
                    auto isCritical = false;
                    if (value.tag == ASN_BOOLEAN)
                    {
                        isCritical = true;
                        value = ReadASNData(extSequence.data);
                    }
                    ASSERT(value.tag == ASN_OCTETSTRING);
                    if (value.tag == ASN_OCTETSTRING)
                    {
                        value = ReadASNData(value.data);
                    }
                    if (name.tag == ASN_OID)
                    {
                        if (name.data == OID_id_ce_subjectKeyIdentifier)
                        {
                            LogInfo("subjectKeyId");
                            subject.keyId = value.data;
                        }
                        else if (name.data == OID_id_ce_authorityKeyIdentifier)
                        {
                            LogInfo("authorityKeyId");
                            ASSERT(value.tag == ASN_SEQUENCE);
                            auto extensionValue = ReadASNData(value.data);
                            ASSERT(extensionValue.tag == ASN_CTX_PTAG_0);
                            authority.keyId = extensionValue.data;
                        }
                        else if (name.data == OID_id_ce_subjectAltName)
                        {
                            LogInfo("subjectAltName");
                            TSTRING_STREAM nameStream;
                            while (value.data)
                            {
                                auto nextValue = ReadASNData(value.data);
                                if (nextValue.tag == ASN_CTX_PTAG_2) nameStream.append(nextValue.data);
                            }
                            subject.altNames = nameStream.toBuffer();
                        }
                        else if (name.data == OID_id_ce_basicConstraints)
                        {
                            LogInfo("basicConstraints");
                            ASSERT(value.tag == ASN_SEQUENCE);
                            if (value.data)
                            {
                                auto value1 = ReadASNData(value.data);
                                ASSERT(value1.tag == ASN_BOOLEAN);
                                status.isCA = value1.data.peek() != 0;
                            }
                        }
                        else if (name.data == OID_id_ce_keyUsage)
                        {
                            LogInfo("keyUsage");
                            ASSERT(value.tag == ASN_BITSTRING);
                            status.keyUsage = value.data.peek();
                        }
                        else if (name.data == OID_id_ce_CRLDistributionPoints)
                        {
                            // crl
                        }
                        else if (name.data == OID_id_ce_extKeyUsage)
                        {
                            // ext key usage
                        }
                        else if (name.data == OID_id_ce_subjectDirectoryAttributes)
                        {
                            // SDA
                        }
                        else DBGBREAK();
                    }
                    else DBGBREAK();
                }
                else DBGBREAK();
            }
            result = true;
        }
        return result;
    }

    BUFFER SplitParts(BUFFER certBytes, BUFFER& tbsData, BUFFER& signature, BUFFER& algorithm)
    {
        auto&& dataStream = ByteStream(256);
        BUFFER tbsHash;

        auto topLevel = ReadASNData(certBytes);
        ASSERT(topLevel.tag == ASN_SEQUENCE);

        auto certLevel = ReadASNData(topLevel.data, tbsData);
        ASSERT(certLevel.tag == ASN_SEQUENCE);

        auto algSequence = ReadASNData(topLevel.data);
        if (algSequence.tag == ASN_SEQUENCE)
        {
            auto alg = ReadASNData(algSequence.data);
            if (alg.tag == ASN_OID)
            {
                algorithm = alg.data;
                auto signatureElement = ReadASNData(topLevel.data);
                if (alg.data == OID_sha256WithRSAEncryption || alg.data == OID_ecdsa_with_SHA256)
                {
                    // handle RSA
                    signature = X509.ParseECDSASignature(signatureElement.data, dataStream.commitTo(EC256_BYTES*2), EC256_BYTES);
                    tbsHash = Sha256ComputeHash(dataStream.commitTo(SHA256_HASH_LENGTH), tbsData);
                }
                else if (alg.data == OID_sha384WithRSAEncryption || alg.data == OID_ecdsa_with_SHA384)
                {
                    signature = X509.ParseECDSASignature(signatureElement.data, dataStream.commitTo(EC384_BYTES*2), EC384_BYTES);
                    tbsHash = Sha384ComputeHash(dataStream.commitTo(SHA384_HASH_LENGTH), tbsData);
                }
                else DBGBREAK();
            }
        }
        else DBGBREAK();

        return tbsHash;
    }

    static BUFFER FormatName(BYTESTREAM& outStream, BUFFER oid, BUFFER value)
    {
        auto streamOffset = outStream.getPosition();
        WriteASNData(outStream, ASN_SET, [](BYTESTREAM& outStream, BUFFER oid, BUFFER value)
            {
                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER oid, BUFFER value)
                    {
                        WriteASNData(outStream, ASN_OID, oid);
                        WriteASNData(outStream, ASN_PRINTSTRING, value);
                    }, oid, value);
            }, oid, value);
        return streamOffset.toBuffer();
    }
    

    template <typename FUNC>
    static void formatExtensionParam(BYTESTREAM& outStream, BUFFER oid, FUNC&& func, auto&& ... args)
    {
        WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER oid, FUNC& func, auto&& ... args)
            {
                WriteASNoid(outStream, oid);
                WriteASNData(outStream, ASN_OCTETSTRING, [](BYTESTREAM& outStream, FUNC& func, auto&& ... args)
                    {
                        func(outStream, args ...);
                    }, func, args ...);
            }, oid, func, args ...);
    }

    static BUFFER formatExtension(BYTESTREAM& outStream, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
    {
        auto savedPosition = outStream.getPosition();
        WriteASNData(outStream, ASN_CTX_CTAG_3, [](BYTESTREAM& outStream, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
            {
                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
                    {
                        formatExtensionParam(outStream, OID_id_ce_subjectKeyIdentifier, [](BYTESTREAM& outStream, BUFFER value)
                            {
                                WriteASNData(outStream, ASN_OCTETSTRING, value);
                            }, subject.keyId);

                        formatExtensionParam(outStream, OID_id_ce_authorityKeyIdentifier, [](BYTESTREAM& outStream, BUFFER value)
                            {
                                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER value)
                                    {
                                        WriteASNData(outStream, ASN_CTX_PTAG_0, value);
                                    }, value);;
                            }, authority.keyId);

                        formatExtensionParam(outStream, OID_id_ce_basicConstraints, [](BYTESTREAM& outStream, bool isCA)
                            {
                                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, bool isCA)
                                    {
                                        WriteASNboolean(outStream, isCA);
                                    }, isCA);;
                                WriteASNInteger(outStream, isCA);
                            }, status.isCA);

                        if (status.keyUsage)
                        {
                            formatExtensionParam(outStream, OID_id_ce_keyUsage, [](BYTESTREAM& outStream, UINT32 value)
                                {
                                    WriteASNbitString(outStream, value);
                                }, status.keyUsage);
                        }

                        if (subject.altNames)
                        {
                            formatExtensionParam(outStream, OID_id_ce_subjectAltName, [](BYTESTREAM& outStream, STREAM_READER<const BUFFER> altNames)
                                {
                                    WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, STREAM_READER<const BUFFER> altNames)
                                        {
                                            for (auto&& name : altNames)
                                            {
                                                WriteASNData(outStream, ASN_CTX_PTAG_2, name);
                                            }
                                        }, altNames);;
                                }, subject.altNames);
                        }

                    }, subject, authority, status);
            }, subject, authority, status);
        return savedPosition.toBuffer();
    }

    static BUFFER FormatTBS(BYTESTREAM& outStream, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
    {
        auto savedPosition = outStream.getPosition();
        WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, X509_SUBJECT& subject, X509_AUTHORITY& authority, X509_STATUS& status)
            {
                WriteASNData(outStream, ASN_CTX_CTAG_0, [](BYTESTREAM& outStream)
                    {
                        WriteASNInteger(outStream, 2);
                    });
                WriteASNInteger(outStream, status.serialNumber);

                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream)
                    {
                        WriteASNoid(outStream, OID_ecdsa_with_SHA256);
                    });

                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER authorityName)
                    {
                        FormatName(outStream, OID_id_at_commonName, authorityName);
                    }, authority.name);

                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, UINT64 expiresAt)
                    {
                        WriteASNtime(outStream, GetTimeS() - (5 * SEC_PER_DAY));
                        WriteASNtime(outStream, expiresAt);
                    }, status.expiresAt);

                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER subjectName)
                    {
                        FormatName(outStream, OID_id_at_commonName, subjectName);
                    }, subject.name);

                WriteASNData(outStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER publicKey)
                    {
                        X509.FormatECCpublicKey(outStream, publicKey);
                    }, subject.publicKey);
                formatExtension(outStream, subject, authority, status);
            }, subject, authority, status);
        return savedPosition.toBuffer();
    }

    BUFFER FormatX509(BYTESTREAM& certStream, BUFFER tbsData, BUFFER signature)
    {
        auto streamOffset = certStream.mark();
        WriteASNData(certStream, ASN_SEQUENCE, [](BYTESTREAM& outStream, BUFFER tbsData, BUFFER signature)
            {
                outStream.writeBytes(tbsData);
                X509.FormatECDSAsignature(outStream, signature);
            }, tbsData, signature);

        return certStream.toBuffer(streamOffset);
    }
};

constexpr UINT64 DEFAULT_CERT_VALID_DAYS = 500;

struct X509_PARTS
{
    BUFFER tbsData;
    BUFFER signature;
    BUFFER algorithm;
    BUFFER tbsHash;

    X509_SUBJECT subject; 
    X509_STATUS status; 
    X509_AUTHORITY authority;

    bool isValid = false;
    X509_PARTS(BUFFER certBytes)
    {
        if (certBytes)
        {
            if (tbsHash = X509.SplitParts(certBytes, tbsData, signature, algorithm))
            {
                ASSERT(algorithm == OID_ecdsa_with_SHA256);
                if (X509.ParseTBS(tbsData, subject, authority, status))
                {
                    isValid = true;
                }
            }
        }
    }

    BUFFER getPublicKey(BYTESTREAM& dataStream)
    {
        return isValid ? dataStream.writeBytesTo(subject.publicKey) : NULL_BUFFER;
    }

    explicit operator bool() const { return isValid; }
};

struct X509_KEY
{
    TPM_HANDLE signHandle = 0;
    EC256_PUBLICKEY signPublicKey;

    BUFFER certBytes;
    
    UINT8 keyUsage = 0;

    U128 nodeId;

    NTSTATUS create(BUFFER label)
    {
        signHandle = TPM.createECDSAhandle(NULL_BUFFER, label, signPublicKey);
        nodeId = TPM.KeyCipher.hash(signPublicKey);
        return signHandle != 0 ? STATUS_SUCCESS : STATUS_UNSUCCESSFUL;
    }

    void close()
    {
        signHandle = 0;
        RtlZeroMemory(signPublicKey, sizeof(signPublicKey));
    }

    BUFFER signHash(BUFFER inputHash, BYTESTREAM&& signature)
    {
        TPM.sign(signHandle, inputHash, std::move(signature));
        return signature.toBuffer();
    }

    BUFFER signData(BUFFER input, BYTESTREAM&& signature)
    {
        SHA256_DATA inputHash;
        Sha256ComputeHash(inputHash, input);
        return signHash(inputHash, std::move(signature));
    }

    BUFFER buildCSR(bool isCA, UINT32 keyUsage, BUFFER name, STRINGBUFFER dnsNames)
    {
        X509_SUBJECT subject; X509_STATUS status; X509_AUTHORITY authority;
        subject.name = authority.name = name;
        subject.keyId = authority.keyId = nodeId;
        subject.altNames = dnsNames;
        subject.publicKey = signPublicKey;

        status.isCA = isCA;
        status.keyUsage = keyUsage;
        status.serialNumber = nodeId;
        status.expiresAt = GetTimeS() + (10 * SEC_PER_DAY);

        auto&& certStream = ByteStream(2048);
        auto tbsData = X509.FormatTBS(certStream, subject, authority, status);

        auto signature = signData(tbsData, certStream.commitTo(ECDSA_SIGN_LENGTH));
        auto newCertBytes = X509.FormatX509(certStream, tbsData, signature);

        return newCertBytes;
    }

    explicit operator bool() const { return signHandle != 0; }
};

struct NODEID_PUBLICKEY_MAP
{
    U128 id;
    U512 publicKey;

    NODEID_PUBLICKEY_MAP(BUFFER idBuf, BUFFER keyBuf)
    {
        ASSERT(idBuf.length() == sizeof(id.u8) && keyBuf.length() == sizeof(publicKey.u8));
        RtlCopyMemory(id.u8, idBuf.data(), idBuf.length());
        RtlCopyMemory(publicKey.u8, keyBuf.data(), keyBuf.length());
    }
};

struct X509_CA
{
    DATASTREAM<NODEID_PUBLICKEY_MAP, GLOBAL_STACK> knownCAs;

    X509_KEY signKey;
    bool isCA = false;
    
    X509_AUTHORITY caAuthority;

    void create(BUFFER label)
    {
        signKey.create(label);
    }

    bool import(BUFFER certBytes)
    {
        auto result = false;
        if (auto&& parts = X509_PARTS(certBytes))
        {
            auto&& subject = parts.subject;
            if (ecdsa_verify(signKey.signPublicKey, parts.tbsHash, parts.signature)) // self-signed
            {
                caAuthority.keyId = subject.keyId;
                caAuthority.name = subject.name;
                isCA = true;
            }
            else
            {
                signKey.close();
            }

            knownCAs.append(subject.keyId, subject.publicKey);
            result = true;
        }
        return result;
    }

    bool verifySignature(U128 authorityKeyId, BUFFER signHash, BUFFER signature)
    {
        auto result = false;
        ASSERT(signHash.length() == SHA256_HASH_LENGTH);

        for (auto&& map : knownCAs.toBuffer())
        {
            if (map.id == authorityKeyId)
            {
                result = ecdsa_verify(map.publicKey, signHash, signature);
                break;
            }
        }
        return result;
    }

    bool verifySignature(BUFFER certBytes, X509_SUBJECT& subject)
    {
        auto isValid = false;
        if (auto&& parts = X509_PARTS(certBytes))
        {
            isValid = verifySignature(parts.authority.keyId.readU128(), parts.tbsHash, parts.signature);
            subject = parts.subject;
        }
        return isValid;
    }

    bool importAK(BUFFER certBytes, X509_KEY& AK)
    {
        ASSERT(AK.signHandle);
        auto result = false;
        do
        {
            auto&& parts = X509_PARTS(certBytes);
            if (!parts) break;

            auto match = verifySignature(parts.authority.keyId.readU128(), parts.tbsHash, parts.signature);
            if (!match) break;

            if (parts.subject.publicKey != AK.signPublicKey)
                break;

            AK.nodeId = parts.subject.keyId.readU128();

            AK.certBytes = GlobalStack().blobStream.writeBytesTo(certBytes);
            result = true;
        } while (false);
        return result;
    }

    BUFFER signCSR(BUFFER csrBytes, BYTESTREAM&& certStream)
    {
        BUFFER newCertBytes;
        if (auto&& certInfo = X509_PARTS(csrBytes))
        {
            ASSERT(certInfo.algorithm == OID_ecdsa_with_SHA256);
            auto&& subject = certInfo.subject;
            if (ecdsa_verify(subject.publicKey, certInfo.tbsHash, certInfo.signature)) // self-signed
            {
                auto nodeId = TPM.KeyCipher.hash(subject.publicKey);

                X509_STATUS newStatus;
                newStatus.serialNumber = nodeId;
                newStatus.keyUsage = CERT_KEYUSAGE;
                newStatus.expiresAt = GetTimeS() + (DEFAULT_CERT_VALID_DAYS * SEC_PER_DAY);

                X509_SUBJECT newSubject;
                newSubject.name = subject.name;
                newSubject.keyId = nodeId;
                newSubject.altNames = subject.altNames;
                newSubject.publicKey = subject.publicKey;

                auto&& tempStream = ByteStream(2048);
                auto tbsData = X509.FormatTBS(tempStream, newSubject, caAuthority, newStatus);

                auto signature = signKey.signData(tbsData, tempStream.commitTo(ECDSA_SIGN_LENGTH));

                newCertBytes = X509.FormatX509(certStream, tbsData, signature);
            }
        }

        return newCertBytes;
    }
};

template <typename CERT_STREAM>
void ValidateCertChain(CERT_STREAM&& certStream)
{
	auto certs = certStream.toBuffer();

	auto&& firstCert = certStream.at(0);
	auto hash = firstCert.hash.toBuffer();
	auto signature = firstCert.signature;

	BCRYPT_PKCS1_PADDING_INFO padding;
	padding.pszAlgId = BCRYPT_SHA256_ALGORITHM;

	BCRYPT_PSS_PADDING_INFO paddingInfo;
	paddingInfo.pszAlgId = BCRYPT_SHA256_ALGORITHM;
	paddingInfo.cbSalt = 32;

	auto status = BCryptVerifySignature(certs[1].keyHandle, &padding, (PUCHAR)hash.data(), 32, (PUCHAR)signature.data(), signature.length(), BCRYPT_PAD_PKCS1);
	ASSERT(NT_SUCCESS(status));
}

