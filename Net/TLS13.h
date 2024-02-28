
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct HKDF
{
    UINT32 keySize;
    SHA512_DATA keyData{ 0 };

    BYTESTREAM keyStream() { return BYTESTREAM(keyData, keySize); }
    BUFFER keyBuffer() { return BUFFER(keyData, keySize); }

    HKDF() {}

    void initialize(UINT32 hashSize)
    {
        initialize(hashSize, Crypto.getZeroHmac(hashSize));
    }

    void copyTo(HKDF& other)
    {
        other.keySize = keySize;
        RtlCopyMemory(other.keyData, keyData, sizeof(keyData));
    }

    void initialize(UINT32 hashSize, BUFFER salt)
    {
        ASSERT(salt.length() == hashSize);

        keySize = hashSize;
        keyStream().writeBytes(salt);
    }

    void extract(BUFFER secret)
    {
        HmacSha(keyStream(), keyBuffer(), secret);
    }

    void extract(BUFFER salt, BUFFER secret)
    {
        HmacSha(keyStream(), salt, secret);
    }

    void extract()
    {
        extract(ZeroBytes.toBuffer(keySize));
    }

    BUFFER deriveKey(BUFFER secret, BUFFER label, BUFFER context, BYTESTREAM&& outStream)
    {
        ASSERT(outStream.size() == outStream.spaceLeft());
        ASSERT(outStream.size() == AES128_KEY_LENGTH || outStream.size() == AES256_KEY_LENGTH || outStream.size() == AES_GCM_IV_LENGTH);

        ASSERT(secret.length() == keySize);

        LOCAL_STREAM<88> labelStream;

        labelStream.beWriteU16(UINT16(outStream.size()));

        auto offset = labelStream.saveOffset(1);
        labelStream.writeBytes("tls13 ");
        labelStream.writeBytes(label);
        offset.writeLength();

        labelStream.writeByte(UINT8(context.length()));
        labelStream.writeBytes(context);
        labelStream.writeByte(0x01);  // RFC5869, T(1), we do just one round

        auto hash = HmacSha(ByteStream(keySize), secret, labelStream.toBuffer());

        ASSERT(outStream.spaceLeft() <= hash.length());
        outStream.writeBytes(hash, outStream.size());

        return outStream.toBuffer();
    }

    BUFFER deriveSecret(BUFFER label, BUFFER context, BYTESTREAM&& outStream)
    {
        ASSERT(outStream.size() == keySize);
        return deriveKey(keyBuffer(), label, context, std::move(outStream));
    }

    void update()
    {
        deriveKey(keyBuffer(), "derived", Crypto.getNullHash(keySize), keyStream());
    }
};

struct TLS13_CIPHER
{
    UINT32 keySize;
    UINT32 hashSize;
    CIPHER_SUITE cipherSuite;

    BYTESTREAM hashStream() { return ByteStream(hashSize); }

    X25519_KEYSHARE keyShare;

    SHA_STREAM clientHandshakeSecret;
    SHA_STREAM serverHandshakeSecret;

    SHA_STREAM clientMasterSecret;
    SHA_STREAM serverMasterSecret;

    AES_GCM sendKey;
    AES_GCM recvKey;

    UINT64 sendSequenceNumber = 0;
    UINT64 recvSequenceNumber = 0;

    bool isEncrypted = false;
    bool isServer;

    TLS13_CIPHER(bool isServer) : isServer(isServer) {}

    void setCipher(CIPHER_SUITE suite)
    {
        cipherSuite = suite;
        if (cipherSuite == TLS_AES_128_GCM_SHA256)
        {
            hashSize = SHA256_HASH_LENGTH;
            keySize = AES128_KEY_LENGTH;
        }
        else if (cipherSuite == TLS_AES_256_GCM_SHA384)
        {
            hashSize = SHA384_HASH_LENGTH;
            keySize = AES256_KEY_LENGTH;
        }
        else DBGBREAK();
        clientHandshakeSecret.resize(hashSize);
        serverHandshakeSecret.resize(hashSize);
        clientMasterSecret.resize(hashSize);
        serverMasterSecret.resize(hashSize);
    }

    template <typename STREAM>
    NTSTATUS writePublicKey(STREAM&& buffer)
    {
        keyShare.getPublicKey(buffer);
        return STATUS_SUCCESS;
    }

    NTSTATUS createSecret(BUFFER importData)
    {
        keyShare.createSecret(importData);
        return STATUS_SUCCESS;
    }

    template <typename STREAM>
    BYTESTREAM&& ToByteStream(STREAM&& stream)
    {
        return std::move(stream.byteStream());
    }

    void generateHandshakeKeys(HKDF& kdf, TRANSCRIPT_HASH& transcript)
    {
        isEncrypted = true;

        kdf.update();
        kdf.extract(keyShare.sharedSecret);

        kdf.deriveSecret("c hs traffic", transcript.getHash(), std::move(clientHandshakeSecret.byteStream()));

        auto key = kdf.deriveKey(clientHandshakeSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? recvKey.setKey(key) : sendKey.setKey(key);
        kdf.deriveKey(clientHandshakeSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? recvKey.saltStream() : sendKey.saltStream());

        kdf.deriveSecret("s hs traffic", transcript.getHash(), std::move(serverHandshakeSecret.byteStream()));

        key = kdf.deriveKey(serverHandshakeSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? sendKey.setKey(key) : recvKey.setKey(key);
        kdf.deriveKey(serverHandshakeSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? sendKey.saltStream() : recvKey.saltStream());
    }

    void generateMasterKeys(HKDF& kdf, BUFFER transcriptHash)
    {
        kdf.update();
        kdf.extract();

        sendSequenceNumber = 0;
        recvSequenceNumber = 0;

        kdf.deriveSecret("c ap traffic", transcriptHash, std::move(clientMasterSecret.byteStream()));

        auto key = kdf.deriveKey(clientMasterSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? recvKey.setKey(key) : sendKey.setKey(key);
        kdf.deriveKey(clientMasterSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? recvKey.saltStream() : sendKey.saltStream());

        kdf.deriveSecret("s ap traffic", transcriptHash, std::move(serverMasterSecret.byteStream()));

        key = kdf.deriveKey(serverMasterSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? sendKey.setKey(key) : recvKey.setKey(key);
        kdf.deriveKey(serverMasterSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? sendKey.saltStream() : recvKey.saltStream());
    }

    void updateMasterKeys(HKDF& kdf, BUFFER label)
    {
        DBGBREAK();
        kdf.deriveKey(clientMasterSecret.toBuffer(), label, NULL_BUFFER, std::move(clientMasterSecret.clear().byteStream()));
        kdf.deriveKey(serverMasterSecret.toBuffer(), label, NULL_BUFFER, std::move(serverMasterSecret.clear().byteStream()));

        auto key = kdf.deriveKey(clientMasterSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? recvKey.setKey(key) : sendKey.setKey(key);
        kdf.deriveKey(clientMasterSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? recvKey.saltStream() : sendKey.saltStream());

        key = kdf.deriveKey(serverMasterSecret.toBuffer(), "key", NULL_BUFFER, ByteStream(keySize));
        isServer ? sendKey.setKey(key) : recvKey.setKey(key);
        kdf.deriveKey(serverMasterSecret.toBuffer(), "iv", NULL_BUFFER, isServer ? sendKey.saltStream() : recvKey.saltStream());
    }

    void encrypt(RWBUFFER record)
    {
        auto aad = record.readBytes(TLS_RECORD_HEADER).toBuffer();
        auto tag = record.shrink(AES_TAG_LENGTH);

        auto seqNumber = sendSequenceNumber++;

        AES_GCM_IV ivData;
        ivData.setU32(0, SWAP32(seqNumber >> 32), SWAP32(seqNumber));

        sendKey.encrypt(ivData, aad, record, tag.readU128());
    }

    BUFFER decrypt(RWBUFFER record)
    {
        auto additonalData = record.readBytes(TLS_RECORD_HEADER).toBuffer();

        auto tag = record.shrink(AES_TAG_LENGTH);

        auto seqNumber = recvSequenceNumber++;

        AES_GCM_IV ivData;
        ivData.setU32(0, SWAP32(seqNumber >> 32), SWAP32(seqNumber));

        return recvKey.decrypt(ivData, additonalData, record, tag.toBuffer());
    }
};

template <typename SERVICE>
struct TLS13_HANDSHAKE
{
    SERVICE& session;
    TRANSCRIPT_HASH transcriptHash;

    HKDF kdf;
    TLS13_CIPHER cipher;
    TOKEN serverName;
    TOKEN alpn;

    BYTESTREAM sendStream;
    BYTESTREAM recvStream;

    BUFFER peerPublicKey;
    bool isHandshakeComplete = false;
    bool isServer;

    UINT64 cryptoFrameOffset = 0;

    TLS13_HANDSHAKE(SERVICE& session, bool isServer) : session(session), isServer(isServer), cipher(isServer) {}

    void init(TOKEN server, TOKEN alpnName)
    {
        serverName = server;
        alpn = alpnName;
        recvStream.allocReserve<SESSION_STACK>(TLS_RECORD_SIZE);
        sendStream.allocReserve<SESSION_STACK>(TLS_RECORD_SIZE / 2);
    }

    BUFFER readExtension(BUFFER& message, EXTENSION_TYPE& type)
    {
        type = message.readEnumBE<EXTENSION_TYPE>();
        auto length = message.beReadU16();

        return message.readBytes(length);
    }

    void setCipher(CIPHER_SUITE suite)
    {
        cipher.setCipher(suite);
        kdf.initialize(cipher.hashSize);
        transcriptHash.init(cipher.hashSize);
    }

    template <typename FUNC, typename ... ARGS>
    NTSTATUS sendData(FUNC func, ARGS&& ... args)
    {
        if (isHandshakeComplete == false)
            return STATUS_CONNECTION_INVALID;

        return sendRecord(record_application_data, func, args ...);
    }

    auto& getScheduler() { return session.getScheduler(); }

    BUFFER readVariableData(BUFFER& message, UINT8 lengthBytes)
    {
        auto length = message.readIntBE(lengthBytes);
        return message.readBytes(length);
    }

    void formatServerName(BYTESTREAM& recordStream)
    {
        recordStream.writeEnumBE(ext_server_name);
        {
            auto extLength = recordStream.saveOffset(2);
            {
                auto nameListLength = recordStream.saveOffset(2);
                recordStream.writeByte(0); // type
                {
                    auto nameLength = recordStream.saveOffset(2);
                    recordStream.writeName(serverName);
                    nameLength.writeLength();
                }
                nameListLength.writeLength();
            }
            extLength.writeLength();
        }
    }

    bool parseServerName(BUFFER& data)
    {
        auto isValid = false;
        data = readVariableData(data, 2);
        while (data)
        {
            auto type = data.readByte();
            ASSERT(type == 0);
            auto nameString = readVariableData(data, 2);
            auto name = CreateServiceName(nameString);
            if (name == serverName)
                isValid = true;
            LogInfo("server_name, length:", nameString.length());
        }
        return isValid;
    }

    void formatKeyshare(BYTESTREAM& recordStream)
    {
        recordStream.writeEnumBE(ext_key_share);
        auto extLength = recordStream.saveOffset(2);
        if (isServer)
        {
            recordStream.writeEnumBE(SUPPORTED_GROUPS::x25519);
            recordStream.beWriteU16(0x20); // key length
            cipher.keyShare.getPublicKey(std::move(recordStream));
        }
        else
        {
            auto dataLength = recordStream.saveOffset(2);
            recordStream.writeEnumBE(SUPPORTED_GROUPS::x25519);

            recordStream.beWriteU16(0x20); // key length
            cipher.keyShare.getPublicKey(std::move(recordStream));
            dataLength.writeLength();
        }
        extLength.writeLength();
    }

    bool parseKeyshare(BUFFER& data)
    {
        auto isValid = false;
        if (isServer)
        {
            data = readVariableData(data, 2);
            while (data)
            {
                auto groupName = data.readEnumBE<SUPPORTED_GROUPS>();
                auto key = readVariableData(data, 2);
                if (groupName == SUPPORTED_GROUPS::x25519)
                {
                    cipher.keyShare.createSecret(key);
                    isValid = true;
                }
            }
        }
        else
        {
            auto groupName = data.readEnumBE<SUPPORTED_GROUPS>();
            if (groupName == SUPPORTED_GROUPS::x25519)
            {
                auto key = readVariableData(data, 2);
                cipher.keyShare.createSecret(key);
                isValid = true;
            }
        }
        return isValid;
    }

    void formatSupportedGroups(BYTESTREAM& recordStream)
    {
        recordStream.writeEnumBE(ext_supported_groups);
        auto extLength = recordStream.saveOffset(2);
        {
            auto groupLength = recordStream.saveOffset(2);
            recordStream.writeEnumBE(SUPPORTED_GROUPS::x25519);
            groupLength.writeLength();
        }
        extLength.writeLength();
    }

    bool parseSupportedGroups(BUFFER& data)
    {
        auto isValid = false;
        if (isServer)
        {
            data = readVariableData(data, 2);
            while (data)
            {
                auto group = data.readEnumBE<SUPPORTED_GROUPS>();
                if (group == SUPPORTED_GROUPS::x25519)
                    isValid = true;
            }
        }
        else
        {
            auto group = data.readEnumBE<SUPPORTED_GROUPS>();
            if (group == SUPPORTED_GROUPS::x25519)
                isValid = true;
            else DBGBREAK();
        }
        return isValid;
    }

    void formatSignatureAlgorithms(BYTESTREAM& recordStream)
    {
        recordStream.writeEnumBE(ext_signature_algorithms);
        auto extLength = recordStream.saveOffset(2);
        {
            auto algLength = recordStream.saveOffset(2);

            recordStream.writeEnumBE(rsa_pss_rsae_sha256);
            recordStream.writeEnumBE(rsa_pss_pss_sha256);
            recordStream.writeEnumBE(ecdsa_secp256r1_sha256);
            algLength.writeLength();
        }
        extLength.writeLength();
    }

    bool parseSignatureAlgorithms(BUFFER& data)
    {
        auto isValid = false;
        data = readVariableData(data, 2);
        while (data)
        {
            auto signatureSchme = data.readEnumBE<SIGNATURE_SCHEME>();
            if (signatureSchme == ecdsa_secp256r1_sha256)
                isValid = true;
            LogInfo("signature scheme: ", UINT32(signatureSchme));
        }
        return isValid;
    }

    void formatSupportedVersions(BYTESTREAM& recordStream)
    {
        recordStream.writeEnumBE(ext_supported_versions);
        auto offset = recordStream.saveOffset(2);

        if (isServer)
        {
            recordStream.writeEnumBE(VER_TLS13);
        }
        else
        {
            recordStream.writeByte(2); // we support only 1 version
            recordStream.writeEnumBE(VER_TLS13);
        }
        offset.writeLength();
    }

    bool parseSupportedVersions(BUFFER& data)
    {
        auto isValid = false;
        if (isServer)
        {
            data = readVariableData(data, 1);
            while (data)
            {
                auto version = data.readEnumBE<TLS_VERSION>();
                if (version == VER_TLS13)
                    isValid = true;
            }
        }
        else
        {
            auto version = data.readEnumBE<TLS_VERSION>();
            if (version == VER_TLS13)
                isValid = true;
            else DBGBREAK();
        }
        return isValid;
    }

    void formatALPN(BYTESTREAM& recordStream)
    {
        if (alpn)
        {
            auto alpnName = NameToString(alpn);
            recordStream.writeEnumBE(ext_application_layer_protocol_negotiation);
            auto extLength = recordStream.saveOffset(2);
            {
                auto listLength = recordStream.saveOffset(2);
                recordStream.writeByte(alpnName.length());
                recordStream.writeBytes(alpnName);
                listLength.writeLength();
            }
            extLength.writeLength();
        }
    }

    bool parseALPN(BUFFER& extensionData)
    {
        auto isValid = false;

        auto alpnNames = readVariableData(extensionData, 2);
        while (alpnNames)
        {
            auto nameString = readVariableData(alpnNames, 1);
            auto nameToken = CreateServiceName(nameString);
            if (nameToken == alpn)
            {
                isValid = true;
                break;
            }
        }
        return isValid;
    }

    void sendChangeCipherSpec()
    {
        LOCAL_STREAM<16> record;
        record.writeEnumBE(record_change_cipher_spec);
        record.writeEnumBE(VER_TLS12);
        record.beWriteU16(1);
        record.writeByte(1);

        session.send(record.toBuffer());
    }

    void formatClientHello(BYTESTREAM& recordStream)
    {
        ASSERT(!isServer);
        auto msgStart = recordStream.getPosition();
        recordStream.writeEnumBE(client_hello);

        auto msgLength = recordStream.saveOffset(3);
        recordStream.writeEnumBE(VER_TLS12);

        Random.getBytes(recordStream.commitTo(32));

        recordStream.writeByte(0); // no session id

        recordStream.beWriteU16(2);
        recordStream.writeEnumBE(TLS_AES_128_GCM_SHA256);

        recordStream.writeByte(1);
        recordStream.writeByte(0); // zero compression

        {
            auto extensionOffset = recordStream.saveOffset(2);

            formatSupportedVersions(recordStream);
            formatSignatureAlgorithms(recordStream);
            formatSupportedGroups(recordStream);
            formatServerName(recordStream);
            formatKeyshare(recordStream);
            formatALPN(recordStream);
            session.formatClientTransportParams(recordStream);
            extensionOffset.writeLength();
        }

        msgLength.writeLength();
        transcriptHash.addMessage(msgStart.toBuffer());
    }

    void sendClientHello()
    {
        sendRecord(record_handshake, [](BYTESTREAM& recordStream, TLS13_HANDSHAKE& handshake)
            {
                handshake.formatClientHello(recordStream);
            }, *this);
    }

    void doConnect()
    {
        auto&& sendPacket = session.sendCryptoFrame(PACKET_INITIAL, cryptoFrameOffset, [](BYTESTREAM& recordStream, TLS13_HANDSHAKE& handshake)
            {
                handshake.formatClientHello(recordStream);
            }, *this);
        session.sendPacket(sendPacket, PACKET_INITIAL);
        cryptoFrameOffset = 0;
    }

    bool parseClientHello(BUFFER data, BUFFER& sessionId)
    {
        auto isValid = false;
        do
        {
            data.readEnumBE<TLS_VERSION>();
            auto random = data.readBytes(32);

            sessionId = readVariableData(data, 1);

            auto cipherSuites = readVariableData(data, 2);

            while (cipherSuites)
            {
                auto cipher = cipherSuites.readEnumBE<CIPHER_SUITE>();
                if (cipher == TLS_AES_128_GCM_SHA256) // || cipher == TLS_AES_256_GCM_SHA384)
                    isValid = true;
            }

            setCipher(TLS_AES_128_GCM_SHA256);

            if (!isValid)
            {
                DBGBREAK();
                break;
            }

            auto compression = readVariableData(data, 1);
            ASSERT(compression.length() == 1);

            auto extension = readVariableData(data, 2);
            while (extension)
            {
                EXTENSION_TYPE extType;
                auto extData = readExtension(extension, extType);

                if (extType == ext_key_share)
                {
                    isValid = parseKeyshare(extData);
                }
                else if (extType == ext_server_name)
                {
                    isValid = parseServerName(extData);
                }
                else if (extType == ext_supported_groups)
                {
                    isValid = parseSupportedGroups(extData);
                }
                else if (extType == ext_supported_versions)
                {
                    isValid = parseSupportedVersions(extData);
                }
                else if (extType == ext_signature_algorithms)
                {
                    isValid = parseSignatureAlgorithms(extData);
                }
                else if (extType == ext_application_layer_protocol_negotiation)
                {
                    isValid = parseALPN(extData);
                }
                else if (extType == ext_quic_transport_parameters)
                {
                    session.parseTransportParams(extData);
                }
                else
                {
                    LogInfo("Unknown extension: ", UINT32(extType));
                }
                if (!isValid)
                {
                    DBGBREAK();
                    break;
                }
            }
        } while (false);
        return isValid;
    }

    void formatServerHello(BYTESTREAM& recordStream, BUFFER sessionId)
    {
        ASSERT(isServer);
        auto msgStart = recordStream.getPosition();
        recordStream.writeEnumBE(server_hello);
        
        auto msgLength = recordStream.saveOffset(3);

        recordStream.writeEnumBE(VER_TLS12);
        Random.getBytes(recordStream.commitTo(32));
        recordStream.writeByte((UINT8)sessionId.length());
        recordStream.writeBytes(sessionId);
        recordStream.writeEnumBE(cipher.cipherSuite);
        recordStream.writeByte(0);
        {
            auto extensionOffset = recordStream.saveOffset(2);
            //formatEncryptedExtensions(recordStream);
            formatKeyshare(recordStream);
            formatSupportedVersions(recordStream);
            extensionOffset.writeLength();
        }

        msgLength.writeLength();
        
        transcriptHash.addMessage(msgStart.toBuffer());
    }

    void sendServerHello(BUFFER sessionId)
    {
        sendRecord(record_handshake, [](BYTESTREAM& recordStream, TLS13_HANDSHAKE& handshake, BUFFER sessionId)
            {
                handshake.formatServerHello(recordStream, sessionId);
            }, *this, sessionId);
    }

    void sendAlert(ALERT_LEVEL level, ALERT_DESCRIPTION code)
    {
        sendRecord(record_alert, [](BYTESTREAM& recordStream, ALERT_LEVEL level, ALERT_DESCRIPTION code)
            {
                recordStream.writeEnumBE(level);
                recordStream.writeEnumBE(code);
            }, level, code);
    }

    void parseServerHello(BUFFER data)
    {
        data.readEnumBE<TLS_VERSION>();
        auto random = data.readBytes(32);

        auto sessionId = readVariableData(data, 1);

        auto cipherSuite = data.readEnumBE<CIPHER_SUITE>();
        setCipher(cipherSuite);

        data.readByte();

        auto extension = readVariableData(data, 2);
        while (extension)
        {
            EXTENSION_TYPE extType;
            auto extData = readExtension(extension, extType);

            if (extType == ext_supported_versions)
            {
                parseSupportedVersions(extData);
            }
            else if (extType == ext_key_share)
            {
                parseKeyshare(extData);
            }
            else if (extType == ext_supported_groups)
            {
                parseSupportedGroups(extData);
            }
            else if (extType == ext_signature_algorithms)
            {
                parseSignatureAlgorithms(extData);
            }
            else DBGBREAK();
        }
    }

    void formatEncryptedExtensions(BYTESTREAM& recordStream)
    {
        auto transcriptStart = recordStream.getPosition();
        recordStream.writeEnumBE(encrypted_extensions);
        {
            auto msgLength = recordStream.saveOffset(3);
            {
                auto extensionsLength = recordStream.saveOffset(2);
                extensionsLength.writeLength();
            }
            msgLength.writeLength();
        }
        transcriptHash.addMessage(transcriptStart.toBuffer());
    }

    void formatEncryptedExtensions(BYTESTREAM& recordStream, QPACKET& recvPacket)
    {
        auto transcriptStart = recordStream.getPosition();
        recordStream.writeEnumBE(encrypted_extensions);
        {
            auto msgLength = recordStream.saveOffset(3);
            {
                auto extensionsLength = recordStream.saveOffset(2);
                session.formatServerTransportParams(recordStream, recvPacket);
                formatALPN(recordStream);
                extensionsLength.writeLength();
            }
            msgLength.writeLength();
        }
        transcriptHash.addMessage(transcriptStart.toBuffer());
    }

    void parseEncryptedExtensions(BUFFER message)
    {
        auto msgData = readVariableData(message, 2);
        while (msgData)
        {
            auto extType = msgData.readEnumBE<EXTENSION_TYPE>();
            auto extData = readVariableData(msgData, 2);

            if (extType == ext_quic_transport_parameters)
            {
                session.parseTransportParams(extData);
            }
            else if (extType == ext_application_layer_protocol_negotiation)
            {
                parseALPN(extData);
            }
            else
            {
                LogInfo("extenstion type=", UINT32(extType));
            }
        }
    }

    void parseX509Certificate(BUFFER certData)
    {
        LogInfo("Parse certificate");
        peerPublicKey = X509_PARTS(certData).getPublicKey(GetSessionStack().blobStream);
    }

    void formatCertificates(BYTESTREAM& recordStream)
    {
        auto transcriptStart = recordStream.getPosition();
        recordStream.writeEnumBE(certificate);
        {
            auto msgLength = recordStream.saveOffset(3);

            recordStream.writeByte(0); // certificate context
            {
                auto allCertsLength = recordStream.saveOffset(3);
                {
                    auto certLength = recordStream.saveOffset(3);
                    recordStream.writeBytes(session.getTLScert());
                    certLength.writeLength();
                }
                recordStream.beWriteU16(0); // no extensions
                allCertsLength.writeLength();
            }

            msgLength.writeLength();
        }
        transcriptHash.addMessage(transcriptStart.toBuffer());
    }

    void parseCertificates(BUFFER message)
    {
        auto context = readVariableData(message, 1);

        auto certs = readVariableData(message, 3);

        if (certs)
        {
            // parse the first certificate, ignore the rest...
            auto certData = readVariableData(certs, 3);
            parseX509Certificate(certData);

            auto extension = readVariableData(certs, 2);
        }
    }

    BUFFER getVerifyHash()
    {
        auto hash = transcriptHash.getHash();

        auto&& hashStream = ByteStream(512);
        hashStream.writeBytes(Spaces, 64);
        hashStream.writeBytes("TLS 1.3, server CertificateVerify");
        hashStream.writeByte(0);
        hashStream.writeBytes(hash);

        auto verifyHash = HashSha(ByteStream(SHA256_HASH_LENGTH), hashStream.toBuffer());
        return verifyHash;
    }

    void formatCertificateVerify(BYTESTREAM& recordStream)
    {
        auto transcriptStart = recordStream.getPosition();
        recordStream.writeEnumBE(certificate_verify);
        {
            auto msgLength = recordStream.saveOffset(3);

            recordStream.writeEnumBE(ecdsa_secp256r1_sha256);
            auto verifyHash = getVerifyHash();

            auto signatureLength = recordStream.saveOffset(2);

            ECDSA_DATA signData;
            auto signature = SystemService().AKsignKey.signHash(verifyHash, signData);
            X509.FormatECDSAP256Signature(recordStream, signature);
            signatureLength.writeLength();

            msgLength.writeLength();
        }
        transcriptHash.addMessage(transcriptStart.toBuffer());
    }

    void parseCertificateVerify(BUFFER message)
    {
        auto signatureScheme = message.readEnumBE<SIGNATURE_SCHEME>();
        auto signature = readVariableData(message, 2);
        auto verifyHash = getVerifyHash();

        if (signatureScheme == ecdsa_secp256r1_sha256)
        {
            //UINT8 outData[64];
            ECDSA_DATA outData;
            auto sigData = X509.ParseECDSASignature(signature, outData);

            auto status = ecdsa_verify(peerPublicKey, verifyHash, sigData);
            ASSERT(status);
        }
        else DBGBREAK();
        LogInfo("Certificate Verify complete");
    }

    void formatFinished(BYTESTREAM& recordStream)
    {
        auto transcriptStart = recordStream.getPosition();
        recordStream.writeEnumBE(finished);
        {
            auto msgLength = recordStream.saveOffset(3);

            auto finishedKey = kdf.deriveKey(isServer ? cipher.serverHandshakeSecret.toBuffer() : cipher.clientHandshakeSecret.toBuffer(), "finished", NULL_BUFFER, cipher.hashStream());

            auto verifyHash = HmacSha(cipher.hashStream(), finishedKey, transcriptHash.getHash());

            recordStream.writeBytes(verifyHash);

            msgLength.writeLength();
        }
        transcriptHash.addMessage(transcriptStart.toBuffer());
    }

    bool parseFinished(BUFFER message)
    {
        auto receivedHash = message.readBytes(cipher.hashSize);

        auto finishedKey = kdf.deriveKey(isServer ? cipher.clientHandshakeSecret.toBuffer() : cipher.serverHandshakeSecret.toBuffer(), "finished", NULL_BUFFER, cipher.hashStream());

        auto transcript = transcriptHash.getHash();

        auto verifyHash = HmacSha(cipher.hashStream(), finishedKey, transcript);

        return (verifyHash == receivedHash);
    }

    UINT32 getRecordLength(BUFFER record)
    {
        // includes header length TLS_RECORD_HEADER
        ASSERT(record.length() >= TLS_RECORD_HEADER);

        record.shift(3);
        return record.beReadU16() + TLS_RECORD_HEADER;
    }

    BYTESTREAM::OFFSET sendLengthOffset;
    auto beginSendData()
    {
        ASSERT(isHandshakeComplete);

        auto&& recordStream = sendStream.clear();
        recordStream.writeEnumBE(record_application_data);
        recordStream.writeEnumBE(VER_TLS12);
        recordStream.saveOffset(2, sendLengthOffset);

        return BYTESTREAM{ recordStream.end(), recordStream.spaceLeft() - AES_TAG_LENGTH - 2 };
    }

    void finishSendData()
    {
        ASSERT(sendStream.count() > TLS_RECORD_HEADER);
        sendStream.writeEnumBE(record_application_data);
        sendStream.commit(AES_TAG_LENGTH);
        sendLengthOffset.writeLength();
        
        cipher.encrypt(sendStream.toRWBuffer());
        session.sendTLSdata(sendStream.toBuffer());
    }

    template <typename F, typename ... Args>
    NTSTATUS sendRecord(RECORD_TYPE recordType, F func, Args&& ... args)
    {
        auto&& recordStream = sendStream.clear();

        if (cipher.isEncrypted)
        {
            recordStream.writeEnumBE(record_application_data);
            recordStream.writeEnumBE(VER_TLS12);
            {
                auto recordLength = recordStream.saveOffset(2);
                func(recordStream, args ...);
                recordStream.writeEnumBE(recordType);
                recordStream.commit(AES_TAG_LENGTH);
                recordLength.writeLength();
            }
            cipher.encrypt(recordStream.toRWBuffer());
            auto status = session.sendTLShandshake(recordStream.toBuffer());
            return status;
        }
        else
        {
            ASSERT(recordType != record_application_data);
            recordStream.writeEnumBE(recordType);
            recordStream.writeEnumBE(VER_TLS12);
            {
                auto recordLength = recordStream.saveOffset(2);
                func(recordStream, args ...);
                recordLength.writeLength();
            }
            auto status = session.sendTLShandshake(recordStream.toBuffer());
            return status;
        }
    }

    BUFFER parseMessageHeader(BUFFER& recvBuffer, MESSAGE_TYPE& msgType, BUFFER& msgData)
    {
        auto msgStart = recvBuffer.data();

        msgType = recvBuffer.readEnumBE<MESSAGE_TYPE>();
        msgData = readVariableData(recvBuffer, 3);

        return { msgStart,  4 + msgData.length() };
    }

    UINT32 getMessageLength(BUFFER recvData)
    {
        recvData.shift(); // ignore type
        return recvData.readIntBE(3);
    }

    UINT32 tryParseMessageHeader(MBUF_READER mbuf, UINT32 contigBytes)
    {
        UINT32 msgLength = 0;
        if (contigBytes > 4)
        {
            auto data = mbuf.readBytes(4);
            data.shift();
            msgLength = data.readIntBE(3) + 4;
        }
        return msgLength;
    }

    BUFFER tryParseMessage(MBUF_READER& mbuf)
    {
        BUFFER message;
        if (mbuf.chainBytes() > 4)
        {
            auto header = mbuf.peekBytes(4);
            header.shift();
            auto msgLength = header.readIntBE(3) + 4;

            if (mbuf.chainBytes() >= msgLength)
            {
                message = mbuf.readBytes(msgLength);
            }
        }
        return message;
    }

    void sendServerHelloFrame(BYTESTREAM& packetStream, BUFFER sessionId)
    {
        session.formatCryptoFrame(packetStream, [](BYTESTREAM& frameStream, TLS13_HANDSHAKE& handshake, BUFFER sessionId)
            {
                handshake.formatServerHello(frameStream, sessionId);
            }*this, sessionId);
    }

    PDATAFRAME recvFrameQueue;
    void onQuicFrame(DATAFRAME& recvFrame)
    {
        auto recvPacketType = recvFrame.packetType();
        for (auto frame = recvFrameQueue; frame; frame = frame->next)
        {
            if (((recvPacketType == frame->packetType()) && (recvFrame.streamOffset <= frame->streamOffset)) ||
                (recvPacketType < frame->packetType()))
            {
                INSERT_DLINK(*frame, recvFrame);
                break;
            }
        }

        if (recvFrame.prev == nullptr) // not inserted into queue
        {
            APPEND_DLINK(&recvFrameQueue, recvFrame);
        }
    }

    void parseQUICframes()
    {
        FRAME_STREAM frameStream;
        frameStream.reserve(32);

        if (recvFrameQueue)
        {
            auto&& recvPacket = recvFrameQueue->packet;
            for (auto frame = recvFrameQueue; frame; frame = frame->next)
            {
                frameStream.append(frame);
            }

            auto frameList = frameStream.toRWBuffer();
            parseQUICframes(recvPacket, frameList);

            session.clearDataframeQueue(&recvFrameQueue);
        }
    }

    void parseQUICframes(QPACKET& recvPacket, MBUF_READER mbuf)
    {
        while (auto message = tryParseMessage(mbuf))
        {
            auto transcript = message;
            auto msgType = (MESSAGE_TYPE)message.readByte();
            message.shift(3);

            if (msgType == client_hello)
            {
                ASSERT(isServer);
                transcriptHash.addMessage(transcript);
                BUFFER sessionId;
                if (parseClientHello(message, sessionId))
                {
                    cryptoFrameOffset = 0;
                    auto&& initPacket = session.sendCryptoFrame(PACKET_INITIAL, cryptoFrameOffset,
                        [](BYTESTREAM& frameStream, TLS13_HANDSHAKE& handshake, BUFFER sessionId)
                        {
                            handshake.formatServerHello(frameStream, sessionId);
                        }, *this, sessionId);
                    session.sendPacket(initPacket, PACKET_INITIAL);

                    generateHandshakeKeys();
                    cryptoFrameOffset = 0;
                    auto&& handshakePacket = session.sendCryptoFrame(PACKET_HANDSHAKE, cryptoFrameOffset,
                        [](BYTESTREAM& frameStream, TLS13_HANDSHAKE& handshake, QPACKET& recvPacket)
                        {
                            handshake.formatEncryptedExtensions(frameStream, recvPacket);
                            handshake.formatCertificates(frameStream);
                            handshake.formatCertificateVerify(frameStream);
                            handshake.formatFinished(frameStream);

                        }, *this, recvPacket);
                    session.sendPacket(handshakePacket, PACKET_HANDSHAKE);

                    cryptoFrameOffset = 0;
                    generateMasterKeys(transcriptHash.getHash());
                }
            }
            else if (msgType == server_hello)
            {
                ASSERT(!isServer);
                parseServerHello(message);
                transcriptHash.addMessage(transcript);
                generateHandshakeKeys();
            }
            else if (msgType == encrypted_extensions)
            {
                parseEncryptedExtensions(message);
                transcriptHash.addMessage(transcript);
            }
            else if (msgType == certificate)
            {
                parseCertificates(message);
                transcriptHash.addMessage(transcript);
            }
            else if (msgType == certificate_verify)
            {
                parseCertificateVerify(message);
                transcriptHash.addMessage(transcript);
            }
            else if (msgType == finished)
            {
                if (parseFinished(message))
                {
                    if (!isServer)
                    {
                        transcriptHash.addMessage(transcript);
                        generateMasterKeys(transcriptHash.getHash());
                        auto&& sendPacket = session.sendCryptoFrame(PACKET_HANDSHAKE, cryptoFrameOffset,
                            [](BYTESTREAM& frameStream, TLS13_HANDSHAKE& handshake)
                            {
                                handshake.formatFinished(frameStream);
                            }, *this);
                        session.sendPacket(sendPacket, PACKET_HANDSHAKE);
                        cryptoFrameOffset = 0;
                    }
                }
                else DBGBREAK();
                session.onConnect(STATUS_SUCCESS);
            }
            else DBGBREAK();
        }
    }

    BUFFER parseMessage(BUFFER recvData)
    {
        BUFFER message;
        if (recvData.length() > 4)
        {
            auto msgStart = recvData.savePosition();
            auto msgType = recvData.readEnumBE<MESSAGE_TYPE>();
            auto length = recvData.readIntBE(3);

            if (recvData.length() >= length)
            {
                recvData.shift(length);
                message = recvData.diffPosition(msgStart);
            }
        }
        return message;
    }

    NTSTATUS sendFinished()
    {
        auto status = sendRecord(record_handshake, [](BYTESTREAM& recordStream, TLS13_HANDSHAKE& handshake)
            {
                handshake.formatFinished(recordStream);
            }, *this);
        return status;
    }

    UINT32 parseRecordCount = 0;
    BUFFER parseRecord(BUFFER record)
    {
        BUFFER userData;
        LogInfo("ParseRecord: ", parseRecordCount++);
        auto recordStart = record;

        auto recordType = record.readEnumBE<RECORD_TYPE>();
        record.readEnumBE<TLS_VERSION>();
        record.beReadU16(); // length

        if (recordType == record_handshake)
        {
            MESSAGE_TYPE msgType; BUFFER msgData;
            auto message = parseMessageHeader(record, msgType, msgData);

            if (msgType == client_hello)
            {
                ASSERT(isServer);
                transcriptHash.addMessage(message);
                if (isServer)
                {
                    BUFFER sessionId;
                    auto isValid = parseClientHello(msgData, sessionId);
                    if (isValid)
                    {
                        sendServerHello(sessionId);
                        generateHandshakeKeys();
                        sendRecord(record_handshake, [](BYTESTREAM& recordStream, TLS13_HANDSHAKE& handshake)
                            {
                                handshake.formatEncryptedExtensions(recordStream);
                                handshake.formatCertificates(recordStream);
                                handshake.formatCertificateVerify(recordStream);
                                handshake.formatFinished(recordStream);
                            }, *this);
                    }
                    else
                    {
                        DBGBREAK();
                        sendAlert(ALERT_LEVEL::fatal, ALERT_DESCRIPTION::illegal_parameter);
                    }
                }
            }
            else if (msgType == server_hello)
            {
                ASSERT(!isServer);
                transcriptHash.addMessage(message);
                parseServerHello(msgData);
                generateHandshakeKeys();
            }
            else DBGBREAK();
        }
        else if (recordType == record_application_data)
        {
            record = recordStart; // rewind
            record = cipher.decrypt(record.toRWBuffer());

            while (record && record.last() == 0)
                record.shrink(1);

            ASSERT(record.length() > 0);

            recordType = (RECORD_TYPE)record.last();
            record.shrink(1);

            if (recordType == record_handshake)
            {
                while (record.length() > 0)
                {
                    MESSAGE_TYPE msgType; BUFFER msgData;
                    auto message = parseMessageHeader(record, msgType, msgData);

                    if (msgType == encrypted_extensions)
                    {
                        parseEncryptedExtensions(msgData);
                        transcriptHash.addMessage(message);
                    }
                    else if (msgType == certificate)
                    {
                        parseCertificates(msgData);
                        transcriptHash.addMessage(message);
                    }
                    else if (msgType == certificate_verify)
                    {
                        parseCertificateVerify(msgData);
                        transcriptHash.addMessage(message);
                    }
                    else if (msgType == finished)
                    {
                        if (parseFinished(msgData))
                        {
                            if (isServer)
                            {
                                generateMasterKeys(transcriptHash.getHash());
                            }
                            else
                            {
                                transcriptHash.addMessage(message);
                                auto masterHash = transcriptHash.getHash();
                                sendFinished();
                                generateMasterKeys(masterHash);
                                session.onConnect(STATUS_SUCCESS);
                            }
                        }
                        else DBGBREAK();
                    }
                    else
                    {
                        DBGBREAK();
                    }
                }
            }
            else if (recordType == record_alert)
            {
                auto alertLevel = record.readEnumBE<ALERT_LEVEL>();
                auto alertDescription = record.readEnumBE<ALERT_DESCRIPTION>();
                LogInfo("Alert: ", (UINT32)alertLevel, " / ", (UINT32)alertDescription);
            }
            else if (recordType == record_change_cipher_spec)
            {
                LogInfo("Change Cipher Spec");
                // just ignore it.
            }
            else if (recordType == record_application_data)
            {
                userData = record;
            }
            else
            {
                DBGBREAK();
            }
        }
        return userData;
    }

    void generateHandshakeKeys()
    {
        cipher.generateHandshakeKeys(kdf, transcriptHash);
        session.generateHandshakeKeys(kdf, cipher.clientHandshakeSecret.toBuffer(), cipher.serverHandshakeSecret.toBuffer(), cipher.keySize);
    }

    void generateMasterKeys(BUFFER masterHash)
    {
        isHandshakeComplete = true;
        cipher.generateMasterKeys(kdf, masterHash);
        session.generateMasterKeys(kdf, cipher.clientMasterSecret.toBuffer(), cipher.serverMasterSecret.toBuffer(), cipher.keySize);
    }

    void updateMasterSecret(BUFFER label)
    {
        cipher.updateMasterKeys(kdf, label);
        session.updateMasterKeys(kdf, cipher.clientMasterSecret.toBuffer(), cipher.serverMasterSecret.toBuffer(), cipher.keySize);
    }

    void deriveTransportKeys(SERVICE& transport, U128 localNodeId, U128 remoteNodeId, U128 pathId)
    {
        ASSERT(isHandshakeComplete);
        HKDF transportKDF;
        kdf.copyTo(transportKDF);

        localNodeId.Xor(remoteNodeId);
        auto hashInput = WriteMany(localNodeId, pathId);

        SHA256_DATA clientSecret, serverSecret;
        HmacSha256(clientSecret, cipher.clientMasterSecret.toBuffer(), hashInput);
        HmacSha256(serverSecret, cipher.serverMasterSecret.toBuffer(), hashInput);

        transport.generateMasterKeys(transportKDF, clientSecret, masterSecret, cipher.keySize);
    }

    BUFFER recvBuf;
    void releaseRecvBuf()
    {
        recvStream.remove(0, recvBuf._start);
        onReceive();
    }

    BUFFER readRecord(BUFFER& recvData)
    {
        BUFFER record;
        if (recvData.length() > TLS_RECORD_HEADER)
        {
            auto bytesNeeded = getRecordLength(recvData);
            if (bytesNeeded <= recvData.length())
            {
                record = recvData.readBytes(bytesNeeded);
            }
        }
        return record;
    }

    void onReceive()
    {
        auto holdBuf = false;
        recvBuf = recvStream.toBuffer();
        while (auto record = readRecord(recvBuf)) //recvRecord.length() > TLS_RECORD_HEADER)
        {
            if (BUFFER userData = parseRecord(record))
            {
                if (holdBuf = session.onTLSreceive(userData))
                    break;
            }
        }

        if (!holdBuf)
        {
            recvStream.remove(0, recvBuf._start);
            session.beginReceive();
        }
    }

    void test()
    {
        HEXSTRING clientPrivateKey = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
        HEXSTRING clientPublicKey = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
        HEXSTRING clientHello = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece7000006130113031302010000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c00024001";

        HEXSTRING serverPrivateKey = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";
        HEXSTRING serverPublicKey = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
        HEXSTRING serverHello = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";

        cipher.keyShare.importPrivateKey(serverPrivateKey);
        X25519_KEY_DATA keyData;
        ASSERT(cipher.keyShare.getPublicKey(keyData) == serverPublicKey);

        setCipher(TLS_AES_128_GCM_SHA256);

        transcriptHash.addMessage(clientHello);
        transcriptHash.addMessage(serverHello);

        cipher.keyShare.createSecret(clientPublicKey);

        generateHandshakeKeys();
    }
};
