
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
#include "TLS.h"

//RFC8285 - RTP Header extensions
//RFC6184 - RTP payload for H.264
//RFC4566 - SDP
//RFC5764 SRTS and DTLS
//RFC6188 - AES_256_CM_PRF
//draft-ietf-mmusic-ice-sip-sdp-24
//draft-ietf-mmusic-sdp-bundle-negotiation-54.txt
//draft-ietf-rtcweb-jsep-26
//draft-ietf-rtcweb-sdp-11

// The only supported cipher is AES GCM 128.

constexpr UINT32 DTLS_RECORD_HEADER = 13;
constexpr UINT32 DTLS_RECORD_LENGTH_OFFSET = 11;
constexpr UINT32 MSG_HEADER = 6;

constexpr UINT32 AES_EXPLICIT_IV_LENGTH = 8;
constexpr UINT32 AES_IMPLICIT_IV_LENGTH = 4;

constexpr UINT32 SRTP_MASTER_SALT_LENGTH = AES_CTR_IV_LENGTH; // Should be 14 (salt length of SRTP KDF), Workaround google webrtc bug

constexpr UINT32 DTLS_DATA_MAX = 16 * 1024;

constexpr UINT32 DTLS_RECORD_SIZE = DTLS_DATA_MAX + CIPHER_EXPANSION_MAX + DTLS_RECORD_HEADER;

constexpr UINT32 SEQUENCE_NUMBER_OFFSET = 3;

constexpr UINT16 RTP_FLAGS_V = 0xC000;
constexpr UINT16 RTP_FLAGS_P = 0x2000;
constexpr UINT16 RTP_FLAGS_X = 0x1000;
constexpr UINT16 RTP_FLAGS_CC = 0x0F00;

constexpr UINT16 RTP_FLAGS_M = 0x0080;
constexpr UINT16 RTP_FLAGS_PT = 0x007F;

constexpr UINT8 RTP_FIXED_HEADER_SIZE = 12;
constexpr UINT16 RTPEXT_GENERAL = 0xBEDE;
constexpr UINT16 RTPEXT_LONG_GENERAL = 0x1000;

enum class SRTP_PRF_LABEL : UINT8
{
    rtp_encryption = 0x00,
    rtp_msg_auth = 0x01,
    rtp_salt = 0x02,
    rtcp_encryption = 0x03,
    rtcp_msg_auth = 0x04,
    rtcp_salt = 0x05,
    rtp_header_encryption = 0x06,
    rtp_header_salt = 0x07
};
using enum SRTP_PRF_LABEL;

struct RTP_FLAGS
{
    UINT16 value;

    RTP_FLAGS(UINT16 input) : value(input) {}
    RTP_FLAGS() : value(0x8000) {}

    UINT16 getCsrcCount() { return (value & RTP_FLAGS_CC) >> 8; }
    void setCsrcCount(UINT16 csrcCount) { value |= ((csrcCount & 0x0F) << 8); }

    UINT8 getPacketType() { return (UINT8)(value & 0x7F); }
    void setPaketType(UINT8 packetType) { value |= (packetType & 0x7F); }

    bool getPadding() { return value & RTP_FLAGS_P ? true : false; }
    void setPadding() { value |= RTP_FLAGS_P; }

    bool getMarker() { return value & RTP_FLAGS_M ? true : false; }
    void setMarker() { value |= RTP_FLAGS_M; }

    bool getExtension() { return value & RTP_FLAGS_X ? true : false; }
    void setExtension() { value |= RTP_FLAGS_X; }
};

struct RTCP_FLAGS
{
    UINT16 value;
    RTCP_FLAGS(UINT16 input) : value(input) {}
    RTCP_FLAGS() : value(0x8000) {}

    UINT16 getRecordCount() { return (value & 0x1F00) >> 8; }
    void setRecordCount(UINT16 count) { value |= ((count & 0x1F) << 8); }

    UINT8 getPacketType() { return (UINT8)(value & 0xFF); }
    void setPacketType(UINT16 type) { value |= (type & 0xFF); }

    bool getPadding() { return value & 0x2000 ? true : false; };
    void setPadding() { value |= 0x2000; }
};

constexpr UINT32 POPULATE_PACKETS_TIMER_INTERVAL = 5000;

constexpr UINT32 DTLS_MESSAGE_HEADER = 12;
constexpr UINT32 DTLS_FRAGMENT_OVERHEAD = 8;
constexpr UINT32 DTLS_PMTU = 1450;

constexpr auto stunServerName = "stun.l.google.com";
constexpr auto stunServerPort = 19302;

enum class STUN_MESSAGE : UINT16
{
    BINDING_REQUEST = 0x0001,
    BINDING_SUCCESS = 0x0101,
    BINDING_FAILURE = 0x0111,
};
using enum STUN_MESSAGE;

constexpr UINT16 STUN_ATTR_OPTIONAL = 0x8000;
constexpr UINT32 STUN_FINGERPRINT_MAGIC = 0x5354554e;
constexpr UINT32 STUN_MESSAGE_INTEGRITY_SIZE = 24; // includes attribute header
constexpr UINT32 STUN_HEADER_SIZE = 20;
constexpr UINT32 STUN_MAGIC = 0x2112A442;
constexpr UINT32 STUN_ATTR_HEADER = 4;
constexpr UINT32 STUN_FINGERPRINT_LENGTH = 4;

enum class STUN_ATTR : UINT16
{
    MAPPED_ADDRESS = 0x0001,
    USERNAME = 0x0006,
    MESSAGE_INTEGRITY = 0x0008,
    ERROR_CODE = 0x0009,
    UNKNOWN_ATTR = 0x000A,
    REALM = 0x0014,
    NONCE = 0x0015,
    XOR_MAPPED_ADDRESS = 0x0020,
    PRIORITY = 0x0024,
    USE_CANDIDATE = 0x0025,
    ICE_CONTROLLED = 0x0026,
    ICE_CONTROLLING = 0x0027,
    MESSAGE_INTEGRITY_SHA_256 = 0x001C,
    PASSWORD_ALGORITHM = 0x001D,
    USERHASH = 0x001E,

    SOFTWARE = 0x8022,
    ALTERNATE_SERVER = 0x8023,
    FINGERPRINT = 0x8028,
};
using enum STUN_ATTR;

constexpr UINT8 H264_PAYLOAD_1 = 1;
constexpr UINT8 H264_PAYLOAD_23 = 23;
constexpr UINT8 H264_PAYLOAD_STAP_A = 24;
constexpr UINT8 H264_PAYLOAD_STAP_B = 25;
constexpr UINT8 H264_PAYLOAD_MTAP16 = 26;
constexpr UINT8 H264_PAYLOAD_MTAP24 = 27;
constexpr UINT8 H264_PAYLOAD_FU_A = 28;
constexpr UINT8 H264_PAYLOAD_FU_B = 29;

constexpr UINT8 H264_FU_S = 0x80;
constexpr UINT8 H264_FU_E = 0x40;

constexpr UINT32 SRTP_MAX_PAYLOAD = 1430;
constexpr UINT32 SRTP_MAX_DATA = 1524;

using SRTP_DATASTREAM = LOCAL_STREAM<SRTP_MAX_DATA>;

struct SRTP_PACKET
{
    SRTP_PACKET* nextFree;
    SRTP_DATASTREAM dataStream;

    static SRTP_PACKET* freeList;

    static SRTP_PACKET& alloc()
    {
        SRTP_PACKET* allocPacket = nullptr;
        while (freeList)
        {
            auto packet = freeList;
            auto next = freeList->nextFree;
            if (InterlockedCompareExchangePointer((volatile PVOID*)&freeList, next, packet) == packet)
            {
                allocPacket = packet;
                break;
            }
        }

        if (allocPacket == nullptr)
        {
            allocPacket = &MemAlloc<SRTP_PACKET>();
        }

        return *allocPacket;
    }

    static void free(SRTP_PACKET* packet)
    {
        for (;;)
        {
            auto next = freeList;
            packet->nextFree = next;
            if (InterlockedCompareExchangePointer((volatile PVOID*)&freeList, packet, next) == next)
                break;
        }
    }
};

template <typename T, UINT32 SIZE>
struct QUEUE
{
    DATASTREAM<T, SESSION_STACK> dataStream;
    UINT32 size = SIZE;
    UINT32 readIndex = 0, writeIndex = 0;

    void initialize()
    {
        dataStream.reserve(size);
    }

    void write(T item)
    {
        auto nextWrite = (writeIndex + 1) & (size - 1);
        if (nextWrite == readIndex)
        {
            size *= 2;
            dataStream.reserve(size);
            nextWrite = (writeIndex + 1) & (size - 1);
        }

        dataStream.at(writeIndex) = item;
        writeIndex = nextWrite;
    }

    T read()
    {
        if (readIndex == writeIndex)
            return nullptr;

        auto nextRead = (readIndex + 1) & (size - 1);
        auto value = dataStream.at(readIndex);
        readIndex = nextRead;
        return value;
    }

    constexpr explicit operator bool() const { return readIndex != writeIndex; }
};

template <typename SERVICE>
struct WEBRTC_SESSION
{
    struct UDP_TRANSPORT
    {
        WEBRTC_SESSION& session;

        IOCALLBACK ioState{ IO_SOCK_RECV };
        BYTESTREAM recvStream;

        SOCKET socketHandle;
        IPENDPOINT localAddress;
        IPENDPOINT iceCandidate;
        IPENDPOINT remoteAddress;

        IPENDPOINT recvFromAddress;

        UDP_TRANSPORT(WEBRTC_SESSION& session) : session(session) {}

        bool initialize(const IPENDPOINT& ipInterface)
        {
            auto status = false;
            do
            {
                socketHandle = session.createSocket();
                if (socketHandle == INVALID_SOCKET)
                    break;

                localAddress = ipInterface;

                auto result = bind(socketHandle, localAddress.addressC(), sizeof(localAddress));
                if (result == SOCKET_ERROR) { DBGBREAK(); break; }

                int addrLen = sizeof(localAddress);
                result = getsockname(socketHandle, localAddress.addressC(), &addrLen);
                if (result == SOCKET_ERROR) { DBGBREAK(); break; }

                recvStream.allocReserve<SESSION_STACK>(1500);

                session.createTask(ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
                    {
                        auto&& session = *(WEBRTC_SESSION*)context;
                        auto&& transport = *(UDP_TRANSPORT*)argv.read<PVOID>(0);
                        auto bytesTransferred = argv.read<DWORD>(1);
                        transport.recvStream.setCount(bytesTransferred);

                        session.onReceiveFrom(transport, transport.recvStream.toBuffer(), transport.recvFromAddress);
                        transport.beginReceive();
                    }, this);

                beginReceive();

                status = true;
            } while (false);
            return status;
        }

        void beginReceive()
        {
            auto status = SocketRecvFrom(socketHandle, recvFromAddress, ioState, recvStream.clear());
            if (!NT_SUCCESS(status))
            {
                DebugBreak();
                session.onSocketClose();
            }
        }

        void close()
        {
            if (socketHandle != INVALID_SOCKET)
            {
                closesocket(socketHandle);
                socketHandle = INVALID_SOCKET;
            }
        }

        void sendTo(BUFFER sendData, IPENDPOINT& toAddress)
        {
            SocketSendTo(socketHandle, toAddress, sendData);
        }

        void sendTo(BUFFER sendData)
        {
            sendTo(sendData, remoteAddress);
        }

        bool match(const IPENDPOINT& matchAddress) const
        {
            return matchAddress == localAddress;
        }

        explicit operator bool() const { return IsValidRef(*this) && bool(localAddress); }
    };

    struct SRTP_SHAPER
    {
        QUEUE<SRTP_PACKET*, 512> transmitQueue;

        CLOCK playClock;
        UINT32 populatePacketsDuration = 5000; // ms

        WEBRTC_SESSION& session;

        SRTP_SHAPER(WEBRTC_SESSION& sessionArg) : session(sessionArg)
        {
        }

        void start()
        {
            playClock.reset();
        }

        void populatePackets()
        {
            auto startTime = (playClock.elapsedTime() / 1000) * 1000; // convert to seconds first (ignore milliseconds), then to ms
            UNREFERENCED_PARAMETER(startTime);
        }

        void sendPackets()
        {
            auto packet = transmitQueue.read();
            session.getActiveTransport().sendTo(packet->dataStream.toBuffer());
            SRTP_PACKET::free(packet);
        }

        template <typename FUNC, typename ... ARGS>
        void sendPacket(FUNC callback, ARGS&& ... args)
        {
            auto&& packet = SRTP_PACKET::alloc();
            callback(packet.dataStream, args ...);

            transmitQueue.write(&packet);
        }
    };

    DATASTREAM<UDP_TRANSPORT, SESSION_STACK> networkTransports;

    UDP_TRANSPORT& getActiveTransport()
    {
        for (UINT32 i = 0; i < networkTransports.count(); i++)
        {
            if (networkTransports.at(i).socketHandle != INVALID_SOCKET)
                return networkTransports.at(i);
        }
        DBGBREAK();
        return NullRef<UDP_TRANSPORT>();
    }

    struct SRTP_CIPHER
    {
        SRTP_PROTECTION_PROFILE cipher = SRTP_AEAD_AES_128_GCM;

        AES_GCM recvRTPkey;
        AES_GCM recvRTCPkey;

        AES_GCM sendRTPkey;
        AES_GCM sendRTCPkey;

        UINT16 lastRecvSeqNumber = 0;
        UINT32 recvROC = 0;

        UINT16 sendSeqNumber;
        UINT32 sendROC = 0; // roll over counter, incremented on seq number rollover.

        LOCAL_STREAM<1500> rtpSendStream;
        LOCAL_STREAM<1500> rtcpSendStream;

        SRTP_CIPHER()
        {
            Random.getBytes(BYTESTREAM((PUINT8)&sendSeqNumber, sizeof(UINT16)));
            sendSeqNumber &= 0xFFF;
        }

        UINT32 getKeyLength()
        {
            UINT32 keyLength = 0;
            if (cipher == SRTP_AEAD_AES_128_GCM || cipher == SRTP_AES128_CM_HMAC_SHA1_80)
            {
                keyLength = AES128_KEY_LENGTH;
            }
            else if (cipher == SRTP_AEAD_AES_256_GCM)
            {
                keyLength = AES256_KEY_LENGTH;
            }
            else DBGBREAK();
            return keyLength;
        }

        UINT32 getSaltLength()
        {
            UINT32 saltLength = 0;
            if (cipher == SRTP_AEAD_AES_128_GCM || cipher == SRTP_AEAD_AES_256_GCM)
            {
                saltLength = AES_GCM_IV_LENGTH;
            }
            else if (cipher == SRTP_AES128_CM_HMAC_SHA1_80)
            {
                saltLength = AES_CTR_IV_LENGTH;
            }
            else DBGBREAK();
            return saltLength;
        }

        UINT32 getAuthKeyLength()
        {
            UINT32 authKeyLength = 0;
            if (cipher == SRTP_AES128_CM_HMAC_SHA1_80)
            {
                authKeyLength = 20;
            }
            return authKeyLength;
        }

        UINT16 getNextSendSeqNumber()
        {
            if (sendSeqNumber == MAXUINT16)
            {
                sendROC++;
                sendSeqNumber = 0;
            }
            else
            {
                sendSeqNumber++;
            }
            return sendSeqNumber;
        }

        BUFFER decryptRTP(RWBUFFER recvData, BUFFER authData, UINT32 ssrc, UINT16 receivedSeqNumber)
        {
            if (receivedSeqNumber == 0)
            {
                ASSERT(lastRecvSeqNumber == MAXUINT16);
                recvROC++;
            }

            lastRecvSeqNumber = receivedSeqNumber;

            AES_GCM_IV iv;
            BYTESTREAM ivStream = iv;
            ivStream.beWriteU16(0);
            ivStream.beWriteU32(ssrc);
            ivStream.beWriteU32(recvROC);
            ivStream.beWriteU16(receivedSeqNumber);

            return recvRTPkey.decrypt(iv, authData, recvData);
        }

        BUFFER decryptRTCP(RWBUFFER recvData, BUFFER authData, UINT32 ssrc, UINT32 receivedSeqNumber)
        {
            AES_GCM_IV iv;
            BYTESTREAM ivStream = iv;
            ivStream.beWriteU16(0);
            ivStream.beWriteU32(ssrc);
            ivStream.beWriteU16(0);
            ivStream.beWriteU32(receivedSeqNumber);

            return recvRTCPkey.decrypt(iv, authData, recvData);
        }

        void encryptRTP(SRTP_DATASTREAM& rtpStream, BUFFER authData, RWBUFFER payloadData, UINT32 ssrc)
        {
            auto seqNumber = getNextSendSeqNumber();

            AES_GCM_IV iv;
            BYTESTREAM ivStream = iv;
            ivStream.beWriteU16(0);
            ivStream.beWriteU32(ssrc);
            ivStream.beWriteU32(sendROC);
            ivStream.beWriteU16(seqNumber);

            auto&& tag = *(U128*)rtpStream.commit(U128_BYTES);
            sendRTPkey.encrypt(iv, authData, payloadData, tag);
        }

        template <typename F, typename ... ARGS>
        BUFFER formatRTP(UINT8 packetType, bool isKeyFrame, UINT32 timestamp, UINT32 ssrc, F func, ARGS&& ... args)
        {
            return formatRTP(packetType, isKeyFrame, timestamp, ssrc, NULL_BUFFER, NULL_BUFFER, 0, func, args ...);
        }
    };

    struct DTLS_CIPHER
    {
        WEBRTC_SESSION& session;

        UINT64 sendEpoch = 0;
        UINT64 _sendSequenceNumber = 0;

        UINT64 recvEpoch = 0;
        UINT64 _recvSequenceNumber = 0;

        CIPHER_SUITE cipherSuite = TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;

        AES_GCM sendKey;
        AES_GCM recvKey;

        UINT8 masterSecret[MASTER_SECRET_LENGTH];

        UINT8 serverRandom[PRF_RANDOM_LENGTH];
        UINT8 clientRandom[PRF_RANDOM_LENGTH];

        bool sendEncrypted = false;
        bool recvEncrypted = false;

        DTLS_CIPHER(WEBRTC_SESSION& session) : session(session) {}

        UINT32 getKeyLength() { return cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 ? AES128_KEY_LENGTH : AES256_KEY_LENGTH; }

        UINT64 claimSendSeqNumber()
        {
            auto seqNumber = (sendEpoch << 48) | (_sendSequenceNumber & 0xFFFFFFFFFF);
            _sendSequenceNumber++;
            return seqNumber;
        }

        UINT64 nextRecvSeqNumber()
        {
            return (recvEpoch << 48) | (_recvSequenceNumber & 0xFFFFFFFFFF);
        }

        void claimRecvSeqNumber()
        {
            _recvSequenceNumber++;
        }

        void writeExplicitIV(BYTESTREAM& buffer)
        {
            if (sendEncrypted)
            {
                buffer.beWriteU64(_sendSequenceNumber);
            }
        }

        void writeGCMtag(BYTESTREAM& buffer)
        {
            if (sendEncrypted)
            {
                buffer.commit(AES_TAG_LENGTH);
            }
        }

        BUFFER PRF(USTRING label, BUFFER seed, BYTESTREAM prfOutput)
        {
            auto A_Buffer = HmacSha256(ByteStream(PRF_HASH_LENGTH), masterSecret, label, seed);

            while (prfOutput.spaceLeft())
            {
                UINT8 hashOutput[PRF_HASH_LENGTH];
                HmacSha256(hashOutput, A_Buffer, label, seed);

                prfOutput.writeBytes(hashOutput, min(PRF_HASH_LENGTH, prfOutput.spaceLeft()));

                A_Buffer = HmacSha256(ByteStream(PRF_HASH_LENGTH), masterSecret, A_Buffer);
            }
            return prfOutput.toBuffer();
        }

        BUFFER SRTP_PRF(AES_CTR& cipher, SRTP_PRF_LABEL label, BYTESTREAM prfOutput)
        {
            U128 iv;
            iv.u8[7] = UINT8(label);

            RWBUFFER data{ prfOutput.address(), prfOutput.size() };
            cipher.encrypt(iv, data);
            return data.toBuffer();
        }

        void testSRTPkeys()
        {
            HEXSTRING keyData =  "E1F97A0D3E018BE0D64FA32C06DE4139";
            AES_CTR encryptKey;
            encryptKey.setKey(keyData);

            HEXSTRING saltData = "0EC675AD498AFEEBB6960B3AABE6";
            U128 data{ saltData };

            U128 label;
            label.u8[7] = 0;

            XorData(data, label);
            U128 salt;
            encryptKey.encrypt(salt, data);
        }

        void extractSRTPkeys(SRTP_CIPHER& srtpCipher)
        {
            ASSERT(session.isServer);

            do
            {
                auto seed = ByteStream(PRF_SEED_LENGTH).writeMany(clientRandom, serverRandom);

                auto keyLength = srtpCipher.getKeyLength();
                auto saltLength = srtpCipher.getSaltLength();
                auto authKeyLength = srtpCipher.getAuthKeyLength();

                LOCAL_STREAM<128> hashOutput;
                auto extractCount = 2 * keyLength + 2 * SRTP_MASTER_SALT_LENGTH;
                auto prfOutput = PRF("EXTRACTOR-dtls_srtp", seed, ByteStream(extractCount));

                AES_CTR recvSeed, sendSeed;
                if (session.isServer)
                {
                    recvSeed.setKey(prfOutput.readBytes(keyLength));
                    sendSeed.setKey(prfOutput.readBytes(keyLength));

                    recvSeed.setSalt(prfOutput.readBytes(SRTP_MASTER_SALT_LENGTH));
                    sendSeed.setSalt(prfOutput.readBytes(SRTP_MASTER_SALT_LENGTH));
                }
                else
                {
                    sendSeed.setKey(prfOutput.readBytes(keyLength));
                    recvSeed.setKey(prfOutput.readBytes(keyLength));

                    sendSeed.setSalt(prfOutput.readBytes(SRTP_MASTER_SALT_LENGTH));
                    recvSeed.setSalt(prfOutput.readBytes(SRTP_MASTER_SALT_LENGTH));
                }

                {
                    auto keyData = SRTP_PRF(recvSeed, rtp_encryption, ByteStream(keyLength));
                    srtpCipher.recvRTPkey.setKey(keyData);
                    SRTP_PRF(recvSeed, rtp_salt, srtpCipher.recvRTPkey.salt);

                    keyData = SRTP_PRF(recvSeed, rtcp_encryption, ByteStream(keyLength));
                    srtpCipher.recvRTCPkey.setKey(keyData);
                    SRTP_PRF(recvSeed, rtcp_salt, srtpCipher.recvRTCPkey.salt);
                }
                {
                    auto keyData = SRTP_PRF(sendSeed, rtp_encryption, ByteStream(keyLength));
                    srtpCipher.sendRTPkey.setKey(keyData);
                    SRTP_PRF(sendSeed, rtp_salt, srtpCipher.sendRTPkey.salt);

                    keyData = SRTP_PRF(sendSeed, rtcp_encryption, ByteStream(keyLength));
                    srtpCipher.sendRTCPkey.setKey(keyData);
                    SRTP_PRF(sendSeed, rtcp_salt, srtpCipher.sendRTCPkey.salt);
                }
            } while (false);
        }

        void generateTrafficKeys()
        {
            do
            {
                auto seed = ByteStream(PRF_SEED_LENGTH).writeMany(clientRandom, serverRandom);

                auto keyLength = getKeyLength();
                auto bytesNeeded = 2 * keyLength + 2 * AES_IMPLICIT_IV_LENGTH;
                auto hash = PRF("key expansion", seed.toBuffer(), ByteStream(bytesNeeded));

                session.isServer ? recvKey.setKey(hash.readBytes(keyLength)) : sendKey.setKey(hash.readBytes(keyLength));
                session.isServer ? sendKey.setKey(hash.readBytes(keyLength)) : recvKey.setKey(hash.readBytes(keyLength));

                BYTESTREAM(session.isServer ? recvKey.salt : sendKey.salt).writeBytes(hash.readBytes(AES_IMPLICIT_IV_LENGTH));
                BYTESTREAM(session.isServer ? sendKey.salt : recvKey.salt).writeBytes(hash.readBytes(AES_IMPLICIT_IV_LENGTH));

            } while (false);
        }

        void generateMasterSecret(BUFFER sharedSecret)
        {
            auto seed = ByteStream(PRF_SEED_LENGTH).writeMany(clientRandom, serverRandom);

            BYTESTREAM(masterSecret).writeBytes(sharedSecret); // use sharedSecret as preMasterSecret
            auto newSecret = PRF("master secret", seed.toBuffer(), ByteStream(MASTER_SECRET_LENGTH));

            BYTESTREAM(masterSecret).writeBytes(newSecret);
        }

        void encrypt(BUFFER record)
        {
            if (!sendEncrypted)
                return;

            auto recordHeader = record.readBytes(DTLS_RECORD_HEADER);
            auto recordType = recordHeader.readByte();
            auto recordVersion = recordHeader.readEnumBE<TLS_VERSION>();
            auto recordSequenceNumber = recordHeader.readBytes(8);
            auto recordLength = recordHeader.beReadU16();

            AES_GCM_IV ivData;
            BYTESTREAM ivStream{ ivData };
            ivStream.beWriteU32(0);
            ivStream.writeBytes(record.readBytes(AES_EXPLICIT_IV_LENGTH));

            auto&& tag = *(U128 *) record.shrink(AES_TAG_LENGTH).data();

            LOCAL_STREAM<DTLS_RECORD_HEADER> additionalData;
            additionalData.writeBytes(recordSequenceNumber);
            additionalData.writeByte(recordType);
            additionalData.writeEnumBE(recordVersion);
            additionalData.beWriteU16(recordLength - AES_TAG_LENGTH - AES_EXPLICIT_IV_LENGTH);

            sendKey.encrypt(additionalData.toBuffer(), record.toRWBuffer(), tag);
        }

        BUFFER decrypt(BUFFER record)
        {
            auto recordHeader = record.readBytes(DTLS_RECORD_HEADER);
            if (recvEncrypted)
            {
                auto recordType = recordHeader.readByte();
                auto recordVersion = recordHeader.readEnumBE<TLS_VERSION>();
                auto recordSequenceNumber = recordHeader.readBytes(8);
                auto recordLength = recordHeader.beReadU16();

                auto tag = record.shrink(AES_TAG_LENGTH);

                AES_GCM_IV ivData;
                BYTESTREAM ivStream{ ivData };
                ivStream.beWriteU32(0);
                ivStream.writeBytes(record.readBytes(AES_EXPLICIT_IV_LENGTH));

                LOCAL_STREAM<DTLS_RECORD_HEADER> additionalData;
                additionalData.writeBytes(recordSequenceNumber);
                additionalData.writeByte(recordType);
                additionalData.writeEnumBE(recordVersion);
                additionalData.beWriteU16(recordLength - AES_TAG_LENGTH - AES_EXPLICIT_IV_LENGTH);

                record = recvKey.decrypt(ivData, additionalData.toBuffer(), record.toRWBuffer(), tag);
            }
            return record;
        }
    };

    struct DTLS_HANDSHAKE
    {
        DTLS_CIPHER cipher;
        UINT16 sendMsgSeqNumber = 0;
        UINT16 recvMsgSeqNumber = 0;
        TRANSCRIPT_HASH transcriptHash;
        ECDH_KEYSHARE keyShare;

        UINT64 retransmitTime;

        BYTESTREAM sendRecordStream;
        BYTESTREAM recvRecordStream;

        //DATASTREAM<CERTIFICATE<SESSION_STACK>, SESSION_STACK> peerCertificates;
        BUFFER peerPublicKey;
        WEBRTC_SESSION& session;
        DTLS_HANDSHAKE(WEBRTC_SESSION& session) : session(session), cipher(session)
        {
            transcriptHash.init(SHA256_HASH_LENGTH);
            retransmitTime = 10000 * 5000 * 10000000ull;
        }

        UDP_TRANSPORT* retransmitSocket;
        IPENDPOINT retransmitAddress;

        void startRetransmitTimer(UDP_TRANSPORT& socket, IPENDPOINT toAddress)
        {
            retransmitSocket = &socket;
            retransmitAddress = toAddress;
        }

        void stopRetransmitTimer()
        {
        }

        void retransmit()
        {
            retransmitSocket->sendTo(sendRecordStream.toBuffer());
        }

        template <typename FUNC, typename ... Args>
        void formatRecord(BYTESTREAM& outStream, RECORD_TYPE recordType, MESSAGE_TYPE msgType, FUNC func, Args&& ... args)
        {
            auto recordStart = outStream.getPosition();

            outStream.writeEnumBE(recordType);
            outStream.writeEnumBE(VER_DTLS12);
            outStream.beWriteU64(cipher.claimSendSeqNumber());

            {
                auto recordLength = outStream.saveOffset(2);
                cipher.writeExplicitIV(outStream);
                if (recordType == record_handshake)
                {
                    auto messageOffset = outStream.getPosition();

                    ASSERT(msgType != MESSAGE_TYPE::unknown);

                    outStream.writeEnumBE(msgType);
                    {
                        auto msgLength = outStream.saveOffset(3);
                        outStream.beWriteU16(sendMsgSeqNumber++);
                        outStream.writeBytes(ZeroBytes, 3); // frame offset
                        {
                            auto fragmentOffset = outStream.saveOffset(3);
                            func(outStream, args ...);
                            fragmentOffset.writeLength();
                        }
                        msgLength.writeLength(-1 * (INT32)DTLS_FRAGMENT_OVERHEAD); // msgLength doesn't include fragment info
                    }

                    transcriptHash.addMessage(messageOffset.toBuffer());
                }
                else
                {
                    func(outStream, args ...);
                }
                cipher.writeGCMtag(outStream);
                recordLength.writeLength();
            }

            if (recordStart.getLength() > DTLS_PMTU)
            {
                DBGBREAK(); // fragments!!! There shouldn't be fragments, make sure certificate(s) not too big
            }
            auto dataBuffer = recordStart.toBuffer();
            cipher.encrypt(dataBuffer);
        }

        void formatServerName(BYTESTREAM& buffer)
        {
            buffer.writeEnumBE(ext_server_name);
            {
                auto extLength = buffer.saveOffset(2);
                {
                    auto nameListLength = buffer.saveOffset(2);
                    buffer.writeByte(0); // type
                    {
                        auto nameLength = buffer.saveOffset(2);
                        buffer.writeName(SystemService().hostname); // HttpConfig.serverHostname); // session.service.getServerName());
                    }
                }
            }
        }

        void formatUseSrtp(BYTESTREAM& outStream)
        {
            outStream.writeEnumBE(ext_use_srtp);
            {
                auto extLength = outStream.saveOffset(2);
                {
                    {
                        auto profileLength = outStream.saveOffset(2);
                        outStream.writeEnumBE(SRTP_AEAD_AES_128_GCM);
                    }
                    outStream.writeByte(0); // for MKI, 
                }
            }
        }

        void formatSupportedGroups(BYTESTREAM& outStream)
        {
            outStream.writeEnumBE(ext_supported_groups);
            auto extLength = outStream.saveOffset(2);
            {
                auto groupLength = outStream.saveOffset(2);
                outStream.writeEnumBE(secp256r1);
            }
        }

        void formatECPointFormats(BYTESTREAM& outStream)
        {
            outStream.writeEnumBE(ext_ec_point_formats);
            auto extLength = outStream.saveOffset(2);
            {
                outStream.writeByte(0x01);
                outStream.writeByte(0);
            }
        }

        void formatSignatureAlgorithms(BYTESTREAM& outStream)
        {
            outStream.writeEnumBE(ext_signature_algorithms);
            auto extLength = outStream.saveOffset(2);
            {
                auto algLength = outStream.saveOffset(2);

                outStream.writeEnumBE(rsa_pss_rsae_sha256);
                outStream.writeEnumBE(rsa_pss_pss_sha256);
                outStream.writeEnumBE(rsa_pss_rsae_sha512);
                outStream.writeEnumBE(rsa_pss_pss_sha512);
                outStream.writeEnumBE(ecdsa_secp256r1_sha256);
                outStream.writeEnumBE(ecdsa_secp521r1_sha512);
            }
        }

        void formatClientHello(BYTESTREAM& msgStream, BUFFER cookie)
        {
            msgStream.writeEnumBE(VER_DTLS12);

            BYTESTREAM random{ cipher.clientRandom };
            random.beWriteU32(GetUnixTime());
            Random.getBytes(std::move(random));
            msgStream.writeBytes(cipher.clientRandom);

            msgStream.writeByte(0); // session id

            msgStream.writeByte((UINT8)cookie.length());
            msgStream.writeBytes(cookie);

            msgStream.beWriteU16(2);
            msgStream.writeEnumBE(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);

            msgStream.writeByte(1);
            msgStream.writeByte(0);
            {
                auto extensionOffset = msgStream.saveOffset(2);
                formatServerName(msgStream);
                formatECPointFormats(msgStream);
                formatSupportedGroups(msgStream);
                formatSignatureAlgorithms(msgStream);
                formatUseSrtp(msgStream);
            }
        }

        void formatServerHelloInternal(BYTESTREAM& msgStream, BUFFER sessionId)
        {
            msgStream.writeEnumBE(VER_DTLS12);

            BYTESTREAM random{ cipher.serverRandom };
            random.beWriteU32(GetUnixTime());
            Random.getBytes(std::move(random));
            msgStream.writeBytes(cipher.serverRandom);

            msgStream.writeByte((UINT8)sessionId.length());
            msgStream.writeBytes(sessionId);

            msgStream.writeEnumBE(TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
            msgStream.writeByte(0);
            {
                auto extensionLength = msgStream.saveOffset(2);
                formatECPointFormats(msgStream);
                formatUseSrtp(msgStream);
            }
        }

        void formatCertificatesInternal(BYTESTREAM& msgStream)
        {
            auto allCertsLength = msgStream.saveOffset(3);
            {
                auto certLength = msgStream.saveOffset(3);
                msgStream.writeBytes(SystemService().AKsignKey.certBytes); // HttpConfig.tlsCertData); // session.service.getCertificateBytes());
            }
        }

        void formatCertificateRequestInternal(BYTESTREAM& msgStream)
        {
            {
                auto typeLength = msgStream.saveOffset(1);
                msgStream.writeEnumBE(cert_ecdsa_sign);
                msgStream.writeEnumBE(cert_rsa_sign);
            }
            {
                auto algLength = msgStream.saveOffset(2);
                msgStream.writeEnumBE(ecdsa_secp256r1_sha256);
                msgStream.writeEnumBE(rsa_pss_rsae_sha256);
                msgStream.writeEnumBE(rsa_pkcs1_sha256);
            }
            msgStream.beWriteU16(0); // no CAs requested.
        }

        void formatCertificateVerify(BYTESTREAM& msgStream)
        {
            msgStream.writeEnumBE(ecdsa_secp256r1_sha256);

            ECDSA_DATA signData;
            ecdsa_sign(HttpConfig.tlsCertPrivateKey, transcriptHash.getHash(), signData);

            UINT8 asnSigData[128];
            FormatECDSAP256Signature(asnSigData, signData);
            {
                auto signatureLength = msgStream.saveOffset(2);
                msgStream.writeBytes(asnSigData);
                signatureLength.writeLength();
            }
        }

        void formatServerKeyExchangeInternal(BYTESTREAM& msgStream)
        {
            auto msgStart = msgStream.getPosition();

            msgStream.writeEnumBE(named_curve);
            msgStream.writeEnumBE(secp256r1);

            keyShare.initialize(secp256r1);
            {
                auto keyLength = msgStream.saveOffset(1);
                keyShare.getPublicKey(msgStream);
            }

            auto hashInput = msgStart.toBuffer();

            msgStream.writeEnumBE(ecdsa_secp256r1_sha256);

            SHA256_DATA hashOutput;
            HashSha(hashOutput, cipher.clientRandom, cipher.serverRandom, hashInput);

            ECDSA_DATA sigData;
            //TPM.sign(SystemService().AKhandle, hashOutput, sigData);
            SystemService().AKsignKey.signHash(hashOutput, sigData);
            //ecdsa_sign(HttpConfig.tlsCertPrivateKey, hashOutput, sigData);

            UINT8 asnSigData[128];
            BYTESTREAM sigStream{ asnSigData };
            X509.FormatECDSAP256Signature(sigStream, sigData);
            auto sigLength = msgStream.saveOffset(2);
            msgStream.writeBytes(sigStream.toBuffer());
            sigLength.writeLength();
        }

        NTSTATUS formatChangeCipherSpec(BYTESTREAM& outStream)
        {
            outStream.writeEnumBE(record_change_cipher_spec);
            outStream.writeEnumBE(VER_DTLS12);
            outStream.beWriteU64(cipher.claimSendSeqNumber());
            {
                auto recordLength = outStream.saveOffset(2);
                outStream.writeByte(0x01);
            }

            cipher._sendSequenceNumber = 0;
            cipher.sendEpoch++;

            cipher.sendEncrypted = true;

            return STATUS_SUCCESS;
        }

        void sendClientHello(UDP_TRANSPORT& socket, IPENDPOINT& toAddress, BUFFER cookie = NULL_BUFFER)
        {
            auto& outStream = sendRecordStream.clear();
            formatRecord(outStream, record_handshake, MESSAGE_TYPE::client_hello, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake, BUFFER cookie)
                {
                    handshake.formatClientHello(msgBuffer, cookie);
                    return 0;
                }, *this, cookie);

            socket.sendTo(outStream.toBuffer(), toAddress);
        }

        void formatClientKeyExchange(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::client_key_exchange, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    auto msgLength = msgBuffer.saveOffset(1);
                    handshake.keyShare.getPublicKey(msgBuffer);
                }, *this);
        }

        void formatServerHello(BYTESTREAM& dataStream, BUFFER sessionId)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::server_hello, [](BYTESTREAM& msgBuffer,
                DTLS_HANDSHAKE& handshake, BUFFER sessionId)
                {
                    handshake.formatServerHelloInternal(msgBuffer, sessionId);
                    return 0;
                }, *this, sessionId);
        }

        void formatCertificates(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::certificate, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    handshake.formatCertificatesInternal(msgBuffer);
                    return 0;
                }, *this);
        }

        void formatCertificateRequest(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::certificate_request, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    handshake.formatCertificateRequestInternal(msgBuffer);
                    return 0;
                }, *this);
        }

        void formatServerKeyExchange(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::server_key_exchange, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    handshake.formatServerKeyExchangeInternal(msgBuffer);
                    return 0;
                }, *this);
        }

        void formatServerHelloDone(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::server_hello_done, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    UNREFERENCED_PARAMETER(handshake);
                    UNREFERENCED_PARAMETER(msgBuffer);
                }, *this);
        }

        void sendAlert(ALERT_DESCRIPTION code, UDP_TRANSPORT& socket, IPENDPOINT& toAddress)
        {
            LogInfo("Sending alert ", UINT32(code));
            auto& dataStream = sendRecordStream.clear();
            formatRecord(dataStream, record_alert, MESSAGE_TYPE::unknown, [](BYTESTREAM& msgBuffer, ALERT_DESCRIPTION code)
                {
                    msgBuffer.writeEnumBE(ALERT_LEVEL::fatal);
                    msgBuffer.writeEnumBE(code);
                }, code);
            socket.sendTo(dataStream.toBuffer(), toAddress);
        }

        void formatFinished(BYTESTREAM& dataStream)
        {
            formatRecord(dataStream, record_handshake, MESSAGE_TYPE::finished, [](BYTESTREAM& msgBuffer, DTLS_HANDSHAKE& handshake)
                {
                    auto label = handshake.session.isServer ? "server finished" : "client finished";
                    handshake.cipher.PRF(label, handshake.transcriptHash.getHash(), msgBuffer.commitTo(12));
                }, *this);
        }

        BUFFER readVariableData(BUFFER& message, UINT8 lengthBytes)
        {
            if (lengthBytes == 3)
            {
                auto c = message.readByte();
                ASSERT(c == 0);
                lengthBytes = 2;
            }

            ASSERT(lengthBytes == 1 || lengthBytes == 2);

            UINT32 length = lengthBytes == 1 ? message.readByte() : message.beReadU16();
            return message.readBytes(length);
        }

        UINT16 readUINT24(BUFFER& data)
        {
            data.read();
            return data.beReadU16();
        }

        void parseFinished(BUFFER msgData)
        {
            auto receiveHash = msgData.readBytes(12);

            UINT8 expectedHash[12];
            cipher.PRF(session.isServer ? "client finished" : "server finished", transcriptHash.getHash(), expectedHash);
            ASSERT(receiveHash == BUFFER(expectedHash));
        }

        void parseClientKeyExchange(BUFFER msgData)
        {
            auto keyData = readVariableData(msgData, 1);
            keyShare.createSharedSecret(keyData);

            cipher.generateMasterSecret(keyShare.sharedSecret);
            cipher.generateTrafficKeys();
            cipher.extractSRTPkeys(session.srtpCipher);
        }

        void parseServerKeyExchange(BUFFER msgData)
        {
            auto hashStart = msgData.data();

            auto curveType = msgData.readByte();
            ASSERT(curveType == 0x03); // named curve

            auto group = msgData.readEnumBE<SUPPORTED_GROUPS>();
            keyShare.initialize(group);

            auto peerKey = readVariableData(msgData, 1);
            keyShare.createSharedSecret(peerKey);
            cipher.generateMasterSecret(keyShare.sharedSecret);
            cipher.generateTrafficKeys();
            cipher.extractSRTPkeys(session.srtpCipher);

            BUFFER hashInput{ hashStart, (UINT32)(msgData.data() - hashStart) };

            SHA256_DATA hashOutput;
            Sha256ComputeHash(hashOutput, cipher.clientRandom, cipher.serverRandom, hashInput);

            auto signatureAlgorithm = msgData.readEnumBE<SIGNATURE_SCHEME>();

            auto signatureBuf = readVariableData(msgData, 2);

            //auto&& certificate = peerCertificates.at(0);

            if (signatureAlgorithm == ecdsa_secp256r1_sha256)
            {
                ECDSA_DATA sigData;
                auto signature = X509.ParseECDSASignature(signatureBuf, sigData);

                auto result = ecdsa_verify(peerPublicKey, hashOutput, signature);
                //auto result = ecdsa_verify(certificate.publicKey, hashOutput, signature);
                ASSERT(result);
            }
            else
            {
                DBGBREAK();
            }
        }

        BUFFER readExtension(BUFFER& message, EXTENSION_TYPE& type)
        {
            type = message.readEnumBE<EXTENSION_TYPE>();
            auto length = message.beReadU16();

            return message.readBytes(length);
        }

        bool parseClientHello(BUFFER data, BUFFER& sessionId)
        {
            bool cipherSuiteValid = false, srtpProfileValid = false;

            data.readEnumBE<TLS_VERSION>();
            BYTESTREAM(cipher.clientRandom).writeBytes(data.readBytes(PRF_RANDOM_LENGTH));

            sessionId = readVariableData(data, 1);

            auto cookie = readVariableData(data, 1);

            auto cipherSuiteData = readVariableData(data, 2);
            while (cipherSuiteData)
            {
                auto cipherSuite = cipherSuiteData.readEnumBE<CIPHER_SUITE>();
                if (cipherSuite == TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)
                {
                    LogInfo("Found valid TLS cipher suite");
                    cipherSuiteValid = true;
                    break;
                }
            }
            readVariableData(data, 1); // compression ...

            auto extensions = readVariableData(data, 2);
            while (extensions)
            {
                EXTENSION_TYPE extType;
                auto extData = readExtension(extensions, extType);

                if (extType == ext_use_srtp)
                {
                    auto profileData = readVariableData(extData, 2);
                    while (profileData)
                    {
                        auto profile = profileData.readEnumBE<SRTP_PROTECTION_PROFILE>();
                        if (profile == SRTP_AES128_CM_HMAC_SHA1_80 /*SRTP_AEAD_AES_128_GCM*/)
                        {
                            LogInfo("Found CTR for SRTP cipher");
                            srtpProfileValid = true;
                        }
                    }
                    session.srtpCipher.cipher = SRTP_AES128_CM_HMAC_SHA1_80;
                }
                else if (extType == ext_server_name)
                {

                }
            }
            return cipherSuiteValid && srtpProfileValid;
        }

        bool parseServerHello(BUFFER data)
        {
            auto isValid = false;

            data.readEnumBE<TLS_VERSION>();

            BYTESTREAM(cipher.serverRandom).writeBytes(data.readBytes(PRF_RANDOM_LENGTH));

            auto sessionId = readVariableData(data, 1);

            data.readEnumBE<CIPHER_SUITE>();

            data.readByte(); // compression

            auto extension = readVariableData(data, 2);
            while (extension)
            {
                EXTENSION_TYPE extType;
                auto extData = readExtension(extension, extType);

                if (extType == ext_use_srtp)
                {
                    auto profile = extData.readEnumBE<SRTP_PROTECTION_PROFILE>();
                    if (profile == SRTP_AEAD_AES_128_GCM)
                        isValid = true;
                    else DBGBREAK();
                }
                else if (extType == ext_server_name)
                {

                }
                else DBGBREAK();
            }

            return isValid;
        }

        void parseCertificates(BUFFER message)
        {
            auto certsData = readVariableData(message, 3);

            if (certsData)
            {
                auto certData = readVariableData(certsData, 3);
                peerPublicKey = X509_PARTS(certData).getPublicKey(GetSessionStack().blobStream);
            }
        }

        bool parseCertificateRequest(BUFFER message)
        {
            auto certificateTypes = readVariableData(message, 1);
            auto signatureSchemes = readVariableData(message, 2);
            auto CAs = readVariableData(message, 2);

            auto certificateTypeValid = false;
            while (certificateTypes)
            {
                if (certificateTypes.readEnumBE<CLIENT_CERTIFICATE_TYPE>() == cert_ecdsa_sign)
                {
                    certificateTypeValid = true;
                    break;
                }
            }

            auto signatureSchemeValid = false;
            while (signatureSchemes)
            {
                if (signatureSchemes.readEnumBE<SIGNATURE_SCHEME>() == ecdsa_secp256r1_sha256)
                {
                    signatureSchemeValid = true;
                    break;
                }
            }

            return certificateTypeValid && signatureSchemeValid;
        }

        bool parseCertificateVerify(BUFFER message)
        {
            auto signatureScheme = message.readEnumBE<SIGNATURE_SCHEME>();
            auto receivedSignature = readVariableData(message, 2);

            auto hash = transcriptHash.getHash();

            if (signatureScheme == ecdsa_secp256r1_sha256)
            {
                ECDSA_DATA sigData;
                auto signature = X509.ParseECDSASignature(receivedSignature, sigData);

                auto result = ecdsa_verify(peerPublicKey, hash, signature);
                ASSERT(result);
            }
            else DBGBREAK();
            return true;
        }

        void parseMessage(UDP_TRANSPORT& socket, BUFFER fragment, IPENDPOINT& fromAddress)
        {
            BUFFER newMessage;
            {
                auto fragmentCopy = fragment;

                fragment.readEnumBE<MESSAGE_TYPE>(); // msgType
                auto msgLength = readUINT24(fragment);

                auto msgSeqNumber = fragment.beReadU16();
                auto fragmentOffset = readUINT24(fragment);
                auto fragmentLength = readUINT24(fragment);

                if (msgSeqNumber == recvMsgSeqNumber)
                {
                    if (fragmentLength == msgLength)
                    {
                        newMessage = fragmentCopy;
                    }
                    else
                    {
                        auto& recvStream = recvRecordStream;
                        if (fragmentOffset == 0)
                        {
                            recvStream.clear();
                            recvStream.writeBytes(BUFFER(fragmentCopy.data(), DTLS_MESSAGE_HEADER - 2)); // copy header upto fragment offset
                            recvStream.beWriteU16(msgLength);
                        }
                        else
                        {
                            ASSERT(recvStream.count() == (fragmentOffset + DTLS_MESSAGE_HEADER));
                        }
                        recvStream.writeBytes(fragment);
                        if (recvStream.count() >= (msgLength + DTLS_MESSAGE_HEADER))
                        {
                            newMessage = recvStream.toBuffer();
                        }
                    }
                }
                else if (msgSeqNumber < recvMsgSeqNumber)
                {
                    LogInfo("Duplicate DTLS message");
                }
                else DBGBREAK();
            }

            if (newMessage)
            {
                stopRetransmitTimer();

                auto messageHash = newMessage;

                auto msgType = newMessage.readEnumBE<MESSAGE_TYPE>();
                auto msgLength = readUINT24(newMessage);
                newMessage.read(DTLS_FRAGMENT_OVERHEAD);

                auto msgData = newMessage.readBytes(msgLength);
                ASSERT(newMessage.length() == 0); // multiple messages in a record, handle it.

                recvMsgSeqNumber++;

                if (msgType != MESSAGE_TYPE::finished && msgType != MESSAGE_TYPE::certificate_verify)
                {
                    transcriptHash.addMessage(messageHash);
                }

                if (msgType == MESSAGE_TYPE::hello_verify_request)
                {
                    msgData.readEnumBE<TLS_VERSION>(); // version
                    auto cookie = readVariableData(msgData, 1);
                    sendClientHello(socket, fromAddress, cookie);
                }
                else if (msgType == MESSAGE_TYPE::server_hello)
                {
                    parseServerHello(msgData);
                }
                else if (msgType == MESSAGE_TYPE::client_hello)
                {
                    BUFFER sessionId;
                    auto isValid = parseClientHello(msgData, sessionId);
                    if (isValid)
                    {
                        auto& dataStream = sendRecordStream.clear();

                        formatServerHello(dataStream, sessionId);
                        formatCertificates(dataStream);
                        formatServerKeyExchange(dataStream);
                        formatCertificateRequest(dataStream);
                        formatServerHelloDone(dataStream);

                        ASSERT(dataStream.count() < DTLS_PMTU);
                        socket.sendTo(dataStream.toBuffer());
                    }
                    else
                    {
                        LogInfo("Rejecting clientHello");
                        sendAlert(ALERT_DESCRIPTION::illegal_parameter, socket, fromAddress);
                    }
                }
                else if (msgType == MESSAGE_TYPE::server_hello_done)
                {
                    auto& outStream = sendRecordStream.clear();
                    formatClientKeyExchange(outStream);
                    formatChangeCipherSpec(outStream);
                    formatFinished(outStream);
                    socket.sendTo(outStream.toBuffer());
                }
                else if (msgType == MESSAGE_TYPE::server_key_exchange)
                {
                    parseServerKeyExchange(msgData);
                }
                else if (msgType == MESSAGE_TYPE::certificate)
                {
                    parseCertificates(msgData);
                }
                else if (msgType == MESSAGE_TYPE::client_key_exchange)
                {
                    parseClientKeyExchange(msgData);
                }
                else if (msgType == MESSAGE_TYPE::certificate_verify)
                {
                    parseCertificateVerify(msgData);
                    transcriptHash.addMessage(messageHash);
                }
                else if (msgType == MESSAGE_TYPE::finished)
                {
                    parseFinished(msgData);
                    auto& outStream = sendRecordStream.clear();
                    transcriptHash.addMessage(messageHash);
                    if (session.isServer)
                    {
                        formatChangeCipherSpec(outStream);
                        formatFinished(outStream);
                        socket.sendTo(outStream.toBuffer(), fromAddress);
                    }
                }
                else DBGBREAK();
            }
        }

        void parseRecord(UDP_TRANSPORT& socket, BUFFER recvData, IPENDPOINT& fromAddress)
        {
            BUFFER record;
            {
                auto dataCopy = recvData;
                dataCopy.read(DTLS_RECORD_LENGTH_OFFSET);
                auto length = dataCopy.beReadU16();
                record = recvData.readBytes(length + DTLS_RECORD_HEADER);
            }

            auto recordCopy = record;

            auto recordType = record.readEnumBE<RECORD_TYPE>();
            record.readEnumBE<TLS_VERSION>();

            auto seqNumber = record.beReadU64();
            if (seqNumber == cipher.nextRecvSeqNumber())
            {
                cipher.claimRecvSeqNumber();
                auto userData = cipher.decrypt(recordCopy);
                if (recordType == record_handshake)
                {
                    parseMessage(socket, userData, fromAddress);
                }
                else if (recordType == record_change_cipher_spec)
                {
                    cipher.recvEncrypted = true;
                    cipher.recvEpoch++;
                    cipher._recvSequenceNumber = 0;
                }
                else if (recordType == record_application_data)
                {
                    DBGBREAK();
                    // call user
                }
                else if (recordType == record_alert)
                {
                    DBGBREAK();
                    auto alertType = userData.readByte();
                    auto alertDescription = userData.readByte();

                    LogInfo("alert received,", alertType, "/", alertDescription);
                }
            }
            else
            {
                DBGBREAK();
            }

            if (recvData)
            {
                parseRecord(socket, recvData, fromAddress);
            }
        }

        void onReceiveFrom(UDP_TRANSPORT& socket, BUFFER recvData, IPENDPOINT& fromAddress)
        {
            parseRecord(socket, recvData, fromAddress);
        }

        NTSTATUS startClient(UDP_TRANSPORT& socket, IPENDPOINT& toAddress)
        {
            sendClientHello(socket, toAddress, NULL_BUFFER);
            return STATUS_SUCCESS;
        }

        void startServer()
        {
            // nothing to do
        }
    };

    struct VIDEO_RECEIVER
    {
        SDP_BUFFER config;

        UINT8 packetType;
        UINT32 rtxPacketType;

        TOKEN mid;

        UINT32 ssrc;
        UINT32 rtxSsrc;

        UINT16 decodeOrder;
        BYTESTREAM reassemblyStream;
    } videoReceiver;

    struct AUDIO_RECEIVER
    {
        SDP_BUFFER config;

        UINT8 packetType;
        TOKEN mid;
        UINT32 ssrc;
    } audioReceiver;

    struct VIDEO_SENDER
    {
        TOKEN mid;
        UINT32 ssrc;
        UINT32 rtxSsrc;

        BUFFER fragmentBuffer;
    } videoSender;

    struct AUDIO_SENDER
    {
        TOKEN mid;
        UINT32 ssrc;
    } audioSender;

    struct EXTNSION_ID
    {
        UINT8 mid = 0;
        UINT8 rid = 0;
        UINT8 rrid = 0;
    } extensionId;

    SOCKET createSocket()
    {
        auto socketHandle = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
        if (socketHandle != INVALID_SOCKET)
        {
            auto status = getScheduler().registerHandle((HANDLE)socketHandle, (PVOID)this);
            ASSERT(NT_SUCCESS(status));
        }
        return socketHandle;
    }

    template <typename ... ARGS>
    void createTask(STASK& task, TASK_HANDLER handler, ARGS&& ... args)
    {
        new (&task) STASK(sessionStack, handler, (PVOID)this, args ...);
    }

    bool isServer = true;

    SESSION_STACK sessionStack;
    SERVICE& service;
    auto&& getScheduler() { return service.scheduler; }

    SDP_STREAM<SESSION_STACK> sdpStream;

    DATASTREAM<ICE_CANDIDATE, SESSION_STACK> remoteIceCandidates;

    LOCAL_STREAM<32> etag;

    LOCAL_STREAM<8> localIceUfrag;
    LOCAL_STREAM<8> remoteIceUfrag;

    LOCAL_STREAM<32> localIcePassword;
    LOCAL_STREAM<32> remoteIcePassword;

    DTLS_HANDSHAKE handshake;
    SRTP_CIPHER srtpCipher;

    LOCAL_STREAM<256> stunStream;
    SRTP_SHAPER shaper;

    WEBRTC_SESSION(SERVICE& serverArg) : service(serverArg), handshake(*this), shaper(*this)
    {
        sessionStack.init(16 * 1024 * 1024, 0);
    }

    BUFFER readStunAttribute(BUFFER& message, STUN_ATTR& attrName)
    {
        BUFFER attrData;
        if (message.length() >= 4)
        {
            attrName = message.readEnumBE<STUN_ATTR>();
            auto length = message.beReadU16();
            attrData = message.readBytes(length);

            message.read(ROUND_TO(length, 4) - length);
        }
        return attrData;
    }

    void sendStunResponse(UDP_TRANSPORT& socket, BUFFER transactionId, IPENDPOINT& fromAddress)
    {
        stunStream.writeEnumBE(STUN_MESSAGE::BINDING_SUCCESS);
        auto msgLengthOffset = stunStream.count();
        stunStream.beWriteU16(0);
        stunStream.beWriteU32(STUN_MAGIC);
        stunStream.writeBytes(transactionId);

        auto attrStart = stunStream.getPosition();
        stunStream.writeEnumBE(XOR_MAPPED_ADDRESS);
        {
            auto attrOffset = stunStream.saveOffset(2);
            stunStream.writeByte(0);
            stunStream.writeByte(0x01); // IPV4

            auto port = SWAP16(fromAddress._address.sin_port) ^ ((UINT16)(STUN_MAGIC >> 16));
            stunStream.beWriteU16((UINT16)port);

            auto addr = SWAP32(fromAddress._address.sin_addr.s_addr) ^ STUN_MAGIC;
            stunStream.beWriteU32(addr);
            attrOffset.writeLength();
        }
        stunStream.writeBytes(ZeroBytes, ROUND_TO(stunStream.count(), 4) - stunStream.count());

        stunStream.writeEnumBE(USERNAME);
        {
            auto attrOffset = stunStream.saveOffset(2);
            stunStream.writeMany(localIceUfrag.toBuffer(), ":", remoteIceUfrag.toBuffer());
            attrOffset.writeLength();
        }
        stunStream.writeBytes(ZeroBytes, ROUND_TO(stunStream.count(), 4) - stunStream.count());

        stunStream.writeEnumBE(MESSAGE_INTEGRITY);
        {
            auto authData = stunStream.toBuffer();
            auto attrOffset = stunStream.saveOffset(2);
            stunStream.beWriteAtU16(msgLengthOffset, (UINT16)(attrStart.getLength() + SHA1_HASH_LENGTH));
            HmacSha1(stunStream.commitTo(SHA1_HASH_LENGTH), localIcePassword.toBuffer(), authData);
            attrOffset.writeLength();
        }

        stunStream.beWriteAtU16(msgLengthOffset, (UINT16)(attrStart.getLength() + STUN_ATTR_HEADER + sizeof(UINT32)));
        auto crc32 = ComputeCrc32(stunStream.toBuffer()) ^ STUN_FINGERPRINT_MAGIC;

        stunStream.writeEnumBE(FINGERPRINT);
        auto attrOffset = stunStream.saveOffset(2);
        stunStream.beWriteU32(crc32);
        attrOffset.writeLength();

        LogInfo("Sent STUN response");
        socket.sendTo(stunStream.toBuffer());
    }

    void StunHandshake(UDP_TRANSPORT& transport, bool isUseCandidate, bool isControlled)
    {
        do
        {
            stunStream.writeEnumBE(STUN_MESSAGE::BINDING_REQUEST);
            auto msgLengthOffset = stunStream.count();
            stunStream.beWriteU16(0);
            {
                stunStream.beWriteU32(STUN_MAGIC);
                Random.getBytes(stunStream.commitTo(12));

                auto attrStart = stunStream.getPosition();
                if (remoteIcePassword && remoteIceUfrag)
                {
                    stunStream.writeEnumBE(USERNAME);
                    auto nameOffset = stunStream.saveOffset(2);
                    stunStream.writeMany(remoteIceUfrag, ":", localIceUfrag);
                    nameOffset.writeLength();

                    stunStream.writeEnumBE(MESSAGE_INTEGRITY);
                    auto authData = stunStream.toBuffer();
                    auto hashAttrOffset = stunStream.saveOffset(2);
                    stunStream.beWriteAtU16(msgLengthOffset, (UINT16)(attrStart.getLength() + SHA1_HASH_LENGTH));
                    HmacSha1(stunStream.commitTo(SHA1_HASH_LENGTH), remoteIcePassword.toBuffer(), authData);
                    hashAttrOffset.writeLength();

                    if (isUseCandidate)
                    {
                        stunStream.writeEnumBE(USE_CANDIDATE);
                        stunStream.beWriteU16(0);
                    }

                    stunStream.writeEnumBE(isControlled ? ICE_CONTROLLED : ICE_CONTROLLING);
                    stunStream.beWriteU16(8); // UINT64
                    Random.getBytes(stunStream.commitTo(8));
                }

                stunStream.beWriteAtU16(msgLengthOffset, (UINT16)(attrStart.getLength() + STUN_ATTR_HEADER + sizeof(UINT32)));
                auto crc32 = ComputeCrc32(stunStream.toBuffer()) ^ STUN_FINGERPRINT_MAGIC;

                stunStream.writeEnumBE(FINGERPRINT);
                auto attrOffset = stunStream.saveOffset(2);
                stunStream.beWriteU32(crc32);
                attrOffset.writeLength();
            }

            transport.sendTo(stunStream.toBuffer());
        } while (false);
    }

    void onStunRequest(UDP_TRANSPORT& recvTransport, BUFFER transactionId, BUFFER message, IPENDPOINT& fromAddress)
    {
        STUN_ATTR attrName;
        auto isRequestValid = true;
        while (message)
        {
            auto attrData = readStunAttribute(message, attrName);
            LogInfo("StunRequest: ATTR:", UINT32(attrName));
            if (attrName == USERNAME)
            {
                LOCAL_STREAM<16> username;
                username.writeMany(localIceUfrag.toBuffer(), ":", remoteIceUfrag.toBuffer());
                if (username.toBuffer() != attrData)
                {
                    DBGBREAK();
                    isRequestValid = false;
                    break;
                }
            }
            else if (attrName == USE_CANDIDATE)
            {
                LogInfo("StunRequest: Setting activeSocket");
                for (auto& transport : networkTransports.toRWBuffer())
                {
                    if (transport.localAddress != recvTransport.localAddress)
                    {
                        transport.close();
                    }
                }
                recvTransport.remoteAddress = fromAddress;
            }
        }

        sendStunResponse(recvTransport, transactionId, fromAddress);
    }

    void onStunResponse(UDP_TRANSPORT& socket, BUFFER transactionId, BUFFER message, IPENDPOINT& fromAddress)
    {
        LogInfo("StrunResponse unexpected");
        UNREFERENCED_PARAMETER(socket);
        UNREFERENCED_PARAMETER(transactionId);
        UNREFERENCED_PARAMETER(message);
        UNREFERENCED_PARAMETER(fromAddress);
    }

    void onStunMessage(UDP_TRANSPORT& socket, BUFFER recvMessage, IPENDPOINT& fromAddress)
    {
        LogInfo("onStunMessage: received %d bytes", recvMessage.length());
        BUFFER messageCopy = recvMessage;

        auto type = recvMessage.readEnumBE<STUN_MESSAGE>();
        auto length = recvMessage.beReadU16();
        auto magic = recvMessage.beReadU32();
        ASSERT(magic == STUN_MAGIC);

        auto transactionId = recvMessage.readBytes(12);
        BUFFER attributes{ recvMessage.data(), length };
        auto attributesCopy = attributes;

        auto attrStart = attributes.data();

        STUN_ATTR attrName;
        auto isValidRequest = true;
        while (attributes)
        {
            auto attrData = readStunAttribute(attributes, attrName);
            if (attrName == MESSAGE_INTEGRITY)
            {
                BUFFER hashData{ attrStart, (UINT32)(attributes.data() - attrStart - STUN_MESSAGE_INTEGRITY_SIZE) }; // hash data doesn't include this attr

                LOCAL_STREAM<32> headerStream;
                headerStream.writeEnumBE(type);
                headerStream.beWriteU16((UINT16)(attributes.data() - attrStart));
                headerStream.beWriteU32(STUN_MAGIC);
                headerStream.writeBytes(transactionId);

                SHA1_DATA hashInput;
                auto hash = HmacSha1(hashInput, localIcePassword.toBuffer(), headerStream.toBuffer(), hashData);

                if (attrData != hash)
                {
                    DBGBREAK();
                    isValidRequest = false;
                    break;
                }
            }
            else if (attrName == FINGERPRINT)
            {
                ASSERT(attrData.length() == STUN_FINGERPRINT_LENGTH);
                auto crcReceived = attrData.beReadU32();

                messageCopy.shrink(STUN_FINGERPRINT_LENGTH + STUN_ATTR_HEADER);
                auto crcComputed = ComputeCrc32(messageCopy) ^ STUN_FINGERPRINT_MAGIC;
                if (crcReceived != crcComputed)
                {
                    DBGBREAK();
                    isValidRequest = false;
                    break;
                }
            }
            else if (attrName == MESSAGE_INTEGRITY_SHA_256)
            {
                DBGBREAK();
            }
        }

        if (!isValidRequest)
        {
            DBGBREAK(); // send error response
        }

        if (type == STUN_MESSAGE::BINDING_REQUEST)
        {
            onStunRequest(socket, transactionId, attributesCopy, fromAddress);
        }
        else if (type == STUN_MESSAGE::BINDING_SUCCESS)
        {
            onStunResponse(socket, transactionId, BUFFER(recvMessage.data(), length), fromAddress);
        }
        else if (type == STUN_MESSAGE::BINDING_FAILURE)
        {
            DBGBREAK();
        }
        else DBGBREAK();
    }

    BUFFER onSignalingReceive(TOKEN type, USTRING sdpString)
    {
        BUFFER response;
        TSDP_STREAM sdpStream;
        if (type == SDP_offer)
        {
            Sdp.parseSdp(sdpString, sdpStream);

            auto ufrag = Sdp.find(sdpStream.toBuffer(), SDP_ice_ufrag);
            remoteIceUfrag.writeString(ufrag.at(0));

            auto passwd = Sdp.find(sdpStream.toBuffer(), SDP_ice_pwd);
            remoteIcePassword.writeString(passwd.at(0));

            selectMediaStreams();

            auto&& outStream = ByteStream(1024);

            outStream.writeString("{ \"type\" : \"answer\", \"sdp\" : \"");
            generateSdp(outStream, audioReceiver.config, videoReceiver.config);
            outStream.writeString("\"}");
            LogInfo("Reply:"); outStream.toBuffer().print();
            response = outStream.toBuffer();
        }
        else if (type == SDP_candidate)
        {
            LogInfo("Parsing ice candidate");
            SDP_LINE sdpLine;
            Sdp.parseSdpLine(sdpString, sdpLine, 'a');
            ICE_CANDIDATE iceCandidate;
            if (Sdp.parseIceCandidate(sdpLine, iceCandidate))
            {
                remoteIceCandidates.append(iceCandidate);
            }
        }
        else DBGBREAK();
        return response;
    }

    void selectMediaStreams()
    {
        SDP_BUFFER videoStream;

        auto sdpBuffer = sdpStream.toBuffer();
        UINT8 profileId = 0, profileLevel = 0;

        Sdp.findMany(sdpBuffer, SDP_video, [](SDP_BUFFER mediaStream, SDP_BUFFER& videoStream, UINT8& profileId, UINT8& profileLevel)
            {
                auto fmtp = Sdp.find(mediaStream, SDP_fmtp);
                for (UINT32 i = 0; i < fmtp.length(); i += 2)
                {
                    if (fmtp.at(i) == SDP_profile_level_id)
                    {
                        auto valueHandle = fmtp.at(i + 1);
                        auto value = (UINT32)Tokens.getNumber(valueHandle);
                        auto id = (UINT8)((value & 0xFF0000) >> 16);
                        auto level = (UINT8)(value & 0xFF);

                        if ((id >= profileId) || ((id == profileId) && (level > profileLevel)))
                        {
                            profileId = id;
                            profileLevel = level;
                            videoStream = mediaStream;
                        }
                    }
                }
            }, videoStream, profileId, profileLevel);

        ASSERT(videoStream);

        videoReceiver.config = videoStream;
        videoReceiver.mid = Sdp.find(videoStream, SDP_mid).at(0);

        auto ssrc = Sdp.find(videoStream, SDP_ssrc);
        ASSERT(ssrc.length() == 2);

        videoReceiver.ssrc = (UINT32)Tokens.getNumber(ssrc.at(0));
        videoReceiver.rtxSsrc = (UINT32)Tokens.getNumber(ssrc.at(1));

        auto audioStream = Sdp.find(sdpBuffer, SDP_audio);
        ASSERT(audioStream);

        audioReceiver.config = audioStream;
        audioReceiver.mid = Sdp.find(audioStream, SDP_mid).at(0);
        audioReceiver.ssrc = (UINT32)Tokens.getNumber(Sdp.find(audioStream, SDP_ssrc).at(0));

        auto extmap = Sdp.find(sdpBuffer, SDP_extmap);
        while (extmap)
        {
            auto id = (UINT8)Tokens.getNumber(extmap.read());
            auto url = extmap.read();

            if (url == RTPEXT_MID)
            {
                extensionId.mid = id;
            }
            else if (url == RTPEXT_RID)
            {
                extensionId.rid = id;
            }
            else if (url == RTPEXT_RRID)
            {
                extensionId.rrid = id;
            }
        }
    }

    template <typename STREAM>
    void generateSdp(STREAM&& sdpString, SDP_BUFFER media)
    {
        sdpString.writeString(" 9 UDP/TLS/RTP/SAVPF");
        auto rtp = Sdp.find(media, SDP_rtpmap);
        TOKEN packetType = NULL_NAME;
        ASSERT(rtp);
        if (rtp)
        {
            packetType = rtp.at(0);
            sdpString.writeMany(" ", packetType);
        }
        auto rtx = Sdp.find(media, SDP_rtx);
        if (rtx)
        {
            sdpString.writeMany(" ", rtx.at(0));
        }
        sdpString.writeString(ESC_CRLF);
        sdpString.writeMany("c=IN IP4 0.0.0.0", ESC_CRLF, "a=rtcp:9 IN IP4 0.0.0.0", ESC_CRLF, "a=rtcp-mux", ESC_CRLF, "a=rtcp-rsize", ESC_CRLF, "a=sendrecv", ESC_CRLF, "a=setup:passive", ESC_CRLF);
        if (auto mid = Sdp.find(media, SDP_mid))
        {
            sdpString.writeMany("a=mid:", mid.read(), ESC_CRLF);
        }

        sdpString.writeMany("a=ice-ufrag:", localIceUfrag.toBuffer(), ESC_CRLF);
        sdpString.writeMany("a=ice-pwd:", localIcePassword.toBuffer(), ESC_CRLF);
        sdpString.writeMany("a=ice-options:trickle", ESC_CRLF);

        SHA256_DATA hashData;
        auto certHash = Sha256ComputeHash(hashData, SystemService().AKsignKey.certBytes); // HttpConfig.tlsCertData);

        sdpString.writeString("a=fingerprint:sha-256 ");
        for (auto& hexChar : certHash)
        {
            sdpString.writeHex(hexChar);
            sdpString.writeString(":");
        }
        sdpString.trim(); // remove the trailing ':'
        sdpString.writeString(ESC_CRLF);

        ASSERT(rtp);
        sdpString.writeMany("a=rtpmap:", packetType, " ");
        auto codec = Sdp.find(media, SDP_codec);
        ASSERT(codec);
        while (codec)
        {
            sdpString.writeMany(codec.read(), "/");
        }
        sdpString.trim(); // remove trailing '/'
        sdpString.writeString(ESC_CRLF);

        auto fmtp = Sdp.find(media, SDP_fmtp);
        ASSERT(fmtp);
        sdpString.writeMany("a=fmtp:", packetType, " ");
        while (fmtp)
        {
            auto key = fmtp.read();
            sdpString.writeMany(key, "=");

            auto value = fmtp.read();
            auto number = Tokens.getNumber(value);
            sdpString.writeString(number, 16);
            sdpString.writeString(";");
        }
        sdpString.trim(); // remove trailing ';'
        sdpString.writeString(ESC_CRLF);

        auto rtcp = Sdp.find(media, SDP_rtcp_fb);
        while (rtcp)
        {
            sdpString.writeMany("a=rtcp-fb:", packetType, " ");
            auto name = rtcp.read();
            sdpString.writeMany(name == SDP_nack ? "nack"
                : name == SDP_nack_pli ? "nack pli"
                : name == SDP_nack_sli ? "nack sli"
                : name == SDP_nack_rpsi ? "nack rpsi"
                : name == SDP_ccm_fir ? "ccm fir"
                : name == SDP_ccm_tmmbr ? "ccm tmmbr"
                : name == SDP_ccm_tstr ? "ccm tstr" : NameToString(name));
            sdpString.writeString(ESC_CRLF);
        }

        if (rtx)
        {
            sdpString.writeMany("a=rtpmap:", rtx.at(0), " rtx/");
            codec.rewind().read();
            while (codec)
            {
                sdpString.writeMany(codec.read(), "/");
            }
            sdpString.trim();
            sdpString.writeString(ESC_CRLF);
            //a=fmtp:115 apt=114

            sdpString.writeMany("a=fmtp:", rtx.at(0), " apt=", packetType, ESC_CRLF);
        }

        auto extmap = Sdp.find(sdpStream.toBuffer(), SDP_extmap);
        while (extmap)
        {
            auto id = extmap.read();
            auto url = extmap.read();

            if ((url == RTPEXT_MID) || (url == RTPEXT_RID) || (url == RTPEXT_RRID))
            {
                sdpString.writeMany("a=extmap:", id, " ", url, ESC_CRLF);
            }
        }
        media.rewind();

        for (auto& transport : networkTransports.toBuffer())
        {
            ICE_CANDIDATE iceCandidate{ transport.localAddress };
            Sdp.formatIceCandidate(sdpString, iceCandidate);
        }
        sdpString.writeMany("a=end-of-candidates", ESC_CRLF);
    }

    template <typename STREAM>
    USTRING generateSdp(STREAM&& sdpOutput, SDP_BUFFER audioStream, SDP_BUFFER videoStream)
    {
        sdpOutput.writeMany("v=0", ESC_CRLF, "o=- ", Random.getNumber());
        sdpOutput.writeMany(" 2 IN IP4 127.0.0.1", ESC_CRLF, "s=-", ESC_CRLF, "t=0 0", ESC_CRLF);

        sdpOutput.writeString("a=group:BUNDLE ");
        if (audioStream)
            sdpOutput.writeString(Sdp.find(audioStream, SDP_mid).at(0));
        if (videoStream)
            sdpOutput.writeMany(" ", Sdp.find(videoStream, SDP_mid).at(0));
        sdpOutput.writeString(ESC_CRLF);

        sdpOutput.writeMany("a=msid-semantic: WMS StateMedia", ESC_CRLF);

        if (audioStream)
        {
            sdpOutput.writeMany("m=audio");
            generateSdp(sdpOutput, audioStream);

            audioSender.ssrc = UINT32(Random.getNumber());
            videoSender.ssrc, UINT32(Random.getNumber());
            videoSender.rtxSsrc, UINT32(Random.getNumber());

            sdpOutput.writeMany("a=ssrc:", audioSender.ssrc, " cname:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", audioSender.ssrc, " msid:StateMedia audio0", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", audioSender.ssrc, " mslabel:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", audioSender.ssrc, " label:audio0", ESC_CRLF);
        }

        if (videoStream)
        {
            sdpOutput.writeMany("m=video");
            generateSdp(sdpOutput, videoStream);

            sdpOutput.writeMany("a=ssrc-group:FID ", videoSender.ssrc, " ", videoSender.rtxSsrc, ESC_CRLF);

            sdpOutput.writeMany("a=ssrc:", videoSender.ssrc, " cname:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.ssrc, " msid:StateMedia video0", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.ssrc, " mslabel:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.ssrc, " label:video0", ESC_CRLF);

            sdpOutput.writeMany("a=ssrc:", videoSender.rtxSsrc, " cname:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.rtxSsrc, " msid:StateMedia video0", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.rtxSsrc, " mslabel:StateMedia", ESC_CRLF);
            sdpOutput.writeMany("a=ssrc:", videoSender.rtxSsrc, " label:video0", ESC_CRLF);
        }
        return sdpOutput.toBuffer();
    }

    void addIceCandidate(ULONG srcAddress)
    {
    }

    void gatherIceCandidates()
    {
        PMIB_UNICASTIPADDRESS_TABLE addrTable;
        GetUnicastIpAddressTable(AF_INET, &addrTable);

        PMIB_IPFORWARD_TABLE2 routeTable;
        auto result = GetIpForwardTable2(AF_INET, &routeTable);
        ASSERT(result == STATUS_SUCCESS);

        for (UINT32 i = 0; i < routeTable->NumEntries; i++)
        {
            auto&& route = routeTable->Table[i];

            PMIB_UNICASTIPADDRESS_ROW addrEntry = nullptr;
            for (UINT32 j = 0; j < addrTable->NumEntries; j++)
            {
                if (addrTable->Table[j].InterfaceIndex == route.InterfaceIndex)
                {
                    ASSERT(addrEntry == nullptr);  // duplicates???
                    addrEntry = &addrTable->Table[j];
                }
            }

            MIB_IPINTERFACE_ROW ipInterfaceEntry;
            RtlZeroMemory(&ipInterfaceEntry, sizeof(ipInterfaceEntry));
            ipInterfaceEntry.InterfaceIndex = addrEntry->InterfaceIndex;
            ipInterfaceEntry.Family = AF_INET;
            result = GetIpInterfaceEntry(&ipInterfaceEntry);
            ASSERT(result == STATUS_SUCCESS);

            MIB_IF_ROW2 ifEntry;
            RtlZeroMemory(&ifEntry, sizeof(ifEntry));
            ifEntry.InterfaceIndex = addrEntry->InterfaceIndex;
            result = GetIfEntry2(&ifEntry);
            ASSERT(result == STATUS_SUCCESS);

            if (!route.Loopback && route.Origin != NlroWellKnown && ifEntry.OperStatus == IfOperStatusUp)
            {
                IPENDPOINT ipInterface { addrEntry->Address.Ipv4 };
                if (ipInterface == IPLOOPBACK) continue;

                if (route.DestinationPrefix.PrefixLength < 32)
                {
                    if (!networkTransports.toBuffer().find(ipInterface))
                    {
                        auto&& transport = networkTransports.append(*this);
                        transport.initialize(ipInterface);
                    }
                }
            }
        }
    }

    NTSTATUS initialize(UINT16 recvPort = 0)
    {
        UNREFERENCED_PARAMETER(recvPort);
        auto status = STATUS_SUCCESS;
        UINT8 ufrag[3];
        Random.getBytes(ufrag);
        localIceUfrag.encodeBase64(ufrag);

        UINT8 password[18];
        Random.getBytes(password);
        localIcePassword.encodeBase64(password);

        UINT8 etagData[8];
        Random.getBytes(etagData);
        etag.encodeBase64(etagData);

        LogInfo("Gathering candidates ...");
        gatherIceCandidates();
        LogInfo("Done ...\n");

        return status;
    }

    void onReceiveFrom(UDP_TRANSPORT& socket, BUFFER recvData, IPENDPOINT& fromAddress)
    {
        auto firstByte = recvData.at(0);
        if (firstByte >= 0 && firstByte <= 3)
        {
            onStunMessage(socket, recvData, fromAddress);
        }
        else if (firstByte >= 20 && firstByte <= 63)
        {
            handshake.onReceiveFrom(socket, recvData, fromAddress);
        }
        else if (firstByte >= 64 && firstByte <= 79)
        {
            DBGBREAK();
            parseTurnMessage(recvData);
        }
        else if (firstByte >= 128 && firstByte <= 191)
        {
            auto secondByte = recvData.at(1);
            if (secondByte >= 192 && secondByte <= 223)
            {
                parseRtcpPacket(recvData);
            }
            else
            {
                parseRTPpacket(recvData);
            }
        }
        else DBGBREAK();
    }

    struct RTP_HEADER
    {
        UINT8 packetType = 0;
        bool isMarkerSet;
        UINT32 timeStamp = 0;
        UINT32 ssrc = 0;
        STREAM_READER<UINT32> csrcData;

        TOKEN mid;
        TOKEN rid;
        TOKEN rrid;
    };

    void parseNalUnit(RTP_HEADER& packetInfo, BUFFER nalData, UINT32 decodeOrder, UINT32 timeOffset = 0)
    {
        UNREFERENCED_PARAMETER(nalData);
        UNREFERENCED_PARAMETER(packetInfo);
        UNREFERENCED_PARAMETER(timeOffset);

        decodeOrder &= 0xFFFF;
    }

    void parseVideoStream(RTP_HEADER& packetInfo, BUFFER recvData)
    {
        UINT8 payloadType = recvData.at(0) & 0x1F;
        UINT8 nri = (recvData.at(0) & 0x60) >> 5;

        if (payloadType > H264_PAYLOAD_23)
            recvData.read();

        if (payloadType == H264_PAYLOAD_STAP_A || payloadType == H264_PAYLOAD_STAP_B)
        {
            auto typeB = payloadType == H264_PAYLOAD_STAP_B;
            UINT16 decodeOrder = typeB ? recvData.beReadU16() : 0;

            while (recvData)
            {
                auto nalLength = recvData.beReadU16();
                auto nalData = recvData.readBytes(nalLength);

                parseNalUnit(packetInfo, nalData, typeB ? ++decodeOrder : 0);
            }
        }
        else if (payloadType == H264_PAYLOAD_MTAP16 || payloadType == H264_PAYLOAD_MTAP24)
        {
            auto mtap24 = payloadType == H264_PAYLOAD_MTAP24;
            UINT16 decodeOrder = recvData.beReadU16();

            while (recvData)
            {
                auto nalLength = recvData.beReadU16();
                auto nalData = recvData.readBytes(nalLength);

                decodeOrder += nalData.readByte();
                UINT32 timestampOffset = mtap24 ? nalData.readIntBE(3) : nalData.readIntBE(2);

                parseNalUnit(packetInfo, nalData, decodeOrder, timestampOffset);
            }
        }
        else if (payloadType == H264_PAYLOAD_FU_A || payloadType == H264_PAYLOAD_FU_B)
        {
            auto fuHeader = recvData.readByte();
            if (fuHeader & H264_FU_S)
            {
                videoReceiver.reassemblyStream.clear();
                videoReceiver.reassemblyStream.reserve(256 * 1024);

                UINT8 nalHeader = (nri << 5) | (fuHeader & 0x1F);
                videoReceiver.reassemblyStream.writeByte(nalHeader);

                videoReceiver.decodeOrder = payloadType == H264_PAYLOAD_FU_B ? recvData.beReadU16() : 0;
            }
            videoReceiver.reassemblyStream.writeBytes(recvData);
            if (fuHeader & H264_FU_E)
            {
                parseNalUnit(packetInfo, videoReceiver.reassemblyStream.toBuffer(), videoReceiver.decodeOrder);
            }
        }
        else
        {
            ASSERT(payloadType > 0 && payloadType < 30);
        }
    }

    void parseAudioStream(RTP_HEADER& recvPacket, BUFFER recvData)
    {
        UNREFERENCED_PARAMETER(recvPacket);
        UNREFERENCED_PARAMETER(recvData);
    }

    void processRtpExtension(RTP_HEADER& packetInfo, UINT16 id, BUFFER data)
    {
        if (extensionId.mid == id)
        {
            auto name = CreateCustomName<SESSION_STACK>(data);
            packetInfo.mid = name;
        }
        else if (extensionId.rid == id)
        {
            auto name = CreateCustomName<SESSION_STACK>(data);
            packetInfo.rid = name;
        }
        else if (extensionId.rrid == id)
        {
            auto name = CreateCustomName<SESSION_STACK>(data);
            packetInfo.rrid = name;
        }
    }

    template <typename STREAM>
    void writeExtension(UINT8 id, TOKEN value, STREAM&& rtpStream)
    {
        LOCAL_STREAM<16> charStream;
        charStream.writeString(value);

        auto roundLength = ROUND_TO(charStream.count(), 4);

        UINT8 byte = ((id & 0x0F) << 4) | ((charStream.count() - 1) & 0x0F);
        rtpStream.writeByte(byte);

        rtpStream.writeBytes(charStream.toBuffer());

        rtpStream.writeBytes(ZeroBytes, roundLength - charStream.count());
    }

    template <typename STREAM>
    void formatRTPheader(RTP_HEADER& header, STREAM&& rtpStream)
    {
        ASSERT(header.csrcData.length() == 0);

        RTP_FLAGS rtpFlags;
        rtpFlags.setExtension();
        rtpFlags.setCsrcCount(0);
        if (header.isMarkerSet) rtpFlags.setMarker();
        rtpFlags.setPaketType(header.packetType);

        rtpStream.beWriteU16(rtpFlags.value);

        auto seqNumber = srtpCipher.getNextSendSeqNumber();
        rtpStream.beWriteU16(seqNumber);

        rtpStream.beWriteU32(header.timeStamp);
        rtpStream.beWriteU32(header.ssrc);

        LOCAL_STREAM<32> extensionStream;
        if (header.mid)
        {
            writeExtension(extensionId.mid, header.mid, extensionStream);
        }
        if (header.rid)
        {
            writeExtension(extensionId.rid, header.rid, extensionStream);
        }
        if (header.rrid)
        {
            writeExtension(extensionId.rrid, header.rrid, extensionStream);
        }

        rtpStream.beWriteU16(RTPEXT_GENERAL);
        rtpStream.beWriteU16((UINT16)(ROUND_TO(extensionStream.count(), 4) / 4));
        rtpStream.writeBytes(extensionStream.toBuffer());
    }

    void parseRTPpacket(BUFFER recvData)
    {
        auto authData = recvData;
        RTP_HEADER recvHeader;

        ASSERT(recvData.length() > RTP_FIXED_HEADER_SIZE);

        auto recvDataStart = recvData.data();

        auto fixedHeader = recvData.readBytes(RTP_FIXED_HEADER_SIZE);

        RTP_FLAGS rtpFlags{ fixedHeader.beReadU16() };
        recvHeader.packetType = rtpFlags.getPacketType();

        auto seqNumber = fixedHeader.beReadU16();
        recvHeader.timeStamp = fixedHeader.beReadU32();

        recvHeader.ssrc = fixedHeader.beReadU32();

        auto csrcCount = rtpFlags.getCsrcCount();
        auto csrcData = recvData.readBytes(csrcCount * sizeof(UINT32));

        if (rtpFlags.getExtension())
        {
            auto extType = recvData.beReadU16();
            auto extLength = (UINT32)(recvData.beReadU16() * sizeof(UINT32));
            auto extData = recvData.readBytes(extLength);

            if (extType == RTPEXT_GENERAL)
            {
                while (extData)
                {
                    auto byte = extData.readByte();
                    if (byte == 0)
                    {
                        extData.read();
                        continue;
                    }

                    if (byte == 15) break;

                    auto id = (UINT16)((byte & 0xF0) >> 4);
                    auto length = (byte & 0x0F) + 1;
                    auto data = extData.readBytes(length);

                    processRtpExtension(recvHeader, id, data);
                }
            }
            else if (extType == RTPEXT_LONG_GENERAL)
            {
                while (extData)
                {
                    auto id = (UINT16)extData.readByte();
                    if (id == 0)
                    {
                        extData.read();
                        continue;
                    }
                    auto length = extData.readByte();
                    auto data = extData.readBytes(length);

                    processRtpExtension(recvHeader, id, data);
                }
            }
            else
            {
                DBGBREAK();
                processRtpExtension(recvHeader, extType, extData);
            }
        }

        DBGBREAK();
        authData.setLength(authData.length() - recvData.length());
        auto payload = srtpCipher.decryptRTP(recvData.toRWBuffer(), authData, recvHeader.ssrc, seqNumber);
        if (payload)
        {
            ASSERT(recvHeader.mid);

            RTP_HEADER sendHeader;
            sendHeader.mid = recvHeader.mid;
            sendHeader.rid = recvHeader.rid;
            sendHeader.timeStamp = recvHeader.timeStamp;
            sendHeader.isMarkerSet = recvHeader.isMarkerSet;

            if (videoReceiver.mid == recvHeader.mid)
            {
                parseVideoStream(recvHeader, payload);
                sendHeader.ssrc = videoSender.ssrc;
            }
            else if (audioReceiver.mid == recvHeader.mid)
            {
                parseAudioStream(recvHeader, payload);
                sendHeader.ssrc = audioSender.ssrc;
            }
            else DBGBREAK();

            shaper.sendPacket([](SRTP_DATASTREAM& rtpStream, WEBRTC_SESSION& session, RTP_HEADER& header, BUFFER payload)
                {
                    session.formatRTPheader(header, rtpStream);
                    auto authData = rtpStream.toBuffer();

                    auto payloadStart = rtpStream.getPosition();
                    rtpStream.writeBytes(payload);
                    auto payloadData = payloadStart.toBuffer();

                    session.srtpCipher.encryptRTP(rtpStream, authData, payloadData.toRWBuffer(), header.ssrc);

                }, *this, sendHeader, payload);
        }
    }

    void parseRtcpPacket(BUFFER recvData)
    {
        auto fixedHeader = recvData.readBytes(8);
        auto authData = fixedHeader;

        RTCP_FLAGS rtcpFlags{ fixedHeader.beReadU16() };
        auto recordCount = rtcpFlags.getRecordCount();
        UNREFERENCED_PARAMETER(recordCount);
        auto packetType = rtcpFlags.getPacketType();
        UNREFERENCED_PARAMETER(packetType);
        auto recordLength = fixedHeader.beReadU16();
        UNREFERENCED_PARAMETER(recordLength);

        auto ssrc = fixedHeader.beReadU32();

        auto trailer = recvData.shrink(sizeof(UINT32));
        auto recvIndex = trailer.beReadU32();

        auto isEncrypted = !!(recvIndex & 0x80000000);
        recvIndex &= 0x7FFFFFF;

        recvData = isEncrypted ? srtpCipher.decryptRTCP(recvData.toRWBuffer(), authData, ssrc, recvIndex) : recvData;
        if (recvData)
        {
            // process data
        }
    }

    void parseTurnMessage(BUFFER recvData)
    {
        UNREFERENCED_PARAMETER(recvData);
    }

    void onSocketClose()
    {
        for (auto& transport : networkTransports.toRWBuffer())
        {
            transport.close();
        }
        // clear the current session.
    }
};
