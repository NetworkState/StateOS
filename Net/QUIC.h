
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

// QUIC protocol implementation

#include "QPACKET.h"

constexpr static UINT8 QTP_original_destination_connection_id = 0;
constexpr static UINT8 QTP_max_idle_timeout = 1;
constexpr static UINT8 QTP_stateless_reset_token = 2;
constexpr static UINT8 QTP_max_udp_payload_size = 3;
constexpr static UINT8 QTP_initial_max_data = 4;
constexpr static UINT8 QTP_initial_max_stream_data_bidi_local = 5;
constexpr static UINT8 QTP_initial_max_stream_data_bidi_remote = 6;
constexpr static UINT8 QTP_initial_max_stream_data_uni = 7;
constexpr static UINT8 QTP_initial_max_streams_bidi = 8;
constexpr static UINT8 QTP_initial_max_streams_uni = 9;
constexpr static UINT8 QTP_ack_delay_exponent = 10;
constexpr static UINT8 QTP_max_ack_delay = 11;
constexpr static UINT8 QTP_disable_active_migration = 12;
constexpr static UINT8 QTP_preferred_address = 13;
constexpr static UINT8 QTP_active_connection_id_limit = 14;
constexpr static UINT8 QTP_initial_source_connection_id = 15;
constexpr static UINT8 QTP_retry_source_connection_id = 16;

constexpr static UINT32 QERR_QUIC_NO_ERROR = 0;
constexpr static UINT32 QERR_INTERNAL_ERROR = 1;
constexpr static UINT32 QERR_CONNECTION_REFUSED = 2;
constexpr static UINT32 QERR_FLOW_CONTROL_ERROR = 3;
constexpr static UINT32 QERR_STREAM_LIMIT_ERROR = 4;
constexpr static UINT32 QERR_STREAM_STATE_ERROR = 5;
constexpr static UINT32 QERR_FINAL_SIZE_ERROR = 6;
constexpr static UINT32 QERR_FRAME_ENCODING_ERROR = 7;
constexpr static UINT32 QERR_TRANSPORT_PARAMETER_ERROR = 8;
constexpr static UINT32 QERR_CONNECTION_ID_LIMIT_ERROR = 9;
constexpr static UINT32 QERR_PROTOCOL_VIOLATION = 10;
constexpr static UINT32 QERR_INVALID_TOKEN = 11;
constexpr static UINT32 QERR_APPLICATION_ERROR = 12;
constexpr static UINT32 QERR_CRYPTO_BUFFER_EXCEEDED = 13;
constexpr static UINT32 QERR_KEY_UPDATE_ERROR = 14;
constexpr static UINT32 QERR_AEAD_LIMIT_REACHED = 15;
constexpr static UINT32 QERR_NO_VIABLE_PATH = 16;
constexpr static UINT32 QERR_CRYPTO_ERROR = 0x100;

template <UINT32 SZ>
struct PACKET_MAP
{
    constexpr static UINT32 ACK_DELAY_EXPONENENT = 3;
    LOCAL_STREAM<512> ackRangeStream;
    bool isDirty = false;
    UINT32 gapCount = 0;

    UINT64 lastReceived = 0;
    UINT64 lastACK = 0;
    UINT64 lastNACK = 0;
    UINT64 recvTimestamp = 0;

    PACKET_MAP()
    {
        ASSERT(_mm_popcnt_u32(SZ) == 1);
        ASSERT((SZ & 0x3F) == 0);
    }

    UINT32 mask = SZ / 64 - 1;
    UINT64 _data[SZ / 64] = { 0 };

    UINT64& offset(UINT64 index)
    {
        ASSERT(index < SZ);
        return _data[index >> 6];
    }

    UINT64 MASKBIT(UINT64 index)
    {
        return ROR64(1, (index & 0x3F) + 1);
    }

    void update(UINT64& offset, UINT64 value)
    {
        if (offset != value)
            isDirty = true;
        offset = value;
    }

    void set(UINT64 index)
    {
        auto&& value = offset(index);
        update(value, value | MASKBIT(index));
    }

    void clear(UINT64 index)
    {
        auto&& value = offset(index);
        update(value, value & ~MASKBIT(index));
    }

    UINT64 readBits(UINT64 packetNumber)
    {
        UINT8 firstBits = packetNumber & 0x3F;
        UINT8 secondBits = 64 - firstBits;

        UINT64 first = _data[packetNumber >> 6] >> (64 - firstBits);
        UINT64 second = (packetNumber > 64) ? second = ROR64((_data[(packetNumber >> 6) - 1] & MASK(secondBits)), secondBits) : 0;

        return first | second;
    }

    void buildAckRange(UINT64 latest)
    {
        gapCount = 0;
        ackRangeStream.clear();
        UINT64 rangeEnd = latest > SZ ? latest - SZ : 0;
        UINT64 gapStart = 0, ackStart = latest;
        for (UINT64 packetNumber = latest; packetNumber > rangeEnd; packetNumber -= min(64, packetNumber))
        {
            auto bits = readBits(packetNumber);
            UINT64 gapBit = 1;
            for (;;)
            {
                if (gapStart > 0)
                {
                    bits = bits ^ ((bits << 1) | gapBit);
                    if (auto ackBit = _blsi_u64(bits))
                    {
                        ackStart = packetNumber - _tzcnt_u64(ackBit);
                        ackRangeStream.writeQInt(gapStart - ackStart);
                        gapCount++;
                        gapStart = 0;
                    }
                }
                else if (gapBit = _blsi_u64(bits))
                {
                    gapStart = packetNumber - _tzcnt_u64(gapBit);
                    if (gapCount == 0)
                        lastNACK = gapStart;
                    else
                        ackRangeStream.writeQInt(ackStart - gapStart);
                    ackStart = 0;
                }
                else break;
            }
        }
        if (ackStart > 0)
        {
            ackRangeStream.writeQInt(ackStart - rangeEnd);
        }
    }

    void formatAckFrame(BYTESTREAM& frameStream)
    {
        return; // XXX Remove!!!
        if (recvTimestamp == 0)
            return;

        if (isDirty)
        {
            buildAckRange(lastReceived);
            isDirty = false;
        }
        frameStream.writeByte(FRAMETYPE_ACK);
        frameStream.writeQInt(lastReceived);
        frameStream.writeQInt((GetUptimeUS() - recvTimestamp) >> ACK_DELAY_EXPONENENT);
        frameStream.writeQInt(gapCount);
        frameStream.writeQInt(lastReceived - lastNACK);
        frameStream.writeBytes(ackRangeStream.toBuffer());

        recvTimestamp = 0;
    }

    void acceptPacket(UINT64 packetNumber)
    {
        recvTimestamp = GetUptimeUS();
        clear(packetNumber);
        for (UINT64 i = lastReceived + 1; i < packetNumber; i++)
        {
            set(i);
        }
        lastReceived = packetNumber;
    }
};

inline BUFFER readVarQData(BUFFER& recvData)
{
    auto length = (UINT32)recvData.readQInt();
    return recvData.readBytes(length);
}

template <typename SERVICE>
struct UDP_SOCKET
{
    SOCKET socketHandle;
    IPENDPOINT localAddress;
    IPENDPOINT remoteAddress;
    PVOID clientSession;

    SERVICE& service;

    OVERLAPPED overlap;
    STASK task;
    PADDRINFOEX addrInfo;

    UDP_SOCKET(SERVICE& service) : service(service) {}

    NTSTATUS createSocket(UINT16 listenPort = 0)
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            socketHandle = WSASocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (socketHandle == INVALID_SOCKET) break;

            IPENDPOINT bindAddress{ INADDR_ANY, listenPort };
            auto result = bind(socketHandle, bindAddress.addressC(), SOCKADDR_LEN);
            if (result == SOCKET_ERROR) break;

            int addrLen = SOCKADDR_LEN;
            result = getsockname(socketHandle, localAddress.addressC(), &addrLen);
            if (result == SOCKET_ERROR) break;

            service.getScheduler().registerHandle(HANDLE(socketHandle), PVOID(this));
            status = STATUS_SUCCESS;
        } while (false);

        return status;
    }

    NTSTATUS init(UINT16 port)
    {
        return createSocket(port);
    }

    template <typename FUNC>
    NTSTATUS init(BUFFER hostname, UINT16 port, FUNC&& callback, auto&& ... args)
    {
        NEW(task, callback, args ...);
        remoteAddress = IPENDPOINT(INADDR_ANY, port);

        ZeroMemory(&overlap, sizeof(OVERLAPPED));
        auto result = GetAddrInfoEx(hostname.toWideString(), nullptr, NS_DNS, nullptr, &DnsResolverHints, &addrInfo, nullptr, &overlap,
            [](DWORD errorCode, DWORD, LPWSAOVERLAPPED overlapPtr)
            {
                auto status = NTSTATUS_FROM_WIN32(errorCode);
                auto&& udpSocket = *(CONTAINING_RECORD(overlapPtr, UDP_SOCKET, overlap));
                if (errorCode == 0)
                {
                    auto addrInfo = udpSocket.addrInfo;
                    ASSERT(addrInfo != nullptr);
                    ASSERT(addrInfo->ai_family == PF_INET);
                    ASSERT(addrInfo->ai_addrlen == sizeof(SOCKADDR_IN));
                    udpSocket.remoteAddress._address.sin_addr = ((LPSOCKADDR_IN)addrInfo->ai_addr)->sin_addr;
                    FreeAddrInfoEx(addrInfo);

                    status = udpSocket.createSocket();
                }
                else DBGBREAK();
                udpSocket.service.runTask(udpSocket.task, status);
            }, nullptr);

        return STATUS_SUCCESS;
    }

    void beginReceive()
    {
        auto&& recvPacket = service.allocPacket();

        NEW(recvPacket.ioState, IO_SOCK_RECV);
        NEW(recvPacket.ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto&& socket = *(UDP_SOCKET*)context;
                if (NT_SUCCESS(result))
                {
                    auto&& recvPacket = *argv.read<PQPACKET>(0);
                    auto bytesReceived = argv.read<DWORD>(1);
                    recvPacket.frameStream.setCount(bytesReceived);

                    socket.service.onSocketReceive(socket, recvPacket);
                }
                else DBGBREAK();
                socket.beginReceive();
            }, this, &recvPacket);

        DWORD bytesReceived = 0, flags = 0;
        WSABUF buf = recvPacket.recvBuf;
        auto result = WSARecvFrom(socketHandle, &buf, 1, &bytesReceived, &flags, recvPacket.recvFrom.addressC(), &recvPacket.recvFromLength, recvPacket.ioState.start(), nullptr);
        if (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING)
            DebugBreak();
    }

    void close()
    {
        closesocket(socketHandle);
        socketHandle = INVALID_SOCKET;
    }

    bool isClosed() { return socketHandle != INVALID_SOCKET; }
};

constexpr static UINT32 RETRY_TOKEN_DIGEST_SIZE = 16;
constexpr static UINT32 RETRY_CID_LENGTH = 16;
constexpr static UINT32 RETRY_KEY_LENGTH = RETRY_TOKEN_DIGEST_SIZE + RETRY_CID_LENGTH + MAX_CID_LENGTH;
using RETRY_KEY = UINT8[RETRY_KEY_LENGTH];

struct QUIC_RETRY
{
    constexpr static HEXSTRING RETRY_PACKET_KEY = "be0c690b9f66575a1d766b54e368c84e";
    constexpr static HEXSTRING RETRY_PACKET_IV = "461599d35d632bf2239825bb";

    AES_GCM retryCipher; // { RETRY_PACKET_KEY, RETRY_PACKET_IV };
    GMAC retryGMAC;

    void init()
    {
        retryCipher.init(RETRY_PACKET_KEY, RETRY_PACKET_IV);
        retryGMAC.init(Random.getBytes(32), "QUIC retry");
    }

    BUFFER generateRetryToken(QPACKET& recvPacket, QUIC_HEADER& recvHeader)
    {
        LOCAL_STREAM<64> keyStream;
        keyStream.beWriteU32(recvPacket.recvFrom._address.sin_addr.s_addr);
        keyStream.beWriteU16(recvPacket.recvFrom._address.sin_port);
        keyStream.writeBytes(recvHeader.sourceCID);

        return retryGMAC.keyGen(keyStream.toBuffer(), ByteStream(ROUND16(RETRY_KEY_LENGTH)));
    }

    void sendRetryPacket(SOCKET socketHandle, QPACKET& recvPacket, QUIC_HEADER& recvHeader)
    {
        auto tokenData = generateRetryToken(recvPacket, recvHeader);
        auto tokenDestCID = (PUINT8)tokenData.data(RETRY_TOKEN_DIGEST_SIZE + RETRY_CID_LENGTH);
        for (UINT32 i = 0; i < recvHeader.destinationCID.length(); i++)
        {
            tokenDestCID[i] ^= recvHeader.destinationCID.at(i);
        }

        LOCAL_STREAM<32> virtualHeader;
        virtualHeader.writeByte(recvHeader.destinationCID.length());
        virtualHeader.writeBytes(recvHeader.destinationCID);

        LOCAL_STREAM<128> sendStream;
        sendStream.writeByte(PACKET_RETRY);
        sendStream.beWriteU32(QUIC_VERSION);

        sendStream.writeByte(recvHeader.sourceCID.length());
        sendStream.writeBytes(recvHeader.sourceCID);

        sendStream.writeByte(RETRY_CID_LENGTH); // token data starts with source CID
        auto cidTokenBytes = tokenData.readBytes(RETRY_CID_LENGTH + RETRY_TOKEN_DIGEST_SIZE + recvHeader.destinationCID.length());
        sendStream.writeBytes(cidTokenBytes);

        U128 tag;
        retryCipher.hash(tag, virtualHeader.toBuffer(), sendStream.toBuffer());
        sendStream.writeBytes(tag.u8);

        WSABUF sendBuf{ sendStream.count(), (CHAR*)sendStream.address() };
        DWORD bytesSent;
        auto error = WSASendTo(socketHandle, &sendBuf, 1, &bytesSent, 0, (sockaddr*)&recvPacket.recvFrom, sizeof(recvPacket.recvFrom),
            nullptr, nullptr);
        ASSERT(error != SOCKET_ERROR);
    }

    BUFFER decryptRetryPacket(QPACKET& packet, BUFFER initialDestCID)
    {
        ASSERT(packet.recvHeader.headerLength > 0);

        LOCAL_STREAM<32> virtualHeader;
        virtualHeader.writeByte(initialDestCID.length());
        virtualHeader.writeBytes(initialDestCID);

        auto recvData = packet.frameStream.toBuffer();
        auto recvTag = recvData.shrink(AES_TAG_LENGTH);

        U128 tag;
        retryCipher.hash(tag, virtualHeader.toBuffer(), recvData);

        auto match = RtlCompareMemory(tag.u8, recvTag.data(), 16);
        ASSERT(match == 16);

        packet.headerStream.fromBuffer(recvData.readBytes((UINT32)packet.recvHeader.headerLength));
        packet.frameStream.fromBuffer(recvData);

        return recvData;
    }

    BUFFER getDestCIDfromToken(QPACKET& recvPacket)
    {
        auto&& recvHeader = recvPacket.recvHeader;
        ASSERT(recvHeader.retryToken);

        BUFFER recvToken = recvHeader.retryToken;
        recvToken.shift(RETRY_TOKEN_DIGEST_SIZE);

        auto retryData = generateRetryToken(recvPacket, recvPacket.recvHeader);
        retryData.shift(RETRY_TOKEN_DIGEST_SIZE + RETRY_CID_LENGTH);

        auto destCID = retryData.readBytes(recvToken.length()).toRWBuffer();
        for (UINT32 i = 0; i < destCID.length(); i++)
        {
            destCID[i] ^= recvToken[i];
        }
        return destCID.toBuffer();
    }

    bool validateToken(QPACKET& recvPacket, QUIC_HEADER& quicHeader)
    {
        auto result = false;
        auto retryData = generateRetryToken(recvPacket, quicHeader);
        if (quicHeader.recvToken)
        {
            BUFFER recvToken = quicHeader.recvToken;
            if ((quicHeader.destinationCID == retryData.readBytes(RETRY_CID_LENGTH)) &&
                (recvToken.readBytes(RETRY_TOKEN_DIGEST_SIZE) == retryData.readBytes(RETRY_TOKEN_DIGEST_SIZE)))
            {
                result = true;
                quicHeader.retryToken = quicHeader.recvToken;
            }
        }
        return result;
    }
};

template <typename SERVICE, typename APP_SESSION/*, bool IS_SERVER*/>
struct QUIC_SESSION
{
    using QUIC_SOCKET = UDP_SOCKET<SERVICE>;
    constexpr static HEXSTRING HKDF_SALT = "38762cf7f55934b34d179ae6a4c80cadccbb7f0a";

    template <UINT32 RECV_MAP_SIZE>
    struct QUIC_CIPHER
    {
        UINT64 sendPacketNumber = 0;
        UINT64 recvPacketNumber = 0;

        AES_GCM sendKey, recvKey;
        AES_ECB headerSendKey, headerRecvKey;

        PQPACKET retransmitQueue = nullptr;
        PQPACKET receiveQueue = nullptr;

        PACKET_MAP<RECV_MAP_SIZE> recvPacketMap;

        QUIC_CIPHER(QUIC_SESSION& session) {}

        NTSTATUS init()
        {
            return STATUS_SUCCESS;
        }

        void deriveKeys(HKDF& kdf, bool isServer, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
        {
            NEW(sendKey); NEW(recvKey); NEW(headerSendKey); NEW(headerRecvKey);
            auto key = kdf.deriveKey(clientSecret, "quic key", NULL_BUFFER, ByteStream(keySize));
            isServer ? recvKey.setKey(key) : sendKey.setKey(key);

            key = kdf.deriveKey(clientSecret, "quic hp", NULL_BUFFER, ByteStream(keySize));
            isServer ? headerRecvKey.setKey(key) : headerSendKey.setKey(key);

            kdf.deriveKey(clientSecret, "quic iv", NULL_BUFFER, BYTESTREAM(isServer ? recvKey.salt : sendKey.salt));

            key = kdf.deriveKey(serverSecret, "quic key", NULL_BUFFER, ByteStream(keySize));
            isServer ? sendKey.setKey(key) : recvKey.setKey(key);

            key = kdf.deriveKey(serverSecret, "quic hp", NULL_BUFFER, ByteStream(keySize));
            isServer ? headerSendKey.setKey(key) : headerRecvKey.setKey(key);

            kdf.deriveKey(serverSecret, "quic iv", NULL_BUFFER, BYTESTREAM(isServer ? sendKey.salt : recvKey.salt));
        }

        void updateKeys(HKDF& kdf, bool isServer, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
        {
            NEW(sendKey); NEW(recvKey);

            auto key = kdf.deriveKey(clientSecret, "quic key", NULL_BUFFER, ByteStream(keySize));
            isServer ? recvKey.setKey(key) : sendKey.setKey(key);

            kdf.deriveKey(clientSecret, "quic iv", NULL_BUFFER, BYTESTREAM(isServer ? recvKey.salt : sendKey.salt));

            key = kdf.deriveKey(serverSecret, "quic key", NULL_BUFFER, ByteStream(keySize));
            isServer ? sendKey.setKey(key) : recvKey.setKey(key);

            kdf.deriveKey(serverSecret, "quic iv", NULL_BUFFER, BYTESTREAM(isServer ? sendKey.salt : recvKey.salt));
        }

        void encrypt(QPACKET& sendBuf)
        {
            ASSERT(sendKey);
            auto packetData = sendBuf.frameStream.toRWBuffer();
            ASSERT(packetData.length() >= 18);

            sendBuf.packetNumber = sendPacketNumber++;
            auto&& headerByte = sendBuf.headerStream.at(0);
            // 4 bytes for packet length
            headerByte = (headerByte & 0xFC) | 0x03;

            auto numberPtr = sendBuf.headerStream.end();
            sendBuf.headerStream.beWriteU32(UINT32(sendBuf.packetNumber));

            AES_GCM_IV ivData;
            ivData.setU32(0, SWAP32(sendBuf.packetNumber >> 32), SWAP32(sendBuf.packetNumber));

            sendKey.encrypt(ivData, sendBuf.headerStream.toBuffer(), packetData, sendBuf.gcmTag);

            U128 cipherSample;
            RtlCopyMemory(cipherSample.u8, packetData.data(), AES_BLOCK_SIZE);

            headerSendKey.encrypt(cipherSample);

            UINT8 mask = (headerByte & 0x80) ? 0x0F : 0x1F;
            headerByte = (headerByte & ~mask) | (headerByte & mask) ^ (cipherSample.u8[0] & mask);

            numberPtr[0] ^= cipherSample.u8[1];
            numberPtr[1] ^= cipherSample.u8[2];
            numberPtr[2] ^= cipherSample.u8[3];
            numberPtr[3] ^= cipherSample.u8[4];
        }

        void sendPacket(QPACKET& sendPacket, SOCKET sendSocket, IPENDPOINT& remoteIP)
        {
            encrypt(sendPacket);
            sendPacket.insertToQueue(&retransmitQueue);
            sendPacket.sendTo(sendSocket, remoteIP);
        }

        void unEncrypt(QPACKET& retransmitBuf)
        {
            auto packetNumber = retransmitBuf.packetNumber;

            AES_GCM_IV ivData;
            ivData.setU32(0, SWAP32(packetNumber >> 32), SWAP32(packetNumber));
            sendKey.encrypt(ivData, retransmitBuf.headerStream.toBuffer(), retransmitBuf.frameStream.toRWBuffer(), retransmitBuf.gcmTag);

            retransmitBuf.headerStream.clear();
        }

        BUFFER decrypt(QPACKET& recvBuf)
        {
            ASSERT(recvKey);
            auto packetData = recvBuf.frameStream.toRWBuffer();
            auto&& headerByte = *packetData.data();

            auto headerLength = recvBuf.recvHeader.headerLength;

            U128 cipherSample;
            RtlCopyMemory(cipherSample.u8, packetData.data(headerLength + 4), AES_BLOCK_SIZE);
            headerRecvKey.encrypt(cipherSample);

            UINT8 mask = (headerByte & 0x80) ? 0x0F : 0x1F;
            headerByte = (headerByte & ~mask) | ((headerByte & mask) ^ (cipherSample.u8[0] & mask));

            if (headerByte & HEADER_KEY_PHASE)
                DBGBREAK(); // do a key update

            UINT8 packetNumberBytes = (headerByte & 0x03) + 1;
            auto numberData = packetData.data(headerLength);

            UINT64 packetNumber = 0;
            for (UINT8 i = 0; i < packetNumberBytes; i++)
            {
                numberData[i] ^= cipherSample.u8[i + 1];
                packetNumber = (packetNumber << 8) | numberData[i];
            }

            UINT64 numberMask = 0 - (1ull << (packetNumberBytes * 8));
            recvBuf.packetNumber = (recvPacketNumber & numberMask) | packetNumber;

            recvPacketMap.acceptPacket(recvBuf.packetNumber);

            auto aad = packetData.readBytes(headerLength + packetNumberBytes).toBuffer();
            BUFFER result = packetData.toBuffer();
            ASSERT(recvKey);

            AES_GCM_IV ivData;
            ivData.setU32(0, SWAP32(packetNumber >> 32), SWAP32(packetNumber));

            result = recvKey.decrypt(ivData, aad, packetData);
            ASSERT(result);
            if (result)
            {
                recvBuf.frameStream.fromBuffer(result);
                recvBuf.headerStream.fromBuffer(aad);
            }

            return result;
        }
    };

    UINT16 getPacketSize(bool shortHeader = true) 
    { 
        return shortHeader ? sendMTU - (destinationCID.count() + AES_TAG_LENGTH + 5) : 1200 - 48; 
    }

    UINT8 GetQIntBytes(UINT64 value)
    {
        auto bits = 64 - _lzcnt_u64(value);
        return bits <= 6 ? 1 :
            bits <= 14 ? 2 :
            bits <= 30 ? 4 : 8;
    };
    constexpr static UINT32 FLAG_IS_CLOSED = 0x02;

    constexpr static UINT32 FLAG_INIT_RECEIVED = 0x04;
    constexpr static UINT32 FLAG_INIT_SENT = 0x08;

    constexpr static UINT32 FLAG_HANDSHAKE_RECEIVED = 0x10;
    constexpr static UINT32 FLAG_HANDSHAKE_SENT = 0x20;

    constexpr static UINT32 FLAG_IS_READY = 0x100;

    constexpr static UINT32 MAX_CID = 20;

    UINT32 flags = FLAG_IS_CLOSED;

    void close()
    {
        udpSocket.close();
        RtlZeroMemory(sourceCID, sizeof(sourceCID));
        flags = FLAG_IS_CLOSED; 
    };

    inline bool isClosed() { return flags & FLAG_IS_CLOSED; }
    explicit operator bool() const { return !isClosed(); }

    SESSION_STACK sessionStack;
    SERVICE& service;
    APP_SESSION appSession;

    UINT8 sourceCID[LOCAL_CID_LENGTH]{ 0 };

    LOCAL_STREAM<MAX_CID> initialDestCID;
    LOCAL_STREAM<MAX_CID> retrySourceCID;
    LOCAL_STREAM<MAX_CID> remoteSourceCID;

    UINT32 idleTimeout = 30000;

    UINT8 remoteAckDelayExponent = 3;

    UINT16 localMaxAckDelayTime = 25; // milliseconds
    UINT16 remoteMaxAckDelayTime = 25; // milliseconds

    using CONTROL_CIPHER = QUIC_CIPHER<128>;
    using APP_CIPHER = QUIC_CIPHER<256 * 1024>;

    CONTROL_CIPHER initCipher;
    CONTROL_CIPHER handshakeCipher;
    APP_CIPHER appCipher;

    UINT16 sendMTU = 1472;
    bool isServer;

    QPACKET* recvQueue;
    TLS13_HANDSHAKE<QUIC_SESSION> tlsHandshake;

    UINT64 recvCount, recvCredit;
    UINT64 sendCount, sendCredit;

    PDATAFRAME dataFramePool = nullptr;
    STREAM_LIMITS streamLimits;

    QUIC_SOCKET& udpSocket;
    QUIC_SESSION(SERVICE& service, QUIC_SOCKET& udpSocket, bool isServer, auto&& ... args) : isServer(isServer), udpSocket(udpSocket), service(service), initCipher(*this), handshakeCipher(*this), 
        appCipher(*this), tlsHandshake(*this, isServer), appSession(args ...), streamLimits(isServer)
    {
    }

    void allocDataFramePool(UINT32 poolSize)
    {
        ASSERT(dataFramePool == nullptr);
        PDATAFRAME list = (PDATAFRAME)StackAlloc<SESSION_STACK>(poolSize * sizeof(DATAFRAME));
        for (UINT32 i = 0; i < poolSize; i++)
        {
            auto frame = &list[i];
            frame->next = dataFramePool;
            dataFramePool = frame;
        }
    }

    DATAFRAME& allocDataFrame(QPACKET& packet, UINT64 streamId, UINT8 frameType,UINT64 streamOffset)
    {
        if (dataFramePool == nullptr)
            allocDataFramePool(512);

        packet.addRefCount();

        auto&& frame = *dataFramePool;
        dataFramePool = frame.next;
        NEW(frame, packet, streamId, frameType, streamOffset);
        return frame;
    }

    void releaseDataFrame(DATAFRAME& frame)
    {
        frame.packet.releaseRefCount();
        frame.next = dataFramePool;
        dataFramePool = &frame;
    }

    void clearDataframeQueue(PDATAFRAME* queue)
    {
        for (PDATAFRAME nextFrame = *queue; nextFrame;)
        {
            auto frame = nextFrame;
            nextFrame = nextFrame->next;
            if (frame->dataBuf.length() == 0)
            {
                REMOVE_DLINK(queue, *frame);
                releaseDataFrame(*frame);
            }
        }
    }

    void init()
    {
        sessionStack.init(256 * 1024);
        SetSessionStack(sessionStack);

        Random.getBytes(sourceCID);
        appSession.init();
        initCipher.init();
        handshakeCipher.init();
        appCipher.init();
        allocDataFramePool(1024);
    }

    static void reset(QUIC_SESSION& session, SERVICE& service, QUIC_SOCKET& udpSocket, bool isServer, auto&& ... args)
    {
        session.sessionStack.free();
        NEW(session, service, udpSocket, isServer, args...);
        session.init();
    }

    template <typename ... ARGS>
    void runTask(TASK_HANDLER handler, ARGS&& ... args)
    {
        service.scheduler.runTask(sessionStack, handler, (PVOID)this, args ...);
    }

    template <typename ... ARGS>
    void createTask(STASK& task, TASK_HANDLER handler, ARGS&& ... args)
    {
        new (&task) STASK(sessionStack, handler, (PVOID)this, args ...);
    }

    static inline QUIC_SESSION& GetSession()
    {
        auto&& sessionStack = GetSessionStack();
        auto session = CONTAINING_RECORD(&sessionStack, QUIC_SESSION, sessionStack);
        return *session;
    }

    BUFFER getServerName()
    {
        return NameToString(tlsHandshake.serverName);
    }

    BUFFER getTLScert()
    {
        return SystemService().AKsignKey.certBytes;
    }

    void parseStreamFrame(QPACKET& packet, UINT8 frameType, BUFFER& recvData)
    {
        ASSERT(IS_STREAM(frameType));
        auto streamFlags = frameType & FRAMETYPE_STREAM_FLAGS;

        auto streamId = recvData.readQInt();
        auto streamOffset = (streamFlags & FRAMETYPE_STREAM_FLAG_OFFSET) ? recvData.readQInt() : 0;

        auto&& frame = allocDataFrame(packet, streamId, frameType, streamOffset);
        
        auto dataLength = (streamFlags & FRAMETYPE_STREAM_FLAG_LENGTH) ? (UINT32)recvData.readQInt() : recvData.length();
        frame.dataBuf = recvData.readBytes(dataLength).rebase();

        ASSERT(dataLength > 0 || frame.endOfStream());

        appSession.onRecvStreamFrame(frame);
    }

    void parseCryptoFrame(QPACKET& packet, BUFFER& recvData)
    {
        auto offset = recvData.readQInt();
        auto length = (UINT32)recvData.readQInt();

        auto&& frame = allocDataFrame(packet, 0, FRAMETYPE_CRYPTO, offset);
        frame.dataBuf = recvData.readBytes(length).rebase();

        tlsHandshake.onQuicFrame(frame);
    }

    void processRecvPackets()
    {
        for (auto buf = recvQueue; buf; buf = buf->next)
        {

            auto headerData = buf->headerStream.toBuffer();
            auto packetType = GetPacketType(headerData.peek());

            if (packetType == PACKET_INITIAL)
            {

            }
        }
    }

    void skipPadding(BUFFER& packetData)
    {
        while (packetData && packetData.peek() == 0)
        {
            packetData.shift();
        }
    }

    PQPACKET findPacket(PQPACKET queueHead, UINT64 packetNumber)
    {
        for (auto current = queueHead; current; current = current->next)
        {
            if (current->packetNumber == packetNumber)
            {
                return current;
            }
        }
        return nullptr;
    }

    void handleAckRange(PQPACKET* retransmitQueue, UINT64 from, UINT64 to)
    {
        for (UINT64 i = from; i <= to; i++)
        {
            if (auto buf = findPacket(*retransmitQueue, i))
            {
                // tell the service
                buf->removeFromQueue(retransmitQueue);
            }
        }
    }

    void handleGapRange(PQPACKET* retransmitQueue, UINT64 from, UINT64 to)
    {
        for (UINT64 i = from; i <= to; i++)
        {
            if (auto buf = findPacket(*retransmitQueue, i))
            {
                // tell the service
                buf->removeFromQueue(retransmitQueue);
            }
        }
    }

    template <typename CIPHER>
    void parseACKframe(CIPHER& cipher, UINT8 frameType, BUFFER& recvData)
    {
        auto latest = recvData.readQInt();
        auto delay = recvData.readQInt();
        auto rangeCount = recvData.readQInt();
        auto smallest = latest - recvData.readQInt();

        for (UINT32 i = 0; i < rangeCount; i++)
        {
            auto gapCount = recvData.readQInt();
            handleGapRange(&cipher.retransmitQueue, smallest - gapCount, smallest);
            smallest -= gapCount;

            auto ackCount = recvData.readQInt();
            handleAckRange(&cipher.retransmitQueue, smallest - ackCount, smallest);
            smallest -= ackCount;
        }

        if (frameType == FRAMETYPE_ACK_ECN)
        {
            DBGBREAK();
            recvData.readQInt();
            recvData.readQInt();
            recvData.readQInt();
        }
    }

    void parseAppFrames(QPACKET& recvBuf)
    {
        auto recvData = recvBuf.frameStream.toBuffer();
        while (recvData)
        {
            skipPadding(recvData);
            auto savedPosition = recvData.mark();
            auto frameType = recvData.readByte();
            if (frameType == FRAMETYPE_NEW_TOKEN)
            {
                auto newToken = readVarQData(recvData);
                // write code to save this token for future connections to this server
            }
            else if (IS_STREAM(frameType))
            {
                parseStreamFrame(recvBuf, frameType, recvData);
            }
            else if (frameType == FRAMETYPE_CRYPTO)
            {
                auto offset = recvData.readQInt();
                auto data = readVarQData(recvData);
                DBGBREAK();
            }
            else if (frameType == FRAMETYPE_STOP_SENDING)
            {
                auto streamId = recvData.readQInt();
                auto errorCode = recvData.readQInt();
                service.onStopSending(streamId, errorCode);
            }
            else if (frameType == FRAMETYPE_RESET_STREAM)
            {
                auto streamId = recvData.readQInt();
                auto errorCode = recvData.readQInt();
                auto finalSize = recvData.readQInt();
                service.onResetStream(streamId, errorCode, finalSize);
            }
            else if (frameType == FRAMETYPE_ACK || frameType == FRAMETYPE_ACK_ECN)
            {
                parseACKframe(appCipher, frameType, recvData);
            }
            else if (frameType == FRAMETYPE_PING)
            {
                // empty
            }
            else if (frameType == FRAMETYPE_MAX_DATA)
            {
                sendCredit = recvData.readQInt();
                service.onSetDataCredit(sendCredit);
            }
            else if (frameType == FRAMETYPE_MAX_STREAM_DATA)
            {
                auto streamId = recvData.readQInt();
                auto transmitCredit = recvData.readQInt();
                service.onSetDataCredit(streamId, transmitCredit);
            }
            else if (frameType == FRAMETYPE_MAX_STREAMS_BIDIR || frameType == FRAMETYPE_MAX_STREAMS_UNI)
            {
                auto maxStreams = recvData.readQInt();
                service.onSetStreamCredit(frameType == FRAMETYPE_MAX_STREAMS_BIDIR, maxStreams);
            }
            else if (frameType == FRAMETYPE_DATA_BLOCKED)
            {
                auto byteCount = recvData.readQInt();
                service.onOutOfDataCredits(byteCount);
            }
            else if (frameType == FRAMETYPE_STREAM_DATA_BLOCKED)
            {
                auto streamId = recvData.readQInt();
                auto byteCount = recvData.readQInt();
                service.onOutOfDataCredits(streamId, byteCount);
            }
            else if (frameType == FRAMETYPE_STREAMS_BLOCKED_BIDIR || frameType == FRAMETYPE_STREAMS_BLOCKED_UNI)
            {
                auto streamCount = recvData.readQInt();
                service.onOutOfStreamCredits(frameType == FRAMETYPE_STREAMS_BLOCKED_BIDIR, streamCount);
            }
            else if (frameType == FRAMETYPE_NEW_CONNECTION_ID)
            {
                auto index = recvData.readQInt();
                auto prior = recvData.readQInt();
                auto length = recvData.readByte();
                auto connectionId = recvData.readBytes(length);
                auto resetToken = recvData.readBytes(16);
                // start using new connection id.
            }
            else if (frameType == FRAMETYPE_RETIRE_CONNECTION_ID)
            {
                auto index = recvData.readQInt();
                // send a new connection id.
            }
            else if (frameType == FRAMETYPE_PATH_CHALLENGE)
            {
                recvData.readBytes(8);
            }
            else if (frameType == FRAMETYPE_PATH_RESPONSE)
            {
                recvData.readBytes(8);
            }
            else if (frameType == FRAMETYPE_CONNECTION_CLOSE_APP_ERROR || frameType == FRAMETYPE_CONNECTION_CLOSE_QUIC_ERROR)
            {
                auto errorCode = recvData.readQInt();
                if (frameType == FRAMETYPE_CONNECTION_CLOSE_QUIC_ERROR)
                    recvData.readQInt(); // frame type that caused error
                auto reason = readVarQData(recvData);

                service.onConnectionClose(frameType == FRAMETYPE_CONNECTION_CLOSE_APP_ERROR ? errorCode : 0, reason);
            }
            else if (frameType == FRAMETYPE_PATH_CHALLENGE)
            {
                // empty
            }
            else DBGBREAK();
        }
        appSession.forwardStreamFrames();
    }

    void onConnect(NTSTATUS result)
    {
        appSession.onConnect();
    }

    void generateHandshakeKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
        handshakeCipher.deriveKeys(kdf, isServer, clientSecret, serverSecret, keySize);
    }

    void generateMasterKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
        flags = FLAG_IS_READY;
        appCipher.deriveKeys(kdf, isServer, clientSecret, serverSecret, keySize);
    }

    void updateMasterKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
        appCipher.updateKeys(kdf, isServer, clientSecret, serverSecret, keySize);
    }

    void initCipherKeys(BUFFER destinationCID)
    {
        HKDF kdf;
        kdf.initialize(SHA256_HASH_LENGTH);
        kdf.extract(HKDF_SALT, destinationCID);

        auto clientSecret = kdf.deriveSecret("client in", NULL_BUFFER, ByteStream(SHA256_HASH_LENGTH));
        auto serverSecret = kdf.deriveSecret("server in", NULL_BUFFER, ByteStream(SHA256_HASH_LENGTH));

        initCipher.deriveKeys(kdf, isServer, clientSecret, serverSecret, AES128_KEY_LENGTH);
    }

    void parseControlPacket(CONTROL_CIPHER& cipher, QPACKET& recvPacket, BUFFER recvData)
    {
        while (recvData)
        {
            skipPadding(recvData);
            auto frameType = recvData.readByte();
            if (frameType == FRAMETYPE_CRYPTO)
            {
                parseCryptoFrame(recvPacket, recvData);
            }
            else if (frameType == FRAMETYPE_ACK)
            {
                parseACKframe(cipher, frameType, recvData);
            }
            else DBGBREAK();
        }
        tlsHandshake.parseQUICframes();
    }

    void onRecvCryptoFrames(QUIC_HEADER& recvHeader, MBUF_READER& mbuf)
    {
        tlsHandshake.parseQUICframes(recvHeader, mbuf);
    }

    void onRecvStreamFrames(UINT64 streamId, MBUF_READER& mbuf) { DBGBREAK(); }

    constexpr static UINT32 CONTROL_PACKET_MTU = 1200 - 48;
    QPACKET& allocSendPacket(UINT8 packetType = PACKET_1RTT)
    {
        auto&& packet = service.allocPacket();
        auto&& dataStream = packet.frameStream.clear();
        if (packetType == PACKET_1RTT)
        {
            dataStream.resize(sendMTU - (remoteSourceCID.count() + AES_TAG_LENGTH + 5));
            appCipher.recvPacketMap.formatAckFrame(dataStream);
        }
        else if (packetType == PACKET_INITIAL)
        {
            dataStream.resize(CONTROL_PACKET_MTU);
            initCipher.recvPacketMap.formatAckFrame(dataStream);
        }
        else if (packetType == PACKET_HANDSHAKE)
        {
            dataStream.resize(CONTROL_PACKET_MTU);
            handshakeCipher.recvPacketMap.formatAckFrame(dataStream);
        }
        else DBGBREAK();
        return packet;
    }

    QPACKET& allocPacketChain(PQPACKET* packetQueue)
    {
        auto firstPacket = *packetQueue == nullptr;
        auto&& packet = service.allocPacket();
        APPEND_LINK(packetQueue, packet);
        packet.frameStream.clear().resize(sendMTU - (remoteSourceCID.count() + AES_TAG_LENGTH + 5));
        
        if (firstPacket)
            appCipher.recvPacketMap.formatAckFrame(packet.frameStream);

        return packet;
    }

    template <typename FUNC, typename ... ARGS>
    void formatCryptoFrame(BYTESTREAM& outStream, UINT64& frameOffset, FUNC func, ARGS&& ... args)
    {
        outStream.writeByte(FRAMETYPE_CRYPTO);
        outStream.writeQInt(frameOffset);
        auto lengthOffset = outStream.saveOffset(2);
        func(outStream, args ...);
        frameOffset += lengthOffset.writeQLength();
    }

    template <typename FUNC, typename ... ARGS>
    QPACKET& sendCryptoFrame(UINT8 packetType, UINT64& frameOffset, FUNC func, ARGS&& ... args)
    {
        auto&& packet = allocSendPacket(packetType);
        auto&& dataStream = packet.frameStream;

        formatCryptoFrame(dataStream, frameOffset, func, args ...);

        return packet;
    }

    PUINT8 formatStreamFrame(BYTESTREAM& frameStream, STREAM_STATE& streamState, BYTESTREAM::OFFSET& lengthOffset)
    {
        auto framePtr = frameStream.end();
        frameStream.writeByte(FRAMETYPE_STREAM_LEN_OFF);
        frameStream.writeQInt(streamState.streamId);
        frameStream.writeQInt(streamState.sendOffset);
        NEW(lengthOffset, frameStream.saveOffset(2));
        return framePtr;
    }

    template <typename FUNC, typename ... ARGS>
    void formatStreamFrame(BYTESTREAM& frameStream, STREAM_STATE& streamState, FUNC func, ARGS&& ... args)
    {
        frameStream.writeByte(FRAMETYPE_STREAM_LEN_OFF);
        frameStream.writeQInt(streamState.streamId);
        frameStream.writeQInt(streamState.sendOffset);
        auto lengthOffset = frameStream.saveOffset(2);
        func(frameStream, args ...);
        streamState.sendOffset += lengthOffset.writeQLength();
    }

    template <typename FUNC, typename ... ARGS>
    QPACKET& sendStreamFrame(STREAM_STATE& streamState, FUNC func, ARGS&& ... args)
    {
        auto&& packet = allocSendPacket();
        formatStreamFrame(packet.frameStream, streamState, func, args...);
        return packet;
    }

    void sendPacket(QPACKET& packet, UINT8 packetType = PACKET_1RTT, BUFFER token = NULL_BUFFER)
    {
        if (packetType == PACKET_INITIAL)
        {
            auto destCID = retrySourceCID ? retrySourceCID.toBuffer() : initialDestCID.toBuffer();
            ASSERT(isServer || destCID);

            if (!destCID) destCID = remoteSourceCID.toBuffer();

            // make room for possibly largeer token!
            auto spaceLeft = packet.frameStream.spaceLeft();
            packet.headerStream.setAddress((PUINT8)StackAlloc<SESSION_STACK>(spaceLeft), spaceLeft);

            auto&& headerStream = initHeader(packet, PACKET_INITIAL, destCID, sourceCID);

            auto tokenOffset = headerStream.saveOffset(2);
            if (token)
            {
                headerStream.writeBytes(token);
            }
            else
            {
                service.generateToken(headerStream, sourceCID, destCID, getServerName());
            }
            tokenOffset.writeQLength();

            headerStream.writeQInt(packet.frameStream.count() + AES_TAG_LENGTH + 4); // 4 bytes for packet number

            initCipher.sendPacket(packet, udpSocket.socketHandle, udpSocket.remoteAddress);
        }
        else if (packetType == PACKET_HANDSHAKE)
        {
            flags = FLAG_HANDSHAKE_SENT;

            auto&& headerStream = initHeader(packet, PACKET_HANDSHAKE, remoteSourceCID.toBuffer(), sourceCID);
            headerStream.writeQInt(packet.frameStream.count() + AES_TAG_LENGTH + 4); // 4 bytes for packet number

            handshakeCipher.sendPacket(packet, udpSocket.socketHandle, udpSocket.remoteAddress);
        }
        else if (packetType == PACKET_1RTT)
        {
            auto&& headerStream = packet.headerStream.clear();

            headerStream.writeByte(PACKET_1RTT);
            headerStream.writeBytes(remoteSourceCID.toBuffer());

            appCipher.sendPacket(packet, udpSocket.socketHandle, udpSocket.remoteAddress);
        }
        else DBGBREAK();
    }

    void sendPacketChain(PQPACKET packetChain)
    {
        for (auto nextPacket = packetChain; nextPacket; )
        {
            auto packet = nextPacket;
            nextPacket = packet->next;
            sendPacket(*packet);
        }
    }

    BYTESTREAM& initHeader(QPACKET& sendPacket, UINT8 packetType, BUFFER destinationCID, BUFFER sourceCID)
    {
        auto&& headerStream = sendPacket.headerStream.clear();

        headerStream.writeByte(packetType);
        headerStream.beWriteU32(QUIC_VERSION); // version

        headerStream.writeByte(destinationCID.length());
        headerStream.writeBytes(destinationCID);

        headerStream.writeByte(sourceCID.length());
        headerStream.writeBytes(sourceCID);

        return headerStream;
    }

    BUFFER decryptPacket(QPACKET& recvPacket)
    {
        auto&& header = recvPacket.recvHeader;
        BUFFER recvData;

        if (header.packetType == PACKET_INITIAL)
        {
            recvData = initCipher.decrypt(recvPacket);
        }
        else if (header.packetType == PACKET_HANDSHAKE)
        {
            flags = FLAG_HANDSHAKE_RECEIVED;
            recvData = handshakeCipher.decrypt(recvPacket);
        }
        else if (header.packetType == PACKET_1RTT)
        {
            recvData = appCipher.decrypt(recvPacket);
        }
        else if (header.packetType == PACKET_RETRY)
        {
            recvData = service.quicRetry.decryptRetryPacket(recvPacket, initialDestCID.toBuffer());
        }
        else DBGBREAK();
        return recvData;
    }

    void onRecvPacket(QPACKET& recvPacket)
    {
        //setSessionStack();
        SetSessionStack(sessionStack);

        auto recvData = decryptPacket(recvPacket);
        auto&& recvHeader = recvPacket.recvHeader;

        if (recvHeader.packetType == PACKET_INITIAL)
        {
            remoteSourceCID.clear().writeBytes(recvHeader.sourceCID);
            parseControlPacket(initCipher, recvPacket, recvData);
        }
        else if (recvHeader.packetType == PACKET_HANDSHAKE)
        {
            parseControlPacket(handshakeCipher, recvPacket, recvData);
        }
        else if (recvHeader.packetType == PACKET_1RTT)
        {
            if (recvHeader.packetType & HEADER_KEY_PHASE)
            {
                DBGBREAK(); // test
                tlsHandshake.updateMasterSecret("quic ku");
            }
            parseAppFrames(recvPacket);
        }
        else if (recvHeader.packetType == PACKET_RETRY)
        {
            auto token = recvData;
            ASSERT(token);

            auto&& originalPacket = *initCipher.retransmitQueue;
            initCipher.unEncrypt(originalPacket);

            retrySourceCID.clear().writeBytes(recvHeader.sourceCID);
            initCipherKeys(retrySourceCID.toBuffer());

            auto&& newPacket = allocSendPacket(PACKET_INITIAL);
            newPacket.frameStream.writeBytes(originalPacket.frameStream.toBuffer());

            sendPacket(newPacket, PACKET_INITIAL, token);
        }
        else DBGBREAK();
    }

    NTSTATUS accept(QPACKET& recvPacket)
    {
        ASSERT(isServer);
        tlsHandshake.init(SystemService().hostname, service.alpnService());

        udpSocket.remoteAddress = recvPacket.recvFrom;

        auto&& recvHeader = recvPacket.recvHeader;
        remoteSourceCID.clear().writeBytes(recvHeader.sourceCID);

        initCipherKeys(recvHeader.destinationCID);

        onRecvPacket(recvPacket);

        flags = FLAG_INIT_RECEIVED;

        return STATUS_SUCCESS;
    }

    NTSTATUS doConnect(TOKEN serverName)
    {
        ASSERT(!isServer);
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            Random.getBytes(initialDestCID.commitTo(8));
            initCipherKeys(initialDestCID.toBuffer());

            tlsHandshake.init(serverName, service.alpnService());
            tlsHandshake.doConnect();

            udpSocket.beginReceive();

            flags = FLAG_INIT_SENT;

        } while (false);
        return status;
    }

    void test()
    {
        constexpr static HEXSTRING CID = "8394c8f03e515708";
        initCipherKeys(CID);

        //HKDF kdf;
        //kdf.initialize(SHA256_HASH_LENGTH);
        //kdf.extract(HKDF_SALT, CID);

        //HEXSTRING client = "00200f746c73313320636c69656e7420696e00";
        //HEXSTRING server = "00200f746c7331332073657276657220696e00";

        HEXSTRING packet = "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868"
            "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578"
            "616d706c652e636f6dff01000100000a00080006001d00170018001000070005"
            "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba"
            "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400"
            "0d0010000e0403050306030203080408050806002d00020101001c0002400100"
            "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000"
            "75300901100f088394c8f03e51570806048000ffff";

        //auto clientSecret = kdf.deriveSecret("client in", NULL_BUFFER, ByteStream(SHA256_HASH_LENGTH));
        //auto serverSecret = kdf.deriveSecret("server in", NULL_BUFFER, ByteStream(SHA256_HASH_LENGTH));

        //deriveKeys(kdf, true, clientSecret, serverSecret, AES128_KEY_LENGTH);

        auto&& packet = service.allocPacket();
        auto&& dataStream = packet.frameStream.clear();
        dataStream.resize(1162);
        dataStream.writeBytes(packet);
        dataStream.writeBytes(ZeroBytes, dataStream.spaceLeft());

        formatInitialHeader(packet.headerStream.clear(), CID, NULL_BUFFER, NULL_BUFFER, dataStream.count());

        initCipher.sendPacketNumber = 2; 
        initCipher.encrypt(packet);

        auto&& rxbuf = service.allocPacket();
        auto&& rxStream = rxbuf.frameStream.clear();
        rxStream.writeBytes(packet.headerStream.toBuffer());
        rxStream.writeBytes(packet.frameStream.toBuffer());
        rxStream.writeBytes(packet.gcmTag);

        initCipher.decrypt(rxbuf);

        printf("done\n");
    }

    void writeTransportParam(BYTESTREAM& outStream, UINT8 param, UINT64 value)
    {
        outStream.writeByte(param);
        outStream.writeQInt(GetQIntBytes(value));
        outStream.writeQInt(value);
    }

    void writeTransportParam(BYTESTREAM& outStream, UINT8 param, BUFFER value)
    {
        outStream.writeByte(param);
        outStream.writeQInt(value.length());
        outStream.writeBytes(value);
    }

    template <typename FUNC, typename ... ARGS>
    void formatTransportParams(BYTESTREAM& tlsStream, FUNC callback, ARGS&& ... args)
    {
        tlsStream.writeEnumBE(ext_quic_transport_parameters);
        auto offset = tlsStream.saveOffset(2);

        writeTransportParam(tlsStream, QTP_initial_max_data, streamLimits.maxRecvBytes);

        writeTransportParam(tlsStream, QTP_initial_max_streams_bidi, streamLimits.maxId_bidirRemote);
        writeTransportParam(tlsStream, QTP_initial_max_streams_uni, streamLimits.maxId_outRemote);

        writeTransportParam(tlsStream, QTP_initial_max_stream_data_bidi_local, streamLimits.maxRecvOffset_bidirLocal);
        writeTransportParam(tlsStream, QTP_initial_max_stream_data_bidi_remote, streamLimits.maxRecvOffset_bidirRemote);

        writeTransportParam(tlsStream, QTP_initial_max_stream_data_uni, streamLimits.maxRecvOffset_out);

        writeTransportParam(tlsStream, QTP_initial_source_connection_id, sourceCID);
        writeTransportParam(tlsStream, QTP_max_udp_payload_size, sendMTU);

        callback(tlsStream, args ...);

        offset.writeLength();
    }

    void formatServerTransportParams(BYTESTREAM& tlsStream, QPACKET& recvPacket)
    {
        formatTransportParams(tlsStream, [](BYTESTREAM& tlsStream, QUIC_SESSION& session, QPACKET& recvPacket)
            {
                if (recvPacket.recvHeader.retryToken)
                {
                    session.writeTransportParam(tlsStream, QTP_original_destination_connection_id, session.service.quicRetry.getDestCIDfromToken(recvPacket));
                    session.writeTransportParam(tlsStream, QTP_retry_source_connection_id, recvPacket.recvHeader.destinationCID);
                }
                else
                {
                    session.writeTransportParam(tlsStream, QTP_original_destination_connection_id, recvPacket.recvHeader.destinationCID);
                }
            }, *this, recvPacket);
    }

    void formatClientTransportParams(BYTESTREAM& tlsStream)
    {
        formatTransportParams(tlsStream, [](BYTESTREAM&)
            {
                // nothing to do.
            });
    }

    template <typename FUNC, typename ... ARGS>
    void readTransportParam(BUFFER msgData, FUNC handler, ARGS&& ... args)
    {
        while (msgData)
        {
            auto param = msgData.readByte();
            auto value = readVarQData(msgData);

            handler(param, value, args ...);
        }
    }

    void parseTransportParams(BUFFER paramData)
    {
        while (paramData)
        {
            auto param = paramData.readByte();
            auto value = readVarQData(paramData);

            if (param == QTP_initial_max_data)
            {
                streamLimits.maxSendBytes = value.readQInt();
            }
            else if (param == QTP_initial_max_streams_bidi)
            {
                streamLimits.maxId_bidirLocal = value.readQInt();
            }
            else if (param == QTP_initial_max_streams_uni)
            {
                streamLimits.maxId_outLocal = value.readQInt();
            }
            else if (param == QTP_initial_max_stream_data_bidi_local)
            {
                streamLimits.maxSendOffset_bidirRemote = value.readQInt();
            }
            else if (param == QTP_initial_max_stream_data_bidi_remote)
            {
                streamLimits.maxSendOffset_bidirLocal = value.readQInt();
            }
            else if (param == QTP_initial_max_stream_data_uni)
            {
                streamLimits.maxSendOffset_out = value.readQInt();
            }
            else if (param == QTP_max_udp_payload_size)
            {
                sendMTU = (UINT32)value.readQInt();
            }
            else if (param == QTP_original_destination_connection_id)
            {
                ASSERT(value == initialDestCID.toBuffer());
                // check
            }
            else if (param == QTP_initial_source_connection_id)
            {
                ASSERT(value == remoteSourceCID.toBuffer());
                // code
            }
            else if (param == QTP_retry_source_connection_id)
            {
                ASSERT(value == retrySourceCID.toBuffer());

                // code, sent on a retry packet
            }
            else if (param == QTP_ack_delay_exponent)
            {
                remoteAckDelayExponent = (UINT32)value.readQInt();
            }
            else if (param == QTP_max_ack_delay)
            {
                remoteMaxAckDelayTime = (UINT32)value.readQInt();
            }
        }
    }

};

