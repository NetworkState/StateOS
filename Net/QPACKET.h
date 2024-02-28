
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
constexpr UINT16 PACKET_FLAG_RX_SOCKET = 0x01;
constexpr UINT16 PACKET_FLAG_RX_HANDLER = 0x02;
constexpr UINT16 PACKET_FLAG_TX_FILL = 0x04;
constexpr UINT16 PACKET_FLAG_TX_SOCKET = 0x08;
constexpr UINT16 PACKET_FLAG_SBUF_LIST = 0x10;
constexpr UINT16 PACKET_FLAG_TX_FILE_WRITE = 0x20;

constexpr UINT32 POOL_SIZE = 2048;

constexpr UINT8 PACKET_INITIAL = 0xC0 | 0x00;
constexpr UINT8 PACKET_0RTT = 0xC0 | 0x10;
constexpr UINT8 PACKET_HANDSHAKE = 0xC0 | 0x20;
constexpr UINT8 PACKET_RETRY = 0xC0 | 0x30;
constexpr UINT8 PACKET_1RTT = 0x40;
constexpr UINT8 HEADER_LONG = 0x80;
constexpr UINT8 HEADER_FIXED = 0x40;
constexpr UINT8 HEADER_TYPE = 0xF0;
constexpr UINT8 HEADER_PACKET_NUMBER = 0x03;
constexpr UINT8 HEADER_KEY_PHASE = 0x04;
constexpr UINT8 HEADER_KEY_SPIN_BIT = 0x20;

constexpr UINT32 QUIC_VERSION = 1;
constexpr UINT32 LOCAL_CID_LENGTH = 8;
constexpr UINT32 MAX_CID_LENGTH = 20;

inline UINT8 GetQIntBytes(UINT64 value)
{
    return value < (1ull << 6) ? 1
        : value < (1ull << 14) ? 2
        : value < (1ull << 30) ? 4 : 8;
}

struct QUIC_HEADER
{
    UINT16 headerLength;

    UINT8 packetType = 0;
    UINT32 version = 0;
    BUFFER destinationCID;
    BUFFER sourceCID;
    BUFFER recvToken;
    BUFFER retryToken;
    UINT64 dataLength = 0;

    UINT64 packetNumber;
};

inline UINT8 GetPacketType(UINT8 headerByte)
{
    return (headerByte & HEADER_LONG) ? headerByte & 0xF0 : PACKET_1RTT;
}

struct QPACKET
{
    constexpr static UINT32 PACKET_SIZE = 2048;
    struct PACKET_POOL
    {
        UINT32 bufCount;
        PUINT8 bufMemory;

        QPACKET* head;

        NTSTATUS init(UINT32 poolSize = POOL_SIZE)
        {
            ASSERT(sizeof(QPACKET) < PACKET_SIZE);
            auto status = STATUS_UNSUCCESSFUL;
            do
            {
                bufCount = poolSize;
                UINT32 allocSize = bufCount * PACKET_SIZE;
                bufMemory = (PUINT8)VirtualAlloc(nullptr, allocSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
                ASSERT(bufMemory);

                if (bufMemory == nullptr)
                    break;

                QPACKET* prev = nullptr;
                for (auto ptr = bufMemory; ptr < (bufMemory + allocSize); ptr += PACKET_SIZE)
                {
                    new (ptr) QPACKET(*this);
                    ((QPACKET*)ptr)->next = prev;
                    prev = (QPACKET*)ptr;
                }

                head = prev;
                status = STATUS_SUCCESS;
            } while (false);
            return status;
        }

        QPACKET& alloc()
        {
            auto&& ptr = *head;
            head = ptr.next;
            ptr.next = nullptr;
            return ptr;
        }

        void free(QPACKET& buf)
        {
            new (&buf) QPACKET(*this);
            buf.next = head;
            head = &buf;
        }
    };

    constexpr static UINT32 FRAME_SIZE = 1470;
    constexpr static UINT32 HEADER_SIZE = 128;

    UINT8 _frameData[FRAME_SIZE];
    UINT8 _headerData[HEADER_SIZE];
    U128 gcmTag;

    QPACKET* next;
    PACKET_POOL& packetPool;
    BYTESTREAM headerStream{ _headerData };
    BYTESTREAM frameStream{ _frameData };
    UINT64 packetNumber;
    IOCALLBACK ioState{ IO_SOCK_SEND };

    WSABUF recvBuf{ FRAME_SIZE + HEADER_SIZE, (CHAR*)_frameData };
    IPENDPOINT recvFrom;
    INT recvFromLength = sizeof(SOCKADDR_IN);
    UINT32 useFlags;
    QUIC_HEADER recvHeader;

    QPACKET(PACKET_POOL& pool) : packetPool(pool) {}

    void sendTo(SOCKET socket, const IPENDPOINT& dest)
    {
        addRef(PACKET_FLAG_TX_SOCKET);

        WSABUF sendBufs[] = {
            {headerStream.count(), (CHAR*)headerStream.address()},
            {frameStream.count(), (CHAR*)frameStream.address()},
            {AES_TAG_LENGTH, (CHAR*)gcmTag.u8},
        };

        NEW(ioState.task, [](PVOID context, NTSTATUS status, STASK_ARGV params)
            {
                //((QPACKET*)context)->release(PACKET_FLAG_TX_SOCKET); // XXX fix ref counting
            }, this);

        DWORD bytesSent;
        WSASendTo(socket, sendBufs, 3, &bytesSent, 0, dest.addressC(), SOCKADDR_LEN, ioState.start(), nullptr);
    }

    void addRef(UINT16 flag = 0)
    {
        ASSERT((useFlags & flag) == 0);
        useFlags |= flag;
    }

    void addRefCount()
    {
        auto refCount = (useFlags >> 16) + 1;
        useFlags = (useFlags & 0xFFFF) | (refCount << 16);
    }

    void releaseRefCount()
    {
        auto refCount = useFlags >> 16;
        ASSERT(refCount > 0);
        useFlags = (useFlags & 0xFFFF) | ((refCount - 1) << 16);

        if (useFlags == 0)
            packetPool.free(*this);
    }

    void release(UINT16 flag)
    {
        useFlags &= ~flag;
        if (useFlags == 0)
            packetPool.free(*this);
    }

    QUIC_HEADER& parseHeader()
    {
        auto packetData = frameStream.toBuffer();
        recvHeader.headerLength = 1;
        auto formatByte = packetData.readByte();
        if (formatByte & HEADER_LONG)
        {
            auto bufStart = packetData.savePosition();
            ASSERT(formatByte & HEADER_FIXED);
            recvHeader.packetType = formatByte & 0xF0;

            recvHeader.version = packetData.beReadU32(); // version
            recvHeader.destinationCID = packetData.readBytes(packetData.readByte()); // destination CID
            recvHeader.sourceCID = packetData.readBytes(packetData.readByte()); // source CID

            if (recvHeader.packetType == PACKET_INITIAL)
                recvHeader.recvToken = packetData.readBytes(UINT32(packetData.readQInt())); // token

            if (recvHeader.packetType != PACKET_RETRY)
                recvHeader.dataLength = packetData.readQInt(); // data length

            recvHeader.headerLength += packetData.diffLength(bufStart);
        }
        else
        {
            recvHeader.packetType = PACKET_1RTT;
            recvHeader.headerLength += LOCAL_CID_LENGTH;
        }
        return recvHeader;
    }

    void insertToQueue(QPACKET** link)
    {
        while (*link) link = &(*link)->next;
        *link = this;
    }

    bool removeFromQueue(QPACKET** nextLink)
    {
        for (; *nextLink; nextLink = &(*nextLink)->next)
        {
            if (*nextLink == this)
            {
                *nextLink = this->next;
                return true;
            }
        }
        return false;
    }
};
using PQPACKET = QPACKET*;

constexpr UINT8 FRAMETYPE_PADDING = 0x00;
constexpr UINT8 FRAMETYPE_PING = 0x01;
constexpr UINT8 FRAMETYPE_ACK = 0x02;
constexpr UINT8 FRAMETYPE_ACK_ECN = 0x03;
constexpr UINT8 FRAMETYPE_RESET_STREAM = 0x04;
constexpr UINT8 FRAMETYPE_STOP_SENDING = 0x05;
constexpr UINT8 FRAMETYPE_CRYPTO = 0x06;
constexpr UINT8 FRAMETYPE_NEW_TOKEN = 0x07;
constexpr UINT8 FRAMETYPE_STREAM = 0x08;

constexpr UINT8 FRAMETYPE_STREAM_FLAGS = 0x07;
constexpr UINT8 FRAMETYPE_STREAM_FLAG_OFFSET = 0x04;
constexpr UINT8 FRAMETYPE_STREAM_FLAG_LENGTH = 0x02;
constexpr UINT8 FRAMETYPE_STREAM_FLAG_FIN = 0x01;

constexpr UINT8 FRAMETYPE_STREAM_LEN_OFF = FRAMETYPE_STREAM | FRAMETYPE_STREAM_FLAG_OFFSET | FRAMETYPE_STREAM_FLAG_LENGTH;

constexpr UINT8 FRAMETYPE_MAX_DATA = 0x10;
constexpr UINT8 FRAMETYPE_MAX_STREAM_DATA = 0x11;
constexpr UINT8 FRAMETYPE_MAX_STREAMS_BIDIR = 0x12;
constexpr UINT8 FRAMETYPE_MAX_STREAMS_UNI = 0x13;
constexpr UINT8 FRAMETYPE_DATA_BLOCKED = 0x14;
constexpr UINT8 FRAMETYPE_STREAM_DATA_BLOCKED = 0x15;
constexpr UINT8 FRAMETYPE_STREAMS_BLOCKED_BIDIR = 0x16;
constexpr UINT8 FRAMETYPE_STREAMS_BLOCKED_UNI = 0x17;
constexpr UINT8 FRAMETYPE_NEW_CONNECTION_ID = 0x18;
constexpr UINT8 FRAMETYPE_RETIRE_CONNECTION_ID = 0x19;
constexpr UINT8 FRAMETYPE_PATH_CHALLENGE = 0x1a;
constexpr UINT8 FRAMETYPE_PATH_RESPONSE = 0x1b;
constexpr UINT8 FRAMETYPE_CONNECTION_CLOSE_QUIC_ERROR = 0x1c;
constexpr UINT8 FRAMETYPE_CONNECTION_CLOSE_APP_ERROR = 0x1d;
constexpr UINT8 FRAMETYPE_HANDSHAKE_DONE = 0x1e;

constexpr UINT8 STREAM_TYPE_OUTGOING = 0x02;
constexpr UINT8 STREAM_TYPE_BIDIR = 0x00;
constexpr UINT8 STREAM_TYPE_SERVER = 0x01;
constexpr UINT8 STREAM_TYPE_CLIENT = 0x00;

constexpr UINT8 STREAM_SERVER_OUTGOING = 0x03;
constexpr UINT8 STREAM_SERVER_BIDIR = 0x01;
constexpr UINT8 STREAM_CLIENT_OUTGOING = 0x02;
constexpr UINT8 STREAM_CLIENT_BIDIR = 0x00;

inline bool IS_STREAM(UINT8 frameType) { return (frameType & 0xF8) == FRAMETYPE_STREAM; }

struct DATAFRAME
{
    struct DATAFRAME* next = nullptr;
    struct DATAFRAME* prev = nullptr;

    QPACKET& packet;
    UINT64 streamId = -1;
    UINT64 streamOffset = -1;

    BUFFER dataBuf;
    UINT32 recvTime = -1;
    UINT8 frameType = 0;

    auto streamEnd() { return streamOffset != -1 ? streamOffset + dataBuf.length() : 0; }
    UINT8 packetType() { return packet.recvHeader.packetType; }
    bool endOfStream() { return frameType & FRAMETYPE_STREAM_FLAG_FIN; }

    DATAFRAME(QPACKET& packet, UINT64 streamId, UINT8 frameType, UINT64 streamOffset) :
        packet(packet), streamId(streamId), streamOffset(streamOffset), frameType(frameType)
    {
        recvTime = UINT32(GetUptimeUS() / 1000);
    }

    BUFFER toBuffer(UINT64 fromOffset, UINT64 toOffset)
    {
        return { (PUINT8)dataBuf._data, UINT32(fromOffset - streamOffset), UINT32(toOffset - streamOffset) };
    }

    void rebase(UINT32 shiftBytes = 0)
    {
        dataBuf.shift(shiftBytes);
        streamOffset += dataBuf._start;
        dataBuf.rebase();
    }
};
using PDATAFRAME = DATAFRAME*;
using FRAME_STREAM = DATASTREAM<PDATAFRAME, SCHEDULER_STACK>;

template <typename T>
void INSERT_DLINK(T& link, T& node)
{
    node.next = link.next;
    if (link.next) link.next->prev = &node;
    link.next = &node;
    node.prev = &link;
}

template <typename T>
void APPEND_DLINK(T** queue, T& node)
{
    auto link = queue;
    T* prev = nullptr;

    while (*link)
    {
        prev = *link;
        link = &((*link)->next);
    }

    *link = &node;
    node.prev = prev;
}

template <typename T>
void REMOVE_DLINK(T** queue, T& node)
{
    if (node.prev == nullptr)
    {
        *queue = node.next;
    }
    else
    {
        node.prev->next = node.next;
    }

    if (node.next)
    {
        node.next->prev = node.prev;
    }
}

struct MBUF_READER
{
    STREAM_READER<PDATAFRAME> frames;
    MBUF_READER(STREAM_READER<PDATAFRAME> list) : frames(list) 
    {
        for (auto&& frame : frames)
        {
            ASSERT(frame->dataBuf._start == 0); // no partial data
        }
    }

    UINT32 chainBytes() const
    {
        UINT32 sum = 0;
        for (auto&& frame : frames)
        {
            sum += frame->dataBuf.length();
        }
        return sum;
    }

    BUFFER& getCurrent() 
    { 
        ASSERT(frames);
        return frames.peek()->dataBuf; 
    }

    void shift()
    {
        if (frames && getCurrent().length() == 0)
            frames.shift();
    }

    BUFFER readBytes(UINT32 byteCount)
    {
        BUFFER result;

        if (byteCount > 0 && chainBytes() >= byteCount)
        {
            auto&& current = getCurrent();
            if (current.length() >= byteCount)
            {
                result = current.readBytes(byteCount);
                shift();
            }
            else
            {
                auto&& outStream = ByteStream(byteCount);
                while (frames && byteCount > 0)
                {
                    auto&& buf = getCurrent();
                    auto partialData = buf.readBytesMax(byteCount);
                    shift();
                    outStream.writeBytes(partialData);
                    byteCount -= partialData.length();
                }
                result = outStream.toBuffer();
            }
        }
        return result;
    }

    template <typename STREAM>
    BUFFER writeBytes(STREAM&& outStream)
    {
        for (UINT32 i = 0; i < frames.length() && outStream.spaceLeft() > 0; i++)
        {
            auto&& dataBuf = frames.at(i)->dataBuf;
            auto count = min(dataBuf.length(), outStream.spaceLeft());
            outStream.writeBytes(dataBuf.readBytes(count));
        }
        return outStream.toBuffer();
    }

    UINT32 mark()
    {
        UINT32 sum = 0;
        auto address = (PDATAFRAME *)frames._data;
        for (UINT32 i = 0; i < frames._end; i++)
        {
            sum += address[i]->dataBuf.mark();
        }
        return sum;
    }

    UINT64 streamOffset()
    {
        auto offset = ((PDATAFRAME*)frames._data)[0]->streamOffset;
        return offset + mark();
    }

    void revert(UINT32 targetMark)
    {
        ASSERT(targetMark < mark());
        auto diffBytes = mark() - targetMark;
        auto address = (PDATAFRAME*)frames._data;
        for (UINT32 i = frames._end; i > 0; i--)
        {
            auto&& buf = address[i - 1]->dataBuf;
            buf._start -= min(buf._start, diffBytes);
            if (mark() == targetMark)
            {
                frames._start = i - 1;
                break;
            }
        }
        ASSERT(targetMark == mark());
    }
    void revertBack(UINT32 bytes)
    {
        if (bytes > 0)
        {
            revert(mark() - bytes);
        }
    }

    BYTE peekByte()
    {
        return getCurrent().peek();
    }

    UINT8 readByte()
    {
        ASSERT(chainBytes() > 0);
        auto byte = getCurrent().readByte();
        shift();
        return byte;
    }

    BUFFER peekBytes(UINT32 byteCount)
    {
        auto position = mark();
        auto result = readBytes(byteCount);
        revert(position);
        return result;
    }

    UINT64 readQInt()
    {
        UINT64 value = -1;
        if (auto bytesAvailable = chainBytes())
        {
            auto&& current = getCurrent();
            auto byteCount = 1ui32 << (current.peek() >> 6);
            if (bytesAvailable >= byteCount)
            {
                value = readBytes(byteCount).readQInt();
            }
        }
        return value;
    }

    explicit operator bool() const { return chainBytes() > 0; }

    bool endOfStream()
    {
        return frames.last()->endOfStream();
    }
};

constexpr static UINT64 STREAM_TYPE(UINT64 id) { return id & 0x03; }

struct STREAM_STATE
{
    constexpr static UINT32 H3_FLAG_FIN_SENT = 0x01;
    constexpr static UINT32 H3_FLAG_FIN_RCVD = 0x02;

    UINT32 flags = 0;
    UINT64 streamId = -1;
    UINT64 sendOffset = 0;
    UINT64 _sendCredit = 0;
    UINT64 recvOffset = 0;
    UINT64 recvCredit = 0;

    PDATAFRAME recvFrameQueue = nullptr;

    void reset()
    {
        NEW(*this);
    }

    UINT32 sendCredit() const
    {
        return (flags & H3_FLAG_FIN_SENT) ? 0 : UINT32(_sendCredit - sendOffset);
    }

    void onRecvFrame(DATAFRAME& recvFrame)
    {
        if (recvFrame.endOfStream())
            flags |= H3_FLAG_FIN_RCVD;

        auto inserted = false;
        for (auto frame = recvFrameQueue; frame; frame = frame->next)
        {
            if ((frame->streamOffset >= recvFrame.streamOffset))
            {
                auto prevEnd = frame->prev ? frame->prev->streamEnd() : recvFrame.streamOffset;
                if (prevEnd > recvFrame.streamOffset)
                {
                    auto diff = UINT32(prevEnd - recvFrame.streamOffset);
                    recvFrame.rebase(diff);
                }
                if (recvFrame.streamEnd() > frame->streamOffset)
                {
                    recvFrame.dataBuf.shrink(UINT32(recvFrame.streamEnd() - frame->streamOffset));
                }
                INSERT_DLINK(*frame, recvFrame);
                inserted = true;
                break;
            }
            else if (frame->streamId > recvFrame.streamId)
            {
                INSERT_DLINK(*frame, recvFrame);
                inserted = true;
                break;
            }
        }
        if (inserted == false)
        {
            APPEND_DLINK(&recvFrameQueue, recvFrame);
        }
    }

    template <typename QUICSESSION, typename FUNC, typename ... ARGS>
    void handleRecvFrames(QUICSESSION& quicSession, FUNC callback, ARGS&& ... args)
    {
        if (!hasRecvBytes())
            return;

        FRAME_STREAM frameStream;
        UINT64 streamOffset = recvOffset;
        for (auto frame = recvFrameQueue; frame; frame = frame->next)
        {
            if (frame->streamOffset == streamOffset)
            {
                frameStream.append(frame);
                streamOffset += frame->dataBuf.length();
            }
        }

        MBUF_READER mbuf{ frameStream.toRWBuffer() };
        callback(mbuf, args ...);

        recvOffset = mbuf.streamOffset();

        quicSession.clearDataframeQueue(&recvFrameQueue);
    }

    bool hasRecvBytes() { return recvFrameQueue && recvFrameQueue->streamOffset == recvOffset; }

    bool sendClosed() { return flags & H3_FLAG_FIN_SENT; }
    bool recvClosed() { return flags & H3_FLAG_FIN_RCVD; }
    explicit operator bool() const { return streamId != -1; }
};

struct STREAM_LIMITS
{
    UINT64 localOutgoingStreamId;
    UINT64 remoteOutgoingStreamId;
    UINT64 localBirdirStreamId;
    UINT64 remoteBidirStreamId;

    UINT64 makeOutgoingStreamId(UINT64 id) { return (id << 2) | localOutgoingStreamId; }
    UINT64 makeBidirStreamId(UINT64 id) { return (id << 2) | localBirdirStreamId; }

    bool isLocalBidir(UINT64 streamId) { return STREAM_TYPE(streamId) == localBirdirStreamId; }
    bool isRemoteBidir(UINT64 streamId) { return STREAM_TYPE(streamId) == remoteBidirStreamId; }
    bool isLocalOutgoing(UINT64 streamId) { return STREAM_TYPE(streamId) == localOutgoingStreamId; }
    bool isRemoteOutgoing(UINT64 streamId) { return STREAM_TYPE(streamId) == remoteOutgoingStreamId; }

    bool isLocal(UINT64 streamId) { return isLocalOutgoing(streamId) || isLocalBidir(streamId); }
    bool isRemote(UINT64 streamId) { return isRemoteOutgoing(streamId) || isRemoteBidir(streamId); }

    UINT64 maxRecvOffset_bidirLocal = MAXUINT32;
    UINT64 maxSendOffset_bidirLocal = 0;

    UINT64 maxRecvOffset_bidirRemote = MAXUINT32;
    UINT64 maxSendOffset_bidirRemote = 0;

    UINT64 maxSendOffset_out = 0;
    UINT64 maxRecvOffset_out = MAXUINT32;

    UINT64 maxSendBytes = 0;
    UINT64 maxRecvBytes = MAXUINT32;

    UINT64 maxId_bidirLocal = 0;
    UINT64 maxId_bidirRemote = MAXUINT32;
    UINT64 maxId_outLocal = 0;
    UINT64 maxId_outRemote = 256;

    UINT64 nextBidirStreamId = 0;
    UINT64 nextOutgoingStreamId = 4;

    STREAM_LIMITS(bool isServer)
    {
        localOutgoingStreamId = STREAM_TYPE_OUTGOING | UINT8(isServer);
        remoteOutgoingStreamId = localOutgoingStreamId ^ 1;
        localBirdirStreamId = STREAM_TYPE_BIDIR | UINT8(isServer);
        remoteBidirStreamId = localBirdirStreamId ^ 1;
    }

    void allocBidirStream(STREAM_STATE& streamState)
    {
        streamState.streamId = -1;
        if (nextBidirStreamId < maxId_bidirLocal)
        {
            streamState.streamId = makeBidirStreamId(nextBidirStreamId++);
            streamState._sendCredit = maxSendOffset_bidirLocal;
            streamState.recvCredit = maxRecvOffset_bidirLocal;
        }
        else DBGBREAK();
    }

    void allocOutgoingStream(STREAM_STATE& streamState, UINT64 streamId = -1)
    {
        streamState.streamId = streamId == -1 
                                    ? makeOutgoingStreamId(nextOutgoingStreamId++) 
                                    : makeOutgoingStreamId(streamId >> 2);
        if (streamState.streamId < maxId_outLocal)
        {
            streamState._sendCredit = maxSendOffset_out;
            streamState.recvCredit = 0;
        }
        else DBGBREAK();
    }

    void initBidirStream(STREAM_STATE& streamState, UINT64 streamId)
    {
        ASSERT(STREAM_TYPE(streamId) == remoteBidirStreamId);
        streamState.streamId = streamId;
        streamState._sendCredit = maxSendOffset_bidirRemote;
        streamState.recvCredit = maxRecvOffset_bidirRemote;
        streamState.sendOffset = streamState.recvOffset = 0;
    }

    void initOutgoingStream(STREAM_STATE& streamState, UINT64 streamId)
    {
        ASSERT(STREAM_TYPE(streamId) == remoteOutgoingStreamId);
        streamState.streamId = streamId;
        streamState._sendCredit = 0;
        streamState.recvCredit = maxRecvOffset_out;
        streamState.recvOffset = 0;
    }
};

template <typename QUICSESSION>
struct MBUF_STREAM
{
    QUICSESSION& quicSession;
    PQPACKET packetChain = nullptr;

    PUINT8 frameType;
    STREAM_STATE* sendState;

    BYTESTREAM::OFFSET lengthOffset;

    struct MBUF_OFFSET
    {
        MBUF_STREAM& mbufStream;
        BYTESTREAM::OFFSET lengthOffset;
        UINT64 beginStreamOffset;

        MBUF_OFFSET(MBUF_STREAM& mbufStream, UINT32 intWidth) : mbufStream(mbufStream), lengthOffset(mbufStream.getCurrent().saveOffset(intWidth))
        {
            beginStreamOffset = mbufStream.getStreamOffset();
        }

        void writeQLength()
        {
            ASSERT(mbufStream.lengthOffset);
            auto length = mbufStream.getStreamOffset()  - beginStreamOffset;
            lengthOffset.writeQLength(UINT32(length));
        }
    };

    MBUF_STREAM(QUICSESSION& quicSession) : quicSession(quicSession)    
    {
        quicSession.allocPacketChain(&packetChain);
    }

    BYTESTREAM& getCurrent()
    {
        auto packet = packetChain;
        ASSERT(packet);

        while (packet->next) packet = packet->next;
        return packet->frameStream;
    }

    UINT64 getStreamOffset()
    {
        ASSERT(lengthOffset);
        return sendState->sendOffset + lengthOffset.getLength();
    }

    MBUF_OFFSET saveOffset(UINT32 intWidth = 2)
    {
        MBUF_OFFSET mbufOffset{ *this, intWidth };
        return mbufOffset;
    }

    BYTESTREAM& reserve(UINT32 size)
    {
        auto&& frameStream = getCurrent();
        if (frameStream.spaceLeft() < size)
        {
            endStream();
            auto&& packet = quicSession.allocPacketChain(&packetChain);
            frameType = quicSession.formatStreamFrame(packet.frameStream, *sendState, lengthOffset);
            return packet.frameStream;
        }
        else
        {
            return frameStream;
        }
    }

    void beginStream(STREAM_STATE& streamState)
    {
        sendState = &streamState;
        ASSERT(lengthOffset.lengthWritten);
        
        if (getCurrent().spaceLeft() < 20)
        {
            quicSession.allocPacketChain(&packetChain);
        }
        frameType = quicSession.formatStreamFrame(getCurrent(), streamState, lengthOffset);
    }

    void endStream()
    {
        sendState->sendOffset += lengthOffset.writeQLength();
    }

    void finalizeStream()
    {
        *frameType |= FRAMETYPE_STREAM_FLAG_FIN;
        endStream();
    }

    void writeQInt(UINT64 value)
    {
        ASSERT(lengthOffset);
        auto&& frameStream = reserve(GetQIntBytes(value));
        frameStream.writeQInt(value);
    }

    void writeByte(UINT8 value)
    {
        ASSERT(lengthOffset);
        auto&& frameStream = reserve(1);
        frameStream.writeByte(value);    
    }

    void writeBytes(BUFFER data)
    {
        ASSERT(lengthOffset);
        while (data)
        {
            auto&& byteStream = reserve(1);
            auto buf = data.readBytes(min(data.length(), byteStream.spaceLeft()));
            byteStream.writeBytes(buf);
        }
    }

    void sendPackets()
    {
        quicSession.sendPacketChain(packetChain);
    }
};

