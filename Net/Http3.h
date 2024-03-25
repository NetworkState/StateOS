
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
struct H3_SERVICE
{
    constexpr static UINT8 H3_FRAME_TYPE_DATA = 0;
    constexpr static UINT8 H3_FRAME_TYPE_HEADERS = 1;
    constexpr static UINT8 H3_FRAME_TYPE_SETTINGS = 4;
    constexpr static UINT8 H3_FRAME_TYPE_CANCEL_PUSH = 3;
    constexpr static UINT8 H3_FRAME_TYPE_PUSH_PROMISE = 5;
    constexpr static UINT8 H3_FRAME_TYPE_GO_AWAY = 7;
    constexpr static UINT8 H3_FRAME_TYPE_MAX_PUSH_ID = 0x0d;

    constexpr static UINT32 H3_NO_ERROR = 0x0100;
    constexpr static UINT32 H3_GENERAL_PROTOCOL_ERROR = 0x0101;
    constexpr static UINT32 H3_INTERNAL_ERROR = 0x0102;
    constexpr static UINT32 H3_STREAM_CREATION_ERROR = 0x0103;
    constexpr static UINT32 H3_CLOSED_CRITICAL_STREAM = 0x0104;
    constexpr static UINT32 H3_FRAME_UNEXPECTED = 0x0105;
    constexpr static UINT32 H3_FRAME_ERROR = 0x0106;
    constexpr static UINT32 H3_EXCESSIVE_LOAD = 0x0107;
    constexpr static UINT32 H3_ID_ERROR = 0x0108;
    constexpr static UINT32 H3_SETTINGS_ERROR = 0x0109;

    constexpr static UINT32 H3_MISSING_SETTINGS = 0x010a;
    constexpr static UINT32 H3_REQUEST_REJECTED = 0x010b;
    constexpr static UINT32 H3_REQUEST_CANCELLED = 0x010c;
    constexpr static UINT32 H3_REQUEST_INCOMPLETE = 0x010d;
    constexpr static UINT32 H3_MESSAGE_ERROR = 0x010e;
    constexpr static UINT32 H3_CONNECT_ERROR = 0x010f;
    constexpr static UINT32 H3_VERSION_FALLBACK = 0x0110;

    struct FILEBUF
    {
        FILEBUF* next = nullptr;
        BYTESTREAM dataStream;
        UINT64 fileOffset = 0;
        IOCALLBACK ioContext{ IO_FILE_READ };

        UINT64 writeOffset() { return fileOffset + dataStream.count(); }
    };
    using PFILEBUF = FILEBUF*;

    struct FILEBUF_POOL
    {
        UINT32 bufSize;
        UINT32 queueSize;

        FILEBUF* bufQueue;

        FILEBUF_POOL(UINT32 bufSize, UINT32 queueSize) : bufSize(bufSize), queueSize(queueSize) {}

        NTSTATUS init()
        {
            auto status = STATUS_UNSUCCESSFUL;
            do
            {
                auto bufTable = ServiceBufAlloc<FILEBUF>(queueSize);
                for (UINT32 i = 0; i < queueSize; i++)
                {
                    auto&& buf = bufTable[i];

                    auto data = (PUINT8)MemAlloc(bufSize);
                    if (data == nullptr)
                    {
                        DBGBREAK();
                        break;
                    }
                    NEW(buf.dataStream, data, bufSize);
                    buf.next = &bufTable[i + 1];
                }
                bufTable[queueSize - 1].next = nullptr;

                APPEND_LINK(&bufQueue, bufTable[0]);
                status = STATUS_SUCCESS;
            } while (false);
            return status;
        }

        FILEBUF& alloc()
        {
            ASSERT(bufQueue != nullptr);
            auto&& buf = *bufQueue;
            bufQueue = buf.next;
            buf.next = nullptr;

            buf.dataStream.clear();
            return buf;
        }

        void free(FILEBUF& buf)
        {
            buf.next = bufQueue;
            bufQueue = &buf;
        }

        void reset()
        {
            for (auto buf = bufQueue; buf; buf = buf->next)
            {
                MemFree(buf->dataStream.data);
            }
            bufQueue = nullptr;
        }
    };

    constexpr static UINT32 BASE_BUFSiZE = 16 * 1024;
    FILEBUF_POOL bufPool16k{ BASE_BUFSiZE, 64 };
    FILEBUF_POOL bufPool64k{ BASE_BUFSiZE * 4, 32 };
    FILEBUF_POOL bufPool256k{ BASE_BUFSiZE * 16, 16 };
    FILEBUF_POOL bufPool1M{ BASE_BUFSiZE * 64, 8 };
    FILEBUF_POOL bufPool4M{ BASE_BUFSiZE * 256, 4 };

    constexpr static UINT32 BUFPOOL_MAX = 5;
    FILEBUF_POOL* fileBufPools[BUFPOOL_MAX]{ &bufPool16k, &bufPool64k, &bufPool256k, &bufPool1M, &bufPool4M };
    FILEBUF_POOL& getBufPool(UINT32 size)
    {
        size = max(BASE_BUFSiZE, size);
        auto index = (LOG2(size) - 13) / 2; // 14bits - 16KB, buf sizes are multiples of 4 (2 bits)
        index = min(BUFPOOL_MAX - 1, index);
        return *fileBufPools[index];
    }

    FILEBUF& allocFileBuf(UINT32 size = 16 * 1024)
    {
        return getBufPool(size).alloc();
    }

    void freeFileBuf(FILEBUF& fileBuf)
    {
        getBufPool(fileBuf.dataStream.size()).free(fileBuf);
    }

    constexpr static UINT8 H3_SETTING_QPACK_MAX_TABLE_CAPACITY = 0x01;
    constexpr static UINT8 H3_SETTING_QPACK_BLOCKED_STREAMS = 0x07;
    constexpr static UINT8 H3_SETTING_MAX_FIELD_SECTION_SIZE = 0x06;

    constexpr static UINT64 QPACK_MAX_TABLE_CAPACITY = 65536;
    constexpr static UINT64 QPACK_BLOCKED_STREAMS = 100;
    constexpr static UINT64 MAX_FIELD_SECTION_SIZE = 65536;

    constexpr static UINT8 H3_STREAM_TYPE_CONTROL_STREAM = 0;
    constexpr static UINT8 H3_STREAM_TYPE_PUSH_STREAM = 1;
    constexpr static UINT8 H3_STREAM_TYPE_ENCODER_STREAM = 2;
    constexpr static UINT8 H3_STREAM_TYPE_DECODER_STREAM = 3;

    struct H3_SESSION;
    using QUICH3_SESSION = QUIC_SESSION<H3_SERVICE, H3_SESSION>;
    using QUIC_SOCKET = UDP_SOCKET<H3_SERVICE>;

    struct H3_SESSION
    {
        static inline QUICH3_SESSION& GetQuicSession()
        {
            return QUICH3_SESSION::GetSession();
        }
        using MBUF_QUIC_STREAM = MBUF_STREAM<QUICH3_SESSION>;
        static H3_SESSION& GetSession()
        {
            return GetQuicSession().appSession;
        }

        inline QUICH3_SESSION& quicSession()
        {
            return *CONTAINING_RECORD(this, QUICH3_SESSION, appSession);
        }

        struct H3_TRANSFER
        {
            STREAM_STATE streamState;
            URL_INFO url;
            UINT32 dataFrameOffset;

            UINT64 contentLength;
            TOKEN contentType;
            PDATAFRAME recvFrameQueue;
            PFILEBUF recvBufChain;
            HANDLE recvFileHandle = INVALID_HANDLE_VALUE;

            H3_TRANSFER() {}

            constexpr static BUFFER GMAC_KEY = "c81bdf16-da4e-4419-ba26-95ead484a1f3";
            BUFFER static generateFilename(TOKEN hostname, TOKEN path)
            {
                GMAC_DATA gmacData;
                auto keyData = ByteStream(512).writeMany(hostname, path);
                auto filename = ByteStream(512).writeMany(WWW_ROOT, GetGMAC(GMAC_KEY, gmacData, keyData));
                return filename;
            }

            void closeReceiver()
            {
                if (recvBufChain == nullptr && streamState.recvClosed())
                {
                    CloseHandle(recvFileHandle);
                    recvFileHandle = INVALID_HANDLE_VALUE;
                }
            }

            void saveToFile(FILEBUF& fileBuf)
            {
                NEW(fileBuf.ioContext.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
                    {
                        ASSERT(NT_SUCCESS(result));

                        auto&& transfer = *(H3_TRANSFER*)context;
                        auto&& fileBuf = *argv.read<FILEBUF*>(0);
                        auto bytesTransferred = argv.read<DWORD>(1);

                        REMOVE_LINK(&transfer.recvBufChain, fileBuf);
                        getService().freeFileBuf(fileBuf);

                        transfer.closeReceiver();

                        ASSERT(bytesTransferred == fileBuf.dataStream.count());
                    }, this, &fileBuf);

                auto result = File.Write(recvFileHandle, fileBuf.fileOffset, fileBuf.dataStream.toBuffer(), fileBuf.ioContext.start());
                ASSERT(NT_SUCCESS(result));
            }

            void writeRecvData(UINT64 recvOffset, MBUF_READER& recvBuf)
            {
                for (auto fileBuf = recvBufChain; fileBuf && recvBuf; fileBuf = fileBuf->next)
                {
                    auto&& dataStream = fileBuf->dataStream;
                    INT32 delta = INT32(recvOffset - fileBuf->fileOffset);
                    if (delta > 0 && delta < INT32(dataStream.size()))
                    {
                        auto buffer = recvBuf.writeBytes(dataStream.subStream(delta));
                        dataStream.setCount(max(dataStream.count(), delta + buffer.length()));
                    }
                }
                while (recvBuf.chainBytes() > 0)
                {
                    auto&& nextBuf = getService().allocFileBuf(UINT32(contentLength / 4));
                    auto prevBuf = APPEND_LINK(&recvBufChain, nextBuf);
                    nextBuf.fileOffset = prevBuf ? prevBuf->fileOffset + prevBuf->dataStream.size() : 0;
                    recvBuf.writeBytes(nextBuf.dataStream);
                }
                if (recvBuf.endOfStream())
                {
                    for (auto recvBuf = recvBufChain; recvBuf; recvBuf = recvBuf->next)
                    {
                        saveToFile(*recvBuf);
                    }
                }
            }

            NTSTATUS initReceiver()
            {
                auto keyData = ByteStream(512).writeMany(url.hostname, url.path);
                GMAC_DATA gmacData;
                auto filename = ByteStream(512).writeMany(WWW_ROOT, GetGMAC(GMAC_KEY, gmacData, keyData));
                auto status = File.CreateNoCache(filename, recvFileHandle, contentLength);
                return status;
            }

            void parseResponseFrames()
            {
                streamState.handleRecvFrames(GetQuicSession(), [](MBUF_READER& mbuf, H3_TRANSFER& transfer, H3_SESSION& h3Session)
                    {
                        if (transfer.dataFrameOffset == 0)
                        {
                            h3Session.parseResponseHeader(mbuf, transfer);
                        }
                        else
                        {
                            transfer.writeRecvData(mbuf.streamOffset() - transfer.dataFrameOffset, mbuf);
                        }
                    }, *this, GetQuicSession().appSession);
            }

            void parseRequestFrames()
            {
                streamState.handleRecvFrames(GetQuicSession(), [](MBUF_READER& mbuf, H3_TRANSFER& transfer, H3_SESSION& h3Session)
                    {
                        if (mbuf.endOfStream())
                        {
                            h3Session.parseRequest(mbuf, transfer);
                        }
                    }, *this, GetQuicSession().appSession);
            }

            PFILEBUF sendBufChain;
            HANDLE sendFileHandle;

            void readFileData(FILEBUF& fileBuf)
            {
                NEW(fileBuf.ioContext.task, [](PVOID context, NTSTATUS result, STASK_ARGV args)
                    {
                        auto&& transfer = *(H3_TRANSFER*)context;
                        auto&& fileBuf = *args.read<FILEBUF*>(0);
                        auto bytesTransferred = args.read<DWORD>(1);

                        fileBuf.dataStream.setCount(bytesTransferred);
                    }, this, &fileBuf);

                File.Read(sendFileHandle, fileBuf.fileOffset, fileBuf.dataStream, fileBuf.ioContext);
            }

            NTSTATUS readFileData(UINT32 bufSize)
            {
                NTSTATUS status = STATUS_SUCCESS;
                auto lastBuf = LAST_LINK(&sendBufChain);
                auto fileOffset = lastBuf ? lastBuf->fileOffset + lastBuf->dataStream.size() : 0;
                if (fileOffset < contentLength)
                {
                    bufSize = min(bufSize, UINT32(contentLength - fileOffset));
                    auto&& fileBuf = getService().allocFileBuf(UINT32(bufSize));
                    fileBuf.fileOffset = fileOffset;
                    APPEND_LINK(&sendBufChain, fileBuf);

                    NEW(fileBuf.ioContext.task, [](PVOID context, NTSTATUS result, STASK_ARGV args)
                        {
                            auto&& transfer = *(H3_TRANSFER*)context;
                            auto&& fileBuf = *args.read<FILEBUF*>(0);
                            auto bytesTransferred = args.read<DWORD>(1);

                            fileBuf.dataStream.setCount(bytesTransferred);
                        }, this, &fileBuf);

                    status = File.Read(sendFileHandle, fileBuf.fileOffset, fileBuf.dataStream, fileBuf.ioContext);
                }
                return status;
            }

            constexpr static BUFFER WWW_ROOT = "public\\";
            NTSTATUS initSender(BUFFER filename)
            {
                auto result = STATUS_UNSUCCESSFUL;
                do
                {
                    filename = ByteStream(512).writeMany(WWW_ROOT, filename);
                    auto status = File.OpenNoCache(filename, sendFileHandle, contentLength);
                    VERIFY_STATUS;

                    status = readFileData(UINT32(contentLength / 4));
                    VERIFY_STATUS;

                    status = readFileData(UINT32(contentLength / 4));
                    VERIFY_STATUS;

                    result = STATUS_SUCCESS;
                } while (false);
                return result;
            }

            void sendFrames(UINT32 sendWindow)
            {
                sendWindow = min(streamState.sendCredit(), sendWindow);
                MBUF_STREAM sendStream{ GetQuicSession()};

                for (auto buf = sendBufChain; buf && sendWindow > 0; buf = buf->next)
                {
                    auto fileOffset = streamState.sendOffset - dataFrameOffset;
                    if (buf->fileOffset <= fileOffset && buf->writeOffset() > fileOffset)
                    {
                        auto data = buf->dataStream.toBuffer();
                        data.shift(UINT32(fileOffset - buf->fileOffset));

                        auto sendData = data.readBytes(min(data.length(), sendWindow));
                        sendWindow -= sendData.length();

                        sendStream.beginStream(streamState);
                        sendStream.writeBytes(sendData);
                        sendStream.endStream();
                    }
                }
            }

            explicit operator bool() const { return streamState.streamId != -1; }

            void close()
            {
                streamState.streamId = -1;
            }
        };
        using H3_TRANSFER_STREAM = DATASTREAM<H3_TRANSFER, SESSION_STACK>;

        struct CONTROL_STREAM
        {
            STREAM_STATE sendState;
            STREAM_STATE recvState;
        };

        CONTROL_STREAM controlStream;

        QPACK::ENCODER qpackEncoder;
        QPACK::DECODER qpackDecoder;

        H3_TRANSFER_STREAM transferRequests;
        H3_TRANSFER_STREAM transferResponses;

        H3_TRANSFER* findTransferContext(H3_TRANSFER_STREAM& transferStream, UINT64 streamId)
        {
            for (auto&& transfer : transferStream.toRWBuffer())
            {
                if (transfer.streamState.streamId == streamId)
                {
                    return &transfer;
                }
            }
            return nullptr;
        }

        H3_TRANSFER& createTransferContext(H3_TRANSFER_STREAM& transferStream)
        {
            for (auto&& transfer : transferStream.toRWBuffer())
            {
                if (!transfer)
                {
                    return transfer;
                }
            }
            return transferStream.append();
        }

        H3_TRANSFER& createTransferRequest()
        {
            auto&& newRequest = createTransferContext(transferRequests);
            quicSession().streamLimits.allocBidirStream(newRequest.streamState);
            return newRequest;
        }

        H3_TRANSFER* findTransferContext(UINT64 streamId)
        {
            if (quicSession().streamLimits.isRemoteBidir(streamId))
            {
                auto transfer = findTransferContext(transferResponses, streamId);
                if (transfer == nullptr)
                {
                    auto&& newTransfer = createTransferContext(transferResponses);
                    quicSession().streamLimits.initBidirStream(newTransfer.streamState, streamId);
                    transfer = &newTransfer;
                }
                return transfer;
            }
            else
            {
                return findTransferContext(transferRequests, streamId);
            }
        }

        STREAM_STATE* getStreamState(DATAFRAME& recvFrame)
        {
            STREAM_STATE* streamState = nullptr;
            if (recvFrame.streamId & STREAM_TYPE_OUTGOING)
            {
                if (recvFrame.streamOffset == 0)
                {
                    auto streamType = recvFrame.dataBuf.readByte();
                    streamState = (streamType == H3_STREAM_TYPE_ENCODER_STREAM) ? &qpackDecoder.recvState
                        : (streamType == H3_STREAM_TYPE_DECODER_STREAM) ? &qpackEncoder.recvState
                        : (streamType == H3_STREAM_TYPE_CONTROL_STREAM) ? &controlStream.recvState : nullptr;
                    ASSERT(streamState);
                    if (streamState)
                    {
                        quicSession().streamLimits.initOutgoingStream(*streamState, recvFrame.streamId);
                        streamState->recvOffset = 1;
                        recvFrame.rebase();
                    }
                    if (recvFrame.dataBuf.length() == 0)
                    {
                        quicSession().releaseDataFrame(recvFrame);
                        return nullptr;
                    }
                }
                else
                {
                    streamState = (qpackDecoder.recvState.streamId == recvFrame.streamId) ? &qpackDecoder.recvState
                        : (qpackEncoder.recvState.streamId == recvFrame.streamId) ? &qpackEncoder.recvState
                        : (controlStream.recvState.streamId == recvFrame.streamId) ? &controlStream.recvState : nullptr;
                }
            }
            else
            {
                if (auto transferContext = findTransferContext(recvFrame.streamId))
                    streamState = &transferContext->streamState;
                else DBGBREAK();
            }
            ASSERT(streamState);
            return streamState;
        }

        void parseEncoderResponse()
        {
            qpackEncoder.recvState.handleRecvFrames(quicSession(), [](MBUF_READER& mbuf, H3_SESSION& h3Session)
                {
                    auto commands = mbuf.readBytes(mbuf.chainBytes());
                    h3Session.qpackEncoder.parseCommands(commands);
                }, *this);
        }

        void parseEncoderRequest()
        {
            qpackDecoder.recvState.handleRecvFrames(quicSession(), [](MBUF_READER& mbuf, H3_SESSION& h3Session)
                {
                    auto commands = mbuf.readBytes(mbuf.chainBytes());
                    h3Session.qpackDecoder.parseCommands(commands);
                }, *this);
        }

        void parseControlFrame()
        {
            controlStream.recvState.handleRecvFrames(quicSession(), [](MBUF_READER& mbuf, H3_SESSION& h3Session)
                {
                    if (auto frame = h3Session.parseH3Frame(mbuf))
                    {
                        ASSERT(frame.frameType == H3_FRAME_TYPE_SETTINGS);
                        auto settingsData = frame.frameData;
                        while (settingsData)
                        {
                            auto name = settingsData.readQInt();
                            auto value = settingsData.readQInt();
                            if (name == H3_SETTING_QPACK_MAX_TABLE_CAPACITY)
                            {

                            }
                            else if (name == H3_SETTING_MAX_FIELD_SECTION_SIZE)
                            {

                            }
                            else if (name == H3_SETTING_QPACK_BLOCKED_STREAMS)
                            {

                            }
                            else DBGBREAK();
                        }
                        h3Session.quicSession().runTask([](PVOID context, NTSTATUS, STASK_ARGV)
                            {
                                auto&& quicSession = *(QUICH3_SESSION*)context;
                                quicSession.isServer ? quicSession.appSession.onServerReady() : quicSession.appSession.onClientReady();
                            });
                    }
                }, *this);
        }

        H3_SESSION()
        {
        }

        void init()
        {
        }

        void writeStreamType(BYTESTREAM& frameStream, UINT64 streamId, UINT8 streamType)
        {
            frameStream.writeByte(FRAMETYPE_STREAM | FRAMETYPE_STREAM_FLAG_LENGTH);
            frameStream.writeQInt(streamId);
            frameStream.writeQInt(1);
            frameStream.writeByte(streamType);
        }

        void onConnect()
        {
            controlStream.sendState.streamId = quicSession().streamLimits.makeOutgoingStreamId(0);
            qpackEncoder.sendState.streamId = quicSession().streamLimits.makeOutgoingStreamId(2);
            qpackDecoder.sendState.streamId = quicSession().streamLimits.makeOutgoingStreamId(3);

            transferRequests.reserve(quicSession().isServer ? 2 : 16);
            transferResponses.reserve(quicSession().isServer ? 16 : 2);

            auto&& sendPacket = quicSession().allocSendPacket();

            quicSession().formatStreamFrame(sendPacket.frameStream, controlStream.sendState,
                [](BYTESTREAM& frameStream, H3_SESSION& h3Session, QUICH3_SESSION& quicSession)
                {
                    frameStream.writeByte(H3_STREAM_TYPE_CONTROL_STREAM);
                    frameStream.writeQInt(H3_FRAME_TYPE_SETTINGS);

                    auto lengthOffset = frameStream.saveOffset(2);
                    frameStream.writeQInt(H3_SETTING_QPACK_MAX_TABLE_CAPACITY);
                    frameStream.writeQInt(QPACK_MAX_TABLE_CAPACITY);
                    frameStream.writeQInt(H3_SETTING_MAX_FIELD_SECTION_SIZE);
                    frameStream.writeQInt(MAX_FIELD_SECTION_SIZE);
                    frameStream.writeQInt(H3_SETTING_QPACK_BLOCKED_STREAMS);
                    frameStream.writeQInt(QPACK_BLOCKED_STREAMS);
                    lengthOffset.writeQLength();

                }, *this, quicSession());

            quicSession().formatStreamFrame(sendPacket.frameStream, qpackEncoder.sendState,
                [](BYTESTREAM& frameStream)
                {
                    frameStream.writeByte(H3_STREAM_TYPE_ENCODER_STREAM);
                });
            quicSession().formatStreamFrame(sendPacket.frameStream, qpackDecoder.sendState,
                [](BYTESTREAM& frameStream)
                {
                    frameStream.writeByte(H3_STREAM_TYPE_DECODER_STREAM);
                });

            quicSession().sendPacket(sendPacket);
        }

        struct H3_FRAME
        {
            UINT64 frameType = -1;
            UINT64 frameLength = -1;
            BUFFER frameData;

            explicit operator bool() const { return frameType == H3_FRAME_TYPE_DATA || frameData; }
        };

        template <typename FUNC, typename ... ARGS>
        void formatH3Frame(MBUF_QUIC_STREAM& packetStream, UINT8 frameType, FUNC callback, ARGS&& ... args)
        {
            packetStream.reserve(30);
            packetStream.writeQInt(frameType);

            auto h3FrameLength = packetStream.saveOffset();
            callback(packetStream, args ...);
            h3FrameLength.writeQLength();
        }

        void formatH3Frame(MBUF_QUIC_STREAM& packetStream, UINT8 frameType, BUFFER contentBody)
        {
            packetStream.reserve(20);
            packetStream.writeQInt(frameType);
            packetStream.writeQInt(contentBody.length());
            packetStream.writeBytes(contentBody);
        }

        H3_FRAME parseH3Frame(MBUF_READER& mbuf)
        {
            H3_FRAME frame;
            if (mbuf)
            {
                auto revertMark = mbuf.mark();

                frame.frameType = mbuf.readQInt();
                frame.frameLength = mbuf.readQInt();

                if (frame.frameType != -1 && frame.frameLength != -1)
                {
                    if (frame.frameType != H3_FRAME_TYPE_DATA)
                    {
                        frame.frameData = mbuf.readBytes((UINT32)frame.frameLength);
                    }
                }

                if (!frame)
                {
                    mbuf.revert(revertMark);
                }
            }
            return frame;
        }

        bool validateResponse(H3_TRANSFER& transfer, QPREADER section)
        {
            auto result = false;
            do
            {
                auto status = FindField(section, QPACK_STATUS);
                if (status.value != QPACK_200)
                {
                    DBGBREAK();
                    break;
                }

                transfer.contentLength = Tokens.getNumber(FindField(section, QPACK_content_length).value);
                transfer.contentType = FindField(section, QPACK_content_type).value;

                result = transfer.contentLength > 0;
            } while (false);
            return result;
        }

        void parseResponseHeader(MBUF_READER& mbuf, H3_TRANSFER& transfer)
        {
            auto restorePoint = mbuf.mark();
            while (auto h3Frame = parseH3Frame(mbuf))
            {
                if (h3Frame.frameType == H3_FRAME_TYPE_HEADERS)
                {
                    parseEncoderRequest();
                    if (auto headers = qpackDecoder.parseHeader(h3Frame.frameData))
                    {
                        auto status = validateResponse(transfer, headers);
                    }
                    else
                    {
                        mbuf.revert(restorePoint);
                        break;
                    }
                }
                else if (h3Frame.frameType == H3_FRAME_TYPE_DATA)
                {
                    transfer.dataFrameOffset = (UINT32)mbuf.streamOffset();
                    transfer.contentLength = h3Frame.frameLength;
                    transfer.initReceiver();
                }
            }
        }

        bool serviceRequest(H3_TRANSFER& transfer, QPREADER section, BUFFER contentBody)
        {
            auto path = FindField(section, QPACK_PATH);
            auto hostname = FindField(section, QPACK_AUTHORITY);
            auto contentType = FindField(section, QPACK_content_type);

            auto filename = path.value == HTTP_SLASH ? "index.html" : NameToString(path.value);
            if (filename)
            {
                auto contentType = QP_content_type_html;
                auto status = transfer.initSender(filename);
                if (NT_SUCCESS(status))
                {
                    sendResponse(transfer, QP_content_type_html, transfer.contentLength);
                }

            }
            else DBGBREAK();
            return true;
        }

        void sendResponse(H3_TRANSFER& transfer, QPFIELD contentType, UINT64 contentLength)
        {
            auto&& fieldSection = qpackEncoder.newSection();
            fieldSection.addField(QP_status_200);
            fieldSection.addField(serverField);
            fieldSection.addField({ QP_date, SessionTokens.currentTime() });
            fieldSection.addField(contentType);
            fieldSection.addField({ QP_content_length, SessionTokens.createNumber(contentLength) });

            auto&& packetStream = MBUF_STREAM{ quicSession()};

            qpackEncoder.formatCommands(packetStream);

            packetStream.beginStream(transfer.streamState);
            formatH3Frame(packetStream, H3_FRAME_TYPE_HEADERS, [](MBUF_QUIC_STREAM& packetStream, H3_SESSION& h3Session, H3_TRANSFER& content, FIELD_SECTION& fieldSection)
                {
                    fieldSection.formatSection(packetStream);
                }, *this, transfer, fieldSection);

            packetStream.writeQInt(H3_FRAME_TYPE_DATA);
            packetStream.writeQInt(contentLength);
            packetStream.endStream();

            packetStream.sendPackets();
        }

        void parseRequest(MBUF_READER& mbuf, H3_TRANSFER& transfer)
        {
            auto restorePoint = mbuf.mark();
            QPREADER fieldSection;
            BUFFER contentBody;
            while (auto h3Frame = parseH3Frame(mbuf))
            {
                if (h3Frame.frameType == H3_FRAME_TYPE_HEADERS)
                {
                    parseEncoderRequest();
                    fieldSection = qpackDecoder.parseHeader(h3Frame.frameData);
                }
                else if (h3Frame.frameType == H3_FRAME_TYPE_DATA)
                {
                    ASSERT(mbuf.chainBytes() >= h3Frame.frameLength);
                    contentBody = mbuf.readBytes(UINT32(h3Frame.frameLength));
                }
            }
            if (fieldSection)
            {
                serviceRequest(transfer, fieldSection, contentBody);
            }
            else mbuf.revert(restorePoint);
        }

        void sendRequest(BUFFER url, QPFIELD method = QP_method_get, QPFIELD contentType = QPFIELD(), BUFFER contentBody = NULL_BUFFER)
        {
            auto&& content = createTransferRequest();

            Http.parseUrl<SESSION_STACK>(url, content.url);

            auto&& fieldSection = qpackEncoder.newSection();
            fieldSection.addField(QP_method_get);
            fieldSection.addField({ QP_authority, content.url.hostname });
            fieldSection.addField({ QP_path, content.url.path });
            fieldSection.addField(userAgentField);
            fieldSection.addField(QP_accept_star_star);
            fieldSection.addField(QP_accept_encoding_gzip_def_br);

            auto&& packetStream = MBUF_STREAM{ quicSession()};

            qpackEncoder.formatCommands(packetStream);

            packetStream.beginStream(content.streamState);
            formatH3Frame(packetStream, H3_FRAME_TYPE_HEADERS, [](MBUF_QUIC_STREAM& packetStream, H3_SESSION& h3Session, H3_TRANSFER& content, FIELD_SECTION& fieldSection)
                {
                    fieldSection.formatSection(packetStream);
                }, *this, content, fieldSection);
            if (contentBody)
            {
                formatH3Frame(packetStream, H3_FRAME_TYPE_DATA, contentBody);
            }
            packetStream.finalizeStream();

            packetStream.sendPackets();
        }

        QPFIELD userAgentField;
        void onClientReady()
        {
            userAgentField = qpackEncoder.encodeField({ QP_user_agent, SystemService().userAgent });
            sendRequest("https://localhost/");
        }

        QPFIELD serverField;
        void onServerReady()
        {
            serverField = qpackEncoder.encodeField({ QP_server, SystemService().serverBrand});
        }

        void onRecvStreamFrame(DATAFRAME& recvFrame)
        {
            if (auto streamState = getStreamState(recvFrame))
            {
                streamState->onRecvFrame(recvFrame);
            }
        }

        void forwardStreamFrames()
        {
            for (auto&& transfer : transferRequests.toRWBuffer())
            {
                if (transfer.streamState && transfer.streamState.recvFrameQueue)
                {
                    transfer.parseResponseFrames();
                }
            }

            for (auto&& transfer : transferResponses.toRWBuffer())
            {
                if (transfer.streamState && transfer.streamState.recvFrameQueue)
                {
                    transfer.parseRequestFrames();
                }
            }

            if (controlStream.recvState.hasRecvBytes())
                parseControlFrame();

            if (qpackEncoder.recvState.hasRecvBytes())
                parseEncoderResponse();
        }

        void onRecvCryptoFrames(QUIC_HEADER& recvHeader, MBUF_READER& mbuf) { DBGBREAK(); }

    };
    bool isServer;

    SERVICE_STACK serviceStack;
    SCHEDULER_INFO<> scheduler;
    QUIC_RETRY quicRetry;

    QPACKET::PACKET_POOL packetPool;
    DATASTREAM<QUIC_SOCKET, SERVICE_STACK> socketPool;

    DATASTREAM<QUICH3_SESSION*, SERVICE_STACK> sessionPool;

    auto&& getScheduler() { return scheduler; }

    void runTask(STASK& task, NTSTATUS status, auto&& ... args)
    {
        scheduler.runTask(task, status, args ...);
    }

    static inline H3_SERVICE& getService()
    {
        auto&& stack = GetServiceStack();
        auto service = CONTAINING_RECORD(&stack, H3_SERVICE, serviceStack);
        return *service;
    }

    template <typename ... ARGS>
    void createTask(STASK& task, TASK_HANDLER handler, ARGS&& ... args)
    {
        new (&task) STASK(handler, (PVOID)this, args ...);
    }

    QUICH3_SESSION* findSession(IPENDPOINT& remoteIP)
    {
        auto list = sessionPool.toRWBuffer();

        for (auto&& session : list)
        {
            if (remoteIP == session->udpSocket.remoteAddress)
            {
                SetSessionStack(session->sessionStack);
                return session;
            }
        }
        return nullptr;
    }

    QUICH3_SESSION& createSession(QUIC_SOCKET& udpSocket)
    {
        auto list = sessionPool.toRWBuffer();
        for (auto&& session : list)
        {
            if (session->isClosed())
            {
                SetSessionStack(session->sessionStack);
                QUICH3_SESSION::reset(*session, *this, udpSocket, isServer);
                return *session;
            }
        }
        auto&& newSession = StackAlloc<QUICH3_SESSION, SERVICE_STACK>(*this, udpSocket, isServer);
        sessionPool.append(&newSession);
        SetSessionStack(newSession.sessionStack);
        newSession.init();
        return newSession;
    }

    void onSocketReceive(QUIC_SOCKET& udpSocket, QPACKET& recvPacket)
    {
        do
        {
            auto&& quicHeader = recvPacket.parseHeader();
            auto session = findSession(recvPacket.recvFrom);
            if (quicHeader.packetType == PACKET_INITIAL)
            {
                ASSERT(session == nullptr);

                if (BUFFER recvToken = quicHeader.recvToken)
                {
                    auto retryData = quicRetry.generateRetryToken(recvPacket, quicHeader);
                    if ((quicHeader.destinationCID == retryData.readBytes(RETRY_CID_LENGTH)) &&
                        (recvToken.readBytes(RETRY_TOKEN_DIGEST_SIZE) == retryData.readBytes(RETRY_TOKEN_DIGEST_SIZE)))
                    {
                        session = &createSession(udpSocket);
                        session->accept(recvPacket);
                    }
                    else
                    {
                        DBGBREAK();
                        break;
                    }
                }
                else
                {
                    quicRetry.sendRetryPacket(udpSocket.socketHandle, recvPacket, quicHeader);
                    break;
                }
            }
            ASSERT(session);
            session->onRecvPacket(recvPacket);
        } while (false);
    }

    void generateToken(BYTESTREAM& packetStream, BUFFER sourceCID, BUFFER destCID, BUFFER hostname)
    {
        // no-op
    }

    void onStopSending(UINT64 streamId, UINT64 errorCode)
    {
        // peer app is no longer willing to receive data
    }

    void onResetStream(UINT64 streamId, UINT64 errorCode, UINT64 finalSize)
    {
        // peer stopped sending, discard received data
    }

    void onOutOfDataCredits(UINT64 byteCount)
    {
        // bytes received so far (in all the streams)
    }

    void onOutOfDataCredits(UINT64 streamId, UINT64 byteCount)
    {
        // bytes received so far on the given stream
    }

    void onOutOfStreamCredits(bool isBirectional, UINT64 streamCount)
    {
        // sender can't send any more streams for lack of credit
    }

    void onSetStreamCredit(bool isBidirectional, UINT64 streamCount)
    {
        // update send allowance
    }

    void onSetDataCredit(UINT64 byteCount)
    {
        // update cumulative send bytes allowance (for all the streams)
    }

    void onSetDataCredit(UINT64 streamId, UINT64 byteCount)
    {
        // update send byte allowance for the specified stream
    }

    void onConnectionClose(UINT64 errorCode, BUFFER reason)
    {
        // 
    }

    QUIC_SOCKET& createSocket()
    {
        auto socketList = socketPool.toRWBuffer();
        for (auto&& socket : socketList)
        {
            if (socket.isClosed())
                return socket;
        }
        return socketPool.append(*this);
    }

    NTSTATUS startServer(UINT16 port)
    {
        ASSERT(isServer);
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            sessionPool.reserve(64);

            for (UINT32 i = 0; i < BUFPOOL_MAX; i++)
            {
                auto result = fileBufPools[i]->init();
                ASSERT(NT_SUCCESS(result));
            }

            packetPool.init();

            auto&& udpSocket = createSocket();
            udpSocket.init(port);
            udpSocket.beginReceive();

            status = STATUS_SUCCESS;
        } while (false);
        return status;
    }

    NTSTATUS initClient()
    {
        ASSERT(!isServer);
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            packetPool.init(256);

            for (UINT32 i = 0; i < BUFPOOL_MAX; i++)
            {
                auto result = fileBufPools[i]->init();
                ASSERT(NT_SUCCESS(result));
            }

            status = STATUS_SUCCESS;
        } while (false);
        return status;
    }

    constexpr static BUFFER ALPN = "h3";
    TOKEN alpnService()
    {
        return CreateServiceName(ALPN);
    }

    QPACKET& allocPacket()
    {
        return packetPool.alloc();
    }

    void doConnect(TOKEN serverName, UINT16 port)
    {
        auto&& udpSocket = createSocket();

        udpSocket.init(NameToString(serverName), port, [](PVOID context, NTSTATUS status, STASK_ARGV argv)
            {
                auto&& udpSocket = *(QUIC_SOCKET*)context;
                auto&& serverName = argv.read<TOKEN>(0);
                if (NT_SUCCESS(status))
                {
                    auto&& service = udpSocket.service;
                    auto&& newSession = service.createSession(udpSocket);
                    newSession.init();
                    udpSocket.clientSession = &newSession;
                    newSession.doConnect(serverName);
                }
                else
                {
                    udpSocket.close();
                }
            }, &udpSocket, serverName);
    }

    void init(UINT32 stackSize)
    {
        scheduler.init();
        serviceStack.init(stackSize);

        quicRetry.init();
    }
    H3_SERVICE(bool isServer) : scheduler(serviceStack), isServer(isServer) {}
};
