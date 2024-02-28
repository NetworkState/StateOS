#pragma once

// Copyright (C) 2024 Network State.
// All rights reserved.

struct HTTP_HEADER
{
    TOKEN name = NULL_NAME;
    USTRING value;

    HTTP_HEADER() {}
    HTTP_HEADER(TOKEN name, USTRING value) : name(name), value(value) {}

    auto match(TOKEN matchName) const { return name == matchName; }
    explicit operator bool() const { return IsValidRef(*this) && name; }
};

using HTTP_HEADERS = STREAM_READER<const HTTP_HEADER>;

enum class TRANSFER_STATE : UINT16
{
    WAITING_FOR_REQUEST = 0x01,
    WAITING_FOR_RESPONSE = 0x02,
    RECV_TO_FILE = 0x10,
    SEND_FROM_FILE = 0x20,
    RECV_TO_MEMORY = 0x40,
    IS_IDLE = 0x80,
};
DEFINE_ENUM_FLAG_OPERATORS(TRANSFER_STATE);

enum class SESSION_FLAGS : UINT16
{
    IS_UNKNOWN = 0x01,
    IS_CONNECTED = 0x02,
    IS_KEEP_ALIVE = 0x04,
    IS_CHUNK_TRANSFER = 0x08,
};
DEFINE_ENUM_FLAG_OPERATORS(SESSION_FLAGS);

template <typename SERVICE>
struct HTTP_SESSION
{
    using enum TRANSFER_STATE;
    using enum SESSION_FLAGS;

    TRANSFER_STATE transferState = IS_IDLE;

    constexpr static UINT32 CONNECTED = 0x0100;
    constexpr static UINT32 KEEP_ALIVE = 0x0200;
    constexpr static UINT32 CHUNK_TRANSFER = 0x0400;

    SESSION_FLAGS sessionFlags = IS_UNKNOWN;
    void setState(SESSION_FLAGS flag) { sessionFlags |= flag; }
    void clearState(SESSION_FLAGS flag) { sessionFlags &= ~flag; };
    bool isSet(SESSION_FLAGS flag) { return bool(sessionFlags & flag); }

    bool isIdle() { return isSet(IS_CONNECTED) && transferState == IS_IDLE; }

    SERVICE& service;
    SOCKET socketHandle = INVALID_SOCKET;

    struct IO_STATE
    {
        IOCALLBACK control{ IO_SOCK_CTRL };
        IOCALLBACK recv{ IO_SOCK_RECV };
        IOCALLBACK send{ IO_SOCK_SEND };
        IOCALLBACK fileRead{ IO_FILE_READ };
        IOCALLBACK fileWrite{ IO_FILE_WRITE };
    } ioState;

    struct HTTP_TRANSFER
    {
        HTTP_SESSION& session;

        DATASTREAM<HTTP_HEADER, SESSION_STACK, 16> headerFields;
        BYTESTREAM headerBytes;
        UINT64 contentLength;
        BYTESTREAM bodyStream;

        TOKEN method;
        BUFFER path;
        BUFFER status;

        HANDLE fileHandle = INVALID_HANDLE_VALUE;
        UINT64 fileOffset = 0;
        auto headers() { return headerFields.toBuffer(); }
        auto body() { return bodyStream.toBuffer(); }

        void sendResponse(BUFFER status, BUFFER additionalHeaders = NULL_BUFFER, BUFFER contentBody = NULL_BUFFER)
        {
            session.sendResponse(status, additionalHeaders, contentBody);
        }

        void sendResponse(BUFFER status, BUFFER additionalHeaders, HANDLE fileHandle)
        {
            session.sendResponse(status, additionalHeaders, fileHandle);
        }
    } transfer;

    bool isServer;
    SESSION_STACK sessionStack;

    DNS_QUERY dnsQuery;
    URL_INFO downloadUrl;

    TLS13_HANDSHAKE<HTTP_SESSION> tlsHandshake;

    HTTP_SESSION(SERVICE& service, bool isServer) : isServer(isServer), service(service), dnsQuery(service.scheduler), tlsHandshake(*this, isServer), transfer(*this) {}

    auto&& getScheduler()
    {
        return service.scheduler;
    }

    BUFFER getTLScert() { return SystemService().AKsignKey.certBytes; }
    BUFFER getTLSpublicKey() { return BUFFER(SystemService().AKsignKey.signPublicKey); }

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

    void formatClientTransportParams(BYTESTREAM&) {}
    void parseTransportParams(BUFFER) {}

    auto parseHeaders(BUFFER& recvData, BUFFER& first, BUFFER& second)
    {
        BUFFER headerLines;
        if ((transfer.headerBytes.count() == 0) && (headerLines = String.splitStringIf(recvData, CRLF_CRLF)))
        {
            transfer.headerBytes.writeSessionBytes(headerLines);
            headerLines = transfer.headerBytes.toBuffer();
        }
        else
        {
            transfer.headerBytes.writeSessionBytes(recvData);
            recvData = transfer.headerBytes.toBuffer();
            headerLines = String.splitStringIf(recvData, CRLF_CRLF);
        }

        auto&& headers = transfer.headerFields.clear();
        if (headerLines)
        {
            auto startLine = String.splitString(headerLines, CRLF);
            first = String.splitChar(startLine, WHITESPACE_PATTERN);
            second = String.splitChar(startLine, WHITESPACE_PATTERN);

            while (auto line = String.splitString(headerLines, CRLF))
            {
                auto header = String.splitChar(line, HTTP_HEADER_NAME_PATTERN);
                auto headerName = CreateName(header);

                headers.append(headerName, line);
            }
        }
        return headers.toBuffer();
    }

    USTRING findHeader(STREAM_READER<HTTP_HEADER> headers, TOKEN name)
    {
        USTRING result;
        for (UINT32 i = 0; i < headers.length(); i++)
        {
            if (heders.at(i).name == name)
            {
                result = headers..at(i).value;
                break;
            }
        }
        return result;
    }

    template <typename LAMBDA>
    void findHeaders(STREAM_READER<HTTP_HEADER> headers, TOKEN name, LAMBDA callback)
    {
        for (UINT32 i = 0; i < headers.length(); i++)
        {
            if (heders.at(i).name == name)
            {
                callback(*this, headers.at(i).value);
            }
        }
    }

    void parseResponse(USTRING code, STREAM_READER<const HTTP_HEADER> headers)
    {
        if (String.equals(code, "200"))
        {
            for (auto&& header : headers)
            {
                if (header.name == HTTP_Content_Length)
                {
                    transfer.contentLength = (UINT32)String.toNumber(header.value);
                }
                else if (header.name == HTTP_Transfer_Encoding)
                {
                    if (String.equals(header.value, "chunked")) setState(IS_CHUNK_TRANSFER);
                }
                else if (header.name == HTTP_Connection)
                {
                    if (String.equals(header.value, "keep-alive")) setState(IS_KEEP_ALIVE);
                }
                else if (header.name == HTTP_Set_Cookie)
                {
                    Http.parseSetCookie(header.value, service.cookieTable.append());
                }
            }

            auto filename = ByteStream(512).writeMany(DATA_DIRECTORY, downloadUrl.path);
            auto status = File.Create(filename, transfer.fileHandle, transfer.contentLength);
            if (NT_SUCCESS(status))
            {
                transferState = RECV_TO_FILE;
            }
        }
        else DBGBREAK();
    }

    void handleRedirect(USTRING code, STREAM_READER<const HTTP_HEADER> headers)
    {
    }

    constexpr static BUFFER DATA_DIRECTORY = "www-root";
    BYTESTREAM fileStream;

    void onTransferComplete()
    {
        if (isSet(IS_KEEP_ALIVE))
        {
            transfer.headerBytes.clear();
            transferState = isServer ? WAITING_FOR_REQUEST : IS_IDLE;
        }
        else
        {
            closesocket(socketHandle);
            socketHandle = INVALID_SOCKET;
        }
    }

    void onReadComplete(NTSTATUS result, UINT32 bytesRead)
    {
        if (NT_SUCCESS(result) && bytesRead > 0)
        {
            transfer.fileOffset += bytesRead;
            tlsHandshake.sendStream.expand(bytesRead);
            tlsHandshake.finishSendData();
        }
        else
        {
            ASSERT(result == STATUS_END_OF_FILE);
            CloseHandle(transfer.fileHandle);
            onTransferComplete();
        }
    }

    void onWriteComplete(NTSTATUS result, UINT32 bytesRead)
    {
        if (transferState == RECV_TO_FILE)
        {
            tlsHandshake.releaseRecvBuf();
        }
        else DBGBREAK();
    }

    NTSTATUS onSendComplete(NTSTATUS status)
    {
        auto result = STATUS_SUCCESS;
        if (!NT_SUCCESS(status))
        {
            ASSERT(0);
        }
        if (transferState == SEND_FROM_FILE)
        {
            auto sendStream = tlsHandshake.beginSendData();
            result = File.Read(transfer.fileHandle, transfer.fileOffset, sendStream, ioState.fileRead);
        }
        return result;
    }

    void onRecvComplete(NTSTATUS status, UINT32 bytesReceived)
    {
        tlsHandshake.recvStream.expand(bytesReceived);
        tlsHandshake.onReceive();
    }

    void setupIoTasks()
    {
        createTask(ioState.send.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto&& session = getSession(context);
                auto bytesTransferred = argv.read<DWORD>(0);
                session.onSendComplete(result);
            });

        createTask(ioState.recv.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto&& session = getSession(context);
                auto bytesTransferred = argv.read<DWORD>(0);
                session.onRecvComplete(result, bytesTransferred);
            });

        createTask(ioState.fileRead.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto&& session = getSession(context);
                auto bytesTransferred = argv.read<DWORD>(0);
                session.onReadComplete(result, bytesTransferred);
            });

        createTask(ioState.fileWrite.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto&& session = getSession(context);
                auto bytesTransferred = argv.read<DWORD>(0);
                session.onWriteComplete(result, bytesTransferred);
            });

    }

    void parseRequest(USTRING method, USTRING path, STREAM_READER<const HTTP_HEADER> headers)
    {
        auto methodName = FindName(method);
        if (methodName == HTTP_GET)
        {
            service.onRequest(transfer);
        }
        else if (methodName == HTTP_POST)
        {
            if (auto&& lengthField = headers.find(HTTP_Content_Length))
            {
                auto&& contentLength = transfer.contentLength;

                contentLength = String.toNumber(lengthField.value);
                ASSERT(contentLength > 0);
                transfer.bodyStream.allocReserve<SESSION_STACK>((UINT32)contentLength);

                transferState = RECV_TO_MEMORY;
            }
            else DBGBREAK();
        }
        else DBGBREAK();
    }

    bool onTLSreceive(BUFFER recvData)
    {
        auto holdBuf = false;
        if (transferState == WAITING_FOR_REQUEST)
        {
            BUFFER method, path;
            if (auto headers = parseHeaders(recvData, method, path))
            {
                parseRequest(method, path, headers);
            }
        }
        else if (transferState == WAITING_FOR_RESPONSE)
        {
            BUFFER version, status;
            if (auto headers = parseHeaders(recvData, version, status))
            {
                parseResponse(status, headers);
            }
        }

        if ((transferState == RECV_TO_FILE) && recvData)
        {
            holdBuf = true;
            File.Write(transfer.fileHandle, 0, recvData, ioState.fileWrite.start());
        }
        else if ((transferState == RECV_TO_MEMORY) && recvData)
        {
            transfer.bodyStream.writeBytes(recvData);
            if (transfer.bodyStream.count() >= transfer.contentLength)
            {
                service.onRequest(transfer);
                transferState = WAITING_FOR_REQUEST;
            }
        }
        return holdBuf;
    }

    NTSTATUS sendTLShandshake(BUFFER dataBuffer)
    {
        auto status = SocketSend(socketHandle, dataBuffer);
        if (!NT_SUCCESS(status)) onSocketClose();
        return status;
    }

    NTSTATUS sendTLSdata(BUFFER dataBuffer)
    {
        auto status = SocketSend(socketHandle, dataBuffer, ioState.send);
        if (!NT_SUCCESS(status)) onSocketClose();
        return status;
    }

    void onSocketClose()
    {
        closesocket(socketHandle);
        DebugBreak();
    }

    void onConnect(NTSTATUS status)
    {
        ASSERT(NT_SUCCESS(status));
        setState(IS_CONNECTED);
        transferState = WAITING_FOR_RESPONSE;
        tlsHandshake.sendData(
            [](BYTESTREAM& dataStream, HTTP_SESSION& session)
            {
                dataStream.writeMany("GET /", session.downloadUrl.path, " HTTP/1.1", CRLF);
                Http.formatHeader(dataStream, HTTP_Host, session.downloadUrl.hostname);
                Http.formatHeader(dataStream, HTTP_User_Agent, SystemService().userAgent);
                Http.formatHeader(dataStream, HTTP_Accept, "*/*");
                Http.formatHeader(dataStream, HTTP_Connection, HTTP_Keep_Alive);

                auto cookies = session.service.cookieTable.toBuffer();
                if (cookies)
                {
                    dataStream.writeString("Cookie: ");
                    for (auto cookie : cookies)
                    {
                        if (cookie.domain == session.downloadUrl.hostname)
                        {
                            dataStream.writeMany(cookie.nameValue, ";");
                        }
                    }
                    dataStream.writeString(CRLF);
                }
                dataStream.writeString(CRLF);
            }, *this);
    }

    static void formatResponseCommon(BYTESTREAM& dataStream)
    {
        Http.formatDate(dataStream, HTTP_Date);
        Http.formatHeader(dataStream, HTTP_Server, SystemService().serverBrand);
    }

    void sendResponse(BUFFER status, BUFFER additionalHeaders, BUFFER contentBody)
    {
        tlsHandshake.sendData(
            [](BYTESTREAM& dataStream, HTTP_SESSION& session, BUFFER status, BUFFER additionalHeaders, BUFFER contentBody)
        {
                dataStream.writeMany("HTTP/1.1 ", status, CRLF);
                formatResponseCommon(dataStream);
                dataStream.writeMany(additionalHeaders, CRLF);
                dataStream.writeBytes(contentBody);
        }, * this, status, additionalHeaders, contentBody);
    }

    void sendResponse(BUFFER status, BUFFER additionalHeaders, HANDLE fileHandle)
    {
        transfer.fileHandle = fileHandle;
        transfer.fileOffset = 0;
        transferState = SEND_FROM_FILE;
        tlsHandshake.sendData(
            [](BYTESTREAM& dataStream, HTTP_SESSION& session, BUFFER status, BUFFER additionalHeaders)
            {
                dataStream.writeMany("HTTP/1.1 ", status, CRLF);
                formatResponseCommon(dataStream);
                dataStream.writeMany(additionalHeaders, CRLF);
            }, *this, status, additionalHeaders);
        auto result = onSendComplete(STATUS_SUCCESS);
        ASSERT(NT_SUCCESS(result));
    }

    void beginReceive()
    {
        LogInfo("beginReceive");
        SocketRecv(socketHandle, tlsHandshake.recvStream, ioState.recv);
    }

    void onSocketConnect(NTSTATUS status)
    {
        if (NT_SUCCESS(status))
        {
            setupIoTasks();
            transfer.headerBytes.allocReserve<SESSION_STACK>(1024);

            tlsHandshake.init(downloadUrl.hostname, HTTP_http_1_1);
            tlsHandshake.sendClientHello();

            beginReceive();
        }
        else DBGBREAK();
    }

    NTSTATUS doConnect(IPENDPOINT& remoteAddress)
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            socketHandle = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (socketHandle == INVALID_SOCKET)
                break;

            status = service.scheduler.registerHandle((HANDLE)socketHandle, (PVOID)this);
            VERIFY_STATUS;

            IPENDPOINT bindSocket;
            auto result = bind(socketHandle, (SOCKADDR*)&bindSocket, sizeof(bindSocket));
            ASSERT(result != SOCKET_ERROR);

            createTask(ioState.control.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
                {
                    auto&& session = getSession(context);
                    session.onSocketConnect(result);
                    ASSERT(NT_SUCCESS(result));
                });

            result = (*ConnectExFunc)(socketHandle, remoteAddress.addressC(), SOCKADDR_LEN, nullptr, 0, NULL, ioState.control.start());
            if (result == FALSE && WSAGetLastError() != ERROR_IO_PENDING)
            {
                DBGBREAK();
                break;
            }


            status = STATUS_SUCCESS;
        } while (false);

        return status;
    }

    auto isClosed() { return socketHandle == INVALID_SOCKET; }

    auto isReady(TOKEN hostname) {
        return false;
    }

    void close()
    {
        closesocket(socketHandle);
    }

    static auto& getSession(PVOID arg)
    {
        auto&& session = *(HTTP_SESSION *)arg;
        return session;
    }

    NTSTATUS download(URL_INFO urlInfo)
    {
        dnsQuery.clear();
        downloadUrl = urlInfo;
        createTask(dnsQuery.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
            {
                auto& session = getSession(context);
                session.doConnect(session.dnsQuery.ipAddress);
            });
        dnsQuery.resolveDns(NameToString(urlInfo.hostname), urlInfo.port);
        return STATUS_SUCCESS;
    }

    void onAcceptComplete(NTSTATUS result)
    {
        ASSERT(NT_SUCCESS(result));

        setupIoTasks();
        transfer.headerBytes.allocReserve<SESSION_STACK>(1024);
        transferState = WAITING_FOR_REQUEST;

        tlsHandshake.init(SystemService().hostname, HTTP_http_1_1);
        beginReceive();
    }

    UINT8 addrBuf[128];
    NTSTATUS listen(SOCKET listenSocket)
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            socketHandle = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (socketHandle == INVALID_SOCKET)
                break;

            status = service.scheduler.registerHandle((HANDLE)socketHandle, (PVOID)this);
            VERIFY_STATUS;

            createTask(ioState.control.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
                {
                    auto&& session = getSession(context);
                    LogInfo("New Connection");
                    session.onAcceptComplete(result);
                });

            auto result = (*AcceptExFunc)(listenSocket, socketHandle, addrBuf, 0, sizeof(SOCKADDR_IN) + 16, sizeof(SOCKADDR_IN) + 16, nullptr, ioState.control.start());
            if (result == FALSE && WSAGetLastError() != WSA_IO_PENDING)
            {
                DBGBREAK();
                break;
            }

            status = STATUS_SUCCESS;
        } while (false);
        return status;
    }

    void generateHandshakeKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
    }

    void generateMasterKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
    }

    void updateMasterKeys(HKDF& kdf, BUFFER clientSecret, BUFFER serverSecret, UINT32 keySize)
    {
    }

    static void reset(HTTP_SESSION& session, SERVICE& service)
    {
        session.sessionStack.free();
        NEW(session, service);
    }

    void init()
    {
        sessionStack.init(512 * 1024);
    }

    void vectorTest()
    {
        tlsHandshake.init(HTTP_localhost, HTTP_http_1_1);
        tlsHandshake.test();
    }
};
