
// Copyright (C) 2024 Network State.
// All rights reserved.

#include "Types.h"
#include "Net.h"
#include "QPACKET.h"
#include "TLS13.h"
#include "Http.h"
#include "QUIC.h"
#include "QPACK.h"
#include "Http3.h"

HTTP_OPS Http;

IPENDPOINT IPLOOPBACK (0x7F000001);

using H3_SERVER = H3_SERVICE;
using H3_CLIENT = H3_SERVICE;

constexpr static BUFFER SERVICE_CERT_FILE = "tlscert.crt";
constexpr static BUFFER SERVICE_KEY_FILE = "tlscert.key";

struct HTTP_CLIENT;

using HTTP_CLIENT_SESSION = HTTP_SESSION<HTTP_CLIENT>;
using HTTP_REQUEST = HTTP_CLIENT_SESSION::HTTP_TRANSFER;

struct HTTP_CLIENT
{
    bool isServer = false;

    SCHEDULER_INFO<> scheduler;
    SERVICE_STACK serviceStack;
    DATASTREAM<HTTP_CLIENT_SESSION, SERVICE_STACK, 8> sessionTable;
    DATASTREAM<HTTP_COOKIE, SERVICE_STACK, 64> cookieTable;

    HTTP_CLIENT() : scheduler(serviceStack) {}

    void init()
    {
        scheduler.init();
        serviceStack.init(2 * 1024 * 1024, 0);
    }

    template <typename FUNC, typename ... ARGS>
    void runTask(FUNC handler, ARGS&& ... args)
    {
        scheduler.runTask(handler, (PVOID)this, args ...);
    }

    void downloadTask(USTRING url)
    {
        auto urlInfo = Http.parseUrl<SERVICE_STACK>(url, URL_INFO());

        HTTP_CLIENT_SESSION* availableSession = nullptr;
        for (auto&& session : sessionTable.toRWBuffer())
        {
            if (session.isReady(urlInfo.hostname))
            {
                availableSession = (HTTP_CLIENT_SESSION*)&session;
                break;
            }
        }

        if (availableSession == nullptr)
        {
            for (auto&& session : sessionTable.toRWBuffer())
            {
                if (session.isClosed())
                {
                    availableSession = (HTTP_CLIENT_SESSION*)&session;
                    break;
                }
            }
        }

        if (availableSession == nullptr)
        {
            availableSession = &sessionTable.append(*this, false);
            availableSession->init();
        }

        availableSession->download(urlInfo);

    }

    NTSTATUS download(USTRING url)
    {
        runTask([](PVOID context, NTSTATUS, STASK_ARGV param)
            {
                auto& session = *(HTTP_CLIENT*)context;
                auto&& url = param.read<BUFFER>(0);
                session.downloadTask(url);
            }, url);;
        return STATUS_SUCCESS;
    }

    BUFFER alpnService() { return NULL_BUFFER; }

    void onRequest(HTTP_REQUEST& request) { DBGBREAK(); }
};

constexpr BUFFER WWW_ROOT = "WWW_ROOT/";

struct H1_SERVER;
using H1SERVER_SESSION = HTTP_SESSION<H1_SERVER>;
using H1_REQUEST = H1SERVER_SESSION::HTTP_TRANSFER;

struct H1_SERVER
{
    SCHEDULER_INFO<> scheduler;
    SERVICE_STACK serviceStack;
    DATASTREAM<H1SERVER_SESSION, SERVICE_STACK, 8> sessionTable;
    DATASTREAM<HTTP_COOKIE, SERVICE_STACK, 64> cookieTable;

    const bool isServer = true;
    constexpr static UINT32 MAX_SOCKETS = 5;

    SOCKET listenSocket;

    H1_SERVER() : scheduler(serviceStack) {}

    void init()
    {
        serviceStack.init(2 * 1024 * 1024, 0);
        scheduler.init();
    }

    NTSTATUS start()
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            listenSocket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
            if (listenSocket == INVALID_SOCKET)
                break;

            status = scheduler.registerHandle((HANDLE)listenSocket, (PVOID)this);
            VERIFY_STATUS;

            IPENDPOINT bindSocket{ INADDR_ANY, TLS_PORT };

            auto result = bind(listenSocket, bindSocket.addressC(), SOCKADDR_LEN);
            if (result == SOCKET_ERROR) { DBGBREAK(); break; }

            result = listen(listenSocket, SOMAXCONN);
            if (result == SOCKET_ERROR) { DBGBREAK(); break; }

            sessionTable.reserve(MAX_SOCKETS);

            for (UINT32 i = 0; i < MAX_SOCKETS; i++)
            {
                auto&& httpSession = sessionTable.append(*this, true);
                httpSession.init();
                result = httpSession.listen(listenSocket);
                if (result == SOCKET_ERROR) { DBGBREAK(); break; }
            }
            if (result == SOCKET_ERROR) { DBGBREAK(); break; }
            status = STATUS_SUCCESS;
        } while (false);
        return status;
    }

    void vectorTest()
    {
        auto&& httpSession = sessionTable.append(*this, true);
        httpSession.init();
        httpSession.vectorTest();
    }

    template <typename FUNC, typename ... ARGS>
    void runTask(FUNC handler, ARGS&& ... args)
    {
        scheduler.runTask(handler, (PVOID)this, args ...);
    }

    void onRequest(H1_REQUEST& request)
    {
        LogInfo("onRequest");
        auto path = request.path && request.path != "/" ? request.path : "index.html";
        auto filename = ByteStream(1024).writeMany(WWW_ROOT, path);
        UINT64 fileSize;
        HANDLE fileHandle;
        auto status = File.Open(filename, fileHandle, fileSize);
        if (NT_SUCCESS(status))
        {
            auto extension = FindName(String.splitCharReverse(filename, '.'));
            ASSERT(extension);

            auto mimeType = GET_MIME_TYPE(extension);
            ASSERT(mimeType);

            auto&& headerStream = ByteStream(1024);
            Http.formatHeader(headerStream, HTTP_Content_Type, mimeType);
            Http.formatDate(headerStream, HTTP_Last_Modified, File.GetFileTime(fileHandle));
            Http.formatHeader(headerStream, HTTP_Content_Length, fileSize);

            request.sendResponse(STATUS_200, headerStream.toBuffer(), fileHandle);
        }
        else
        {
            DBGBREAK();
            request.sendResponse(STATUS_404);
        }
    }
};

static H3_CLIENT* H3Client; // for debugging

void HttpServiceMain()
{
    {
        auto h3ServerPtr = &StackAlloc<H3_SERVER, GLOBAL_STACK>(true);
        h3ServerPtr->init(16 * 1024 * 1024);
        h3ServerPtr->scheduler.runTask([](PVOID context, NTSTATUS, STASK_ARGV)
            {
                auto&& service = *(H3_SERVER*)context;
                service.startServer(TLS_PORT);

            }, (PVOID)h3ServerPtr);
    }
    {
        auto h3ClientPtr = &StackAlloc<H3_CLIENT, GLOBAL_STACK>(false);
        H3Client = h3ClientPtr;
        h3ClientPtr->init(512 * 1024);
        h3ClientPtr->scheduler.runTask([](PVOID context, NTSTATUS, STASK_ARGV)
            {
                auto&& service = *(H3_CLIENT*)context;
                service.initClient();
                service.doConnect(HTTP_localhost, TLS_PORT);

            }, (PVOID)h3ClientPtr);
    }
    {
        auto&& h1Server = StackAlloc<H1_SERVER, GLOBAL_STACK>();
        h1Server.init();
        h1Server.scheduler.runTask([](PVOID context, NTSTATUS, STASK_ARGV)
            {
                auto&& service = *(H1_SERVER*)context;
                service.start();
                //service.vectorTest();
            }, (PVOID)&h1Server);
    }
}

