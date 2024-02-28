#include "Types.h"
#include "Net.h"
#include "QPACKET.h"
#include "TLS13.h"
#include "Http.h"
#include "SDP.h"
#include "WebRTC.h"
#include "RTSP.h"
#include "MP4.h"

SDP_OPS<SERVICE_STACK> Sdp;

SRTP_PACKET* SRTP_PACKET::freeList;

struct MEDIA_TRANSPORT;
using WEBRTC_MEDIA_SESSION = WEBRTC_SESSION<MEDIA_TRANSPORT>;
struct MEDIA_TRANSPORT
{
    SCHEDULER_INFO<> scheduler;
    SERVICE_STACK serviceStack;
    DATASTREAM<WEBRTC_MEDIA_SESSION, SERVICE_STACK, 8> sessionTable;

    MEDIA_TRANSPORT() : scheduler(serviceStack) {}

    void init()
    {
        serviceStack.init(2 * 1024 * 1024, 0);
        scheduler.init();
    }

    auto&& createSession()
    {
        auto&& newSession = sessionTable.append(*this);
        newSession.initialize();
        return newSession;
    }
};

struct MEDIA_CONTROLLER;
using MEDIA_CONTROLLER_SESSION = HTTP_SESSION<MEDIA_CONTROLLER>;

struct MEDIA_CONTROLLER
{
    SCHEDULER_INFO<> scheduler;
    SERVICE_STACK serviceStack;
    DATASTREAM<MEDIA_CONTROLLER_SESSION, SERVICE_STACK, 8> sessionTable;
    DATASTREAM<HTTP_COOKIE, SERVICE_STACK, 64> cookieTable;
    DATASTREAM<RTSP_SESSION<MEDIA_CONTROLLER>, SERVICE_STACK> rtspSessionTable;

    SOCKET listenSocket;
    MEDIA_TRANSPORT transportService;

    MP4_READER<SESSION_STACK> mp4Reader;

    constexpr static UINT32 MAX_SOCKETS = 1;

    MEDIA_CONTROLLER() : scheduler(serviceStack) {}

    void init()
    {
        serviceStack.init(2 * 1024 * 1024, 0);
        scheduler.init();
        transportService.init();
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
                auto&& session = sessionTable.append(*this, true);
                session.init();
                result = session.listen(listenSocket);
                if (result == SOCKET_ERROR) { DBGBREAK(); break; }
            }
            if (result == SOCKET_ERROR) { DBGBREAK(); break; }
            status = STATUS_SUCCESS;

        } while (false);
        return status;
    }

    using HTTP_REQUEST = MEDIA_CONTROLLER_SESSION::HTTP_TRANSFER;
    void processOffer(HTTP_REQUEST& request)
    {
        auto&& transportSession = transportService.createSession();
        auto response = transportSession.onSignalingReceive(SDP_offer, request.body());

        if (response)
        {
            auto&& headerStream = ByteStream(1024);
            Http.formatHeader(headerStream, HTTP_Content_Type, HTTP_application_sdp);
            Http.formatHeader(headerStream, HTTP_Content_Length, response.length());
            Http.formatHeader(headerStream, HTTP_ETag, transportSession.etag.toBuffer());

            request.sendResponse(STATUS_200, headerStream.toBuffer(), response);
        }
    }

    using HTTP_REQUEST = MEDIA_CONTROLLER_SESSION::HTTP_TRANSFER;

    void onRequest(HTTP_REQUEST& request)
    {
        if (request.method == HTTP_POST)
        {
            auto&& contentType = request.headers().find(HTTP_Content_Type);
            if (contentType && FindName(contentType.value) == HTTP_application_sdp)
            {
                processOffer(request);
            }
        }
    }

    void test()
    {
        auto&& rtsp = rtspSessionTable.append(*this);
        rtsp.connect("test");
    }
};

struct WEBRTC_SERVICE
{
    SCHEDULER_INFO<> scheduler;
    SERVICE_STACK serviceStack;

    WEBRTC_SERVICE() : scheduler(serviceStack) {}

    void init()
    {
        serviceStack.init(2 * 1024 * 1024, 0);
        scheduler.init();
    }

    void test()
    {
        auto sdpText = File.ReadFile<SERVICE_STACK>("test.sdp");
        DATASTREAM<TOKEN, SERVICE_STACK> sdpStream;
        sdpStream.reserve(512);

        Sdp.parseSdp(sdpText, sdpStream);
        auto length = sdpStream.toBuffer().length();
        printf("sdp: %d\n", length);
    }
};
//
//WEBRTC_SERVICE* WebRTCServicePtr;
//WEBRTC_SERVICE& WebRTCService() { return *WebRTCServicePtr; }

MEDIA_CONTROLLER* MediaControllerPtr;
MEDIA_CONTROLLER& MediaController() { return *MediaControllerPtr; }

void MediaRouterMain()
{
    //WebRTCServicePtr = &StackAlloc<WEBRTC_SERVICE, GLOBAL_STACK>();
    //WebRTCService().init();

    MediaControllerPtr = &StackAlloc<MEDIA_CONTROLLER, GLOBAL_STACK>();
    MediaController().init();

    MediaController().scheduler.runTask([](PVOID context, NTSTATUS, STASK_ARGV)
        {
            auto&& service = *(MEDIA_CONTROLLER*)context;
            service.start();
            service.test();
        }, MediaControllerPtr);
}