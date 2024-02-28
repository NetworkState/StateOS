
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

constexpr USTRING RTSP_UA = "MediaSwitch V0.4";

template <typename SERVICE>
struct RTSP_SESSION
{
	using RESPONSE_HANDLER = void (RTSP_SESSION::*)(BUFFER header, BUFFER body);
	RESPONSE_HANDLER responseTask;

	SOCKET socketHandle;
	URL_INFO connectUrl;
	HTTP_AUTH authInfo;

	UINT32 cSeqNo = 0;
	SESSION_STACK sessionStack;
	SERVICE& service;
	SDP_STREAM<SESSION_STACK> sdpStream;
	DNS_QUERY dnsQuery;
	IOCALLBACK ioState{ IO_SOCK_RECV };

	LOCAL_STREAM<64> sessionId;
	BYTESTREAM socketSendStream;
	BYTESTREAM socketRecvStream;

	RTSP_SESSION(SERVICE& service) : service(service), dnsQuery(getScheduler())
	{
	}

	void init()
	{
		sessionStack.init(2 * 1024 * 1024, 0);
		socketSendStream.allocReserve<SESSION_STACK>(2048);
		socketRecvStream.allocReserve<SESSION_STACK>(2048);
	}

	template <typename ... ARGS>
	void createTask(STASK& task, TASK_HANDLER handler, ARGS&& ... args)
	{
		new (&task) STASK(sessionStack, handler, (PVOID)this, args ...);
	}

	auto& getScheduler() { return service.scheduler; }

	NTSTATUS sendMessage(BUFFER sendData)
	{
		return SocketSend(socketHandle, sendData);
	}

	void handleSetupAudioResponse(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(headers);
		UNREFERENCED_PARAMETER(body);
	}

	void handleSetupVideoResponse(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(body);
		do
		{
			ASSERT(Http.getStatus(headers) == HTTP_200);

			auto session = Http.findHeader(headers, RTSP_Session);
			ASSERT(session);
			sessionId.writeBytes(session);

			auto audioData = Sdp.find(sdpStream.toBuffer(), SDP_audio);
			if (!audioData)
				break;

			auto controlData = Sdp.find(audioData, SDP_control);
			if (!controlData)
				break;

			auto trackIndex = controlData.findIndex(SDP_trackId);
			if (trackIndex == -1)
				break;

			auto trackId = (UINT32)Tokens.getNumber(controlData.at(trackIndex + 1));
			
			initMessage(socketSendStream, RTSP_SETUP, ByteStream(256).writeMany("/trackId=", trackId));
			socketSendStream.writeMany("Session: ", session, CRLF);
			socketSendStream.writeMany("Require: play.basic", CRLF);
			socketSendStream.writeMany("Accept-Ranges: npt, smpte, clock", CRLF);
			socketSendStream.writeString(CRLF);

			responseTask = &RTSP_SESSION::handleSetupAudioResponse;
			sendMessage(socketSendStream.toBuffer());

		} while (false);
	}

	void setupVideo(TOKEN_BUFFER sdpStream, TOKEN_BUFFER videoStream)
	{
		UNREFERENCED_PARAMETER(sdpStream);
		UNREFERENCED_PARAMETER(videoStream);

		do
		{
			auto controlData = Sdp.find(videoStream, SDP_control);
			if (!controlData)
				break;

			auto trackIndex = controlData.findIndex(SDP_trackId);
			if (trackIndex == -1)
				break;

			auto trackId = (UINT32)Tokens.getNumber(controlData.at(trackIndex + 1));

			initMessage(socketSendStream, RTSP_SETUP, ByteStream(256).writeMany("/trackId=", trackId));
			socketSendStream.writeMany("Require: play.basic", CRLF);
			socketSendStream.writeMany("Accept-Ranges: npt, smpte, clock", CRLF);
			socketSendStream.writeString(CRLF);

			responseTask = &RTSP_SESSION::handleSetupVideoResponse;
			sendMessage(socketSendStream.toBuffer());
		} while (false);
	}

	bool isRedirect(TOKEN status) { return status == RTSP_301 || status == RTSP_302 || status == RTSP_303 || status == RTSP_305; }

	bool getAuthInfo(BUFFER headers)
	{
		Http.parseHeaders(headers, [](TOKEN name, BUFFER value, RTSP_SESSION& session)
			{
				if (name == HTTP_WWW_Authenticate)
				{
					Http.parseAuth(value, session.authInfo);
					if (session.authInfo.algorithm == HTTP_SHA_256)
						return false;
				}
				return true;
			}, *this);
		if (authInfo.algorithm != HTTP_SHA_256)
		{
			authInfo.clear();
			return false;
		}
		return true;
	}

	void handleDescribeResponse(USTRING headers, USTRING body)
	{
		auto status = Http.getStatus(headers);
		if (isRedirect(status))
		{
			auto newUrl = Http.findHeader(headers, RTSP_Location);
			if (newUrl)
			{
				closesocket(socketHandle);
				connect(newUrl);
			}
		}
		else if (status == RTSP_401)
		{
			if (getAuthInfo(headers))
			{
				sendDescribe();
			}
			else DBGBREAK();
		}
		else
		{
			Sdp.parseSdp(body, sdpStream);

			auto video = Sdp.find(sdpStream.toBuffer(), SDP_video);
			if (video)
			{
				setupVideo(sdpStream.toBuffer(), video);
			}
		}
	}

	template <typename STREAM>
	void initMessage(STREAM&& messageStream, TOKEN method, USTRING pathExt = NULL_STRING)
	{
		messageStream.clear();
		messageStream.writeMany(method, " rtsp://", connectUrl.hostname, "/", connectUrl.path, pathExt, " RTSP/1.0", CRLF);
		messageStream.writeMany("CSeq: ", ++cSeqNo, CRLF);
		messageStream.writeMany("User-Agent: ", RTSP_UA, CRLF);
		if (authInfo)
		{
			Http.formatAuth(connectUrl, authInfo, method, messageStream);
		}
	}

	void sendDescribe()
	{
		initMessage(socketSendStream, RTSP_DESCRIBE);
		socketSendStream.writeMany("Accept: ", "application/sdp", CRLF);
		socketSendStream.writeString(CRLF);
		
		responseTask = &RTSP_SESSION::handleDescribeResponse;
		sendMessage(socketSendStream.toBuffer());
	}

	void onConnect()
	{
		sendDescribe();
	}

	void onDescribe(USTRING headers, USTRING body)
	{
		UNREFERENCED_PARAMETER(headers);
		UNREFERENCED_PARAMETER(body);
	}

	void parseMessage(USTRING headers, USTRING body)
	{
		if (Http.isRequest(headers))
		{
			auto method = Http.getMethod(headers);
			UNREFERENCED_PARAMETER(method);

			if (method == RTSP_DESCRIBE)
			{
				onDescribe(headers, body);
			}
		}
		else
		{
			(this->*responseTask)(headers, body);
		}
	}

	void onSocketReceive(BUFFER recvData)
	{
		auto messageData = socketRecvStream.toBuffer();

		auto headers = String.splitStringIf(messageData, CRLF_CRLF);
		if (headers)
		{
			auto headerValue = Http.findHeader(headers, RTSP_Content_Length);
			UINT32 contentLength = UINT32(headerValue ? String.toNumber(headerValue) : 0);

			if (contentLength == 0 || messageData.length() >= contentLength)
			{
				auto body = messageData.readBytes(contentLength);
				parseMessage(headers, body);

				socketRecvStream.remove(0, messageData.mark());
			}
		}
		beginReceive();
	}

	static auto&& getSession(PVOID context) { return *(RTSP_SESSION*)context; }

	void onSocketConnect(NTSTATUS status)
	{
		createTask(ioState.task, [](PVOID context, NTSTATUS status, STASK_ARGV argv)
			{
				auto&& session = getSession(context);
				session.onConnect();
				auto bytesTransferred = argv.read<DWORD>(0);
				session.socketRecvStream.expand(bytesTransferred);
				session.onSocketReceive(session.socketRecvStream.toBuffer());
				ASSERT(NT_SUCCESS(status));
			});
		beginReceive();
	}

	void beginReceive()
	{
		SocketRecv(socketHandle, socketRecvStream, ioState);
	}

	NTSTATUS doConnect(IPENDPOINT remoteAddress)
	{
		auto status = STATUS_UNSUCCESSFUL;
		do
		{
			socketHandle = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, WSA_FLAG_OVERLAPPED);
			if (socketHandle == INVALID_SOCKET)
				break;

			status = getScheduler().registerHandle((HANDLE)socketHandle, (PVOID)this);
			VERIFY_STATUS;

			IPENDPOINT bindSocket;
			auto result = bind(socketHandle, (SOCKADDR*)&bindSocket, sizeof(bindSocket));
			ASSERT(result != SOCKET_ERROR);

			createTask(ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
				{
					auto&& session = getSession(context);
					session.onSocketConnect(result);
					ASSERT(NT_SUCCESS(result));
				});

			result = (*ConnectExFunc)(socketHandle, remoteAddress.addressC(), SOCKADDR_LEN, nullptr, 0, NULL, ioState.start());
			if (result == FALSE && WSAGetLastError() != ERROR_IO_PENDING)
			{
				DBGBREAK();
				break;
			}


			status = STATUS_SUCCESS;
		} while (false);

		return status;
	}

	void connect(USTRING urlText)
	{
		Http.parseUrl<SESSION_STACK>(urlText, connectUrl);
		createTask(dnsQuery.task, [](PVOID context, NTSTATUS status, STASK_ARGV argv)
			{
				auto&& session = *(RTSP_SESSION*)context;
				if (NT_SUCCESS(status))
				{
					session.doConnect(session.dnsQuery.ipAddress);
				}
			});
		dnsQuery.resolveDns(NameToString(connectUrl.hostname), connectUrl.port);
	}

	void onSocketClose()
	{

	}
};
