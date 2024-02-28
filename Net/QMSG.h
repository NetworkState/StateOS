
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct QMSG_SERVICE
{
	constexpr static BUFFER SIGNAL_PATHID = "cf542393-b669-45f5-a798-3d898277fb52";

	struct QMSG_TRANSPORT;
	using QMSG_SESSION = QUIC_SESSION<QMSG_SERVICE, QMSG_TRANSPORT>;
	using PQMSG_TRANSPORT = QMSG_TRANSPORT*;
	using QUIC_SOCKET = UDP_SOCKET<QMSG_SERVICE>;

	struct MSGBUF
	{
		MSGBUF* next = nullptr;
		BYTESTREAM dataStream;
		UINT32 streamOffset;

		MSGBUF(PUINT8 data, UINT32 size) : dataStream(data, size) {}
		void reset()
		{
			dataStream.clear();
			next = nullptr;
			streamOffset = 0;
		}

		UINT32 writeOffset()
		{
			return streamOffset + dataStream.count();
		}
	};
	using PMSGBUF = MSGBUF*;

	struct MSGBUF_POOL
	{
		STREAMPOOL<MSGBUF, SERVICE_STACK, 64> bufPool;
		UINT32 bufSize;
		PMSGBUF freeBufs;

		UINT32 incrQueueSize;

		MSGBUF_POOL(UINT32 bufSize, UINT32 incrQueueSize = 16) : bufSize(bufSize), incrQueueSize(incrQueueSize) {}

		NTSTATUS addBufs(UINT32 queueSize)
		{
			auto bufData = (PUINT8) MemAlloc(queueSize * bufSize);
			ASSERT(bufData);

			for (UINT32 i = 0; i < queueSize; i++)
			{
				auto&& buf = bufPool.append(bufData + (i * bufSize), bufSize);
				buf.next = freeBufs;
				freeBufs = &buf;
			}
			return STATUS_SUCCESS;
		}

		MSGBUF& alloc()
		{
			if (freeBufs == nullptr)
			{
				addBufs(incrQueueSize);
			}
			auto&& newBuf = *freeBufs;
			freeBufs = newBuf.next;

			newBuf.reset();
			return newBuf;
		}

		void free(MSGBUF& buf)
		{
			buf.next = freeBufs;
			freeBufs = &buf;
		}

		NTSTATUS init(UINT32 queueSize)
		{
			return addBufs(queueSize);
		}
	};

	struct RECV_STATE
	{
		STREAM_STATE streamState;
		PMSGBUF recvBufChain = nullptr;

		void reset()
		{
			recvBufChain = nullptr;
			streamState.reset();
		}

		void init(QMSG_SESSION& quicSession, UINT64 streamId)
		{
			streamState.reset();
			quicSession.streamLimits.initOutgoingStream(streamState, streamId);
			recvBufChain = nullptr;
		}
	};

	struct TRANSMIT_STATE
	{
		STREAM_STATE streamState;
		PMSGBUF sendBufChain = nullptr;

		void reset()
		{
			ASSERT(sendBufChain == nullptr);
			sendBufChain = nullptr;
			streamState.reset();
		}

		void init(QMSG_SESSION& quicSession, UINT64 streamId)
		{
			quicSession.streamLimits.allocOutgoingStream(streamState, streamId);
			sendBufChain = nullptr;
		}
	};

	struct QMSG_PATH
	{
		QMSG_SERVICE& msgService;

		constexpr static UINT16 FLAG_FORWARD_MSG = BIT16(0);
		constexpr static UINT16 FLAG_ROUTE_MSG = BIT16(1);
		constexpr static UINT16 FLAG_SIGNAL_MSG = BIT16(2);

		DATASTREAM<PQMSG_TRANSPORT, SERVICE_STACK> inTransports;
		DATASTREAM<PQMSG_TRANSPORT, SERVICE_STACK> outTransports;

		TOKEN pathId;
		MSGBUF_POOL& bufPool;
		UINT16 flags;

		MSGBUF& nextBuf(RECV_STATE& recvState)
		{
			UINT32 writeOffset = 0;
			for (auto buf = recvState.recvBufChain; buf; buf = buf->next)
			{
				if (buf->dataStream.spaceLeft() > 0)
				{
					return *buf;
				}
				writeOffset += buf->dataStream.count();
			}
			auto&& next = bufPool.alloc();
			next.streamOffset = writeOffset;
			APPEND_LINK(&recvState.recvBufChain, next);
			return next;
		}
		
		void onRecvMsg(TOKEN remoteNodeId, UINT64 streamId, PMSGBUF bufChain)
		{
		}

		void forwardFrames(UINT64 msgId, MBUF_READER recvFrames)
		{
			for (auto&& transport : outTransports.toRWBuffer())
			{
				transport->routeFrames(msgId, recvFrames);
			}
		}

		void onRecvFrame(TOKEN nodeId, RECV_STATE& recvState, MBUF_READER& recvFrames)
		{
			auto msgId = recvState.streamState.streamId >> 2;

			if (flags & FLAG_SIGNAL_MSG)
			{
				if (recvFrames.endOfStream())
				{
					msgService.handleSignalMsg(nodeId, msgId, recvFrames);
				}
				ASSERT(flags == FLAG_SIGNAL_MSG);
				return;
			}

			if (flags & FLAG_ROUTE_MSG)
			{
				forwardFrames(msgId, recvFrames);
			}
			
			while (recvFrames.chainBytes() > 0)
			{
				auto&& writeBuf = nextBuf(recvState);
				if (writeBuf.writeOffset() >= recvFrames.streamOffset())
				{
					auto skipCount = writeBuf.writeOffset() >= recvFrames.streamOffset();
					recvFrames.readBytes(skipCount);

					recvFrames.writeBytes(writeBuf.dataStream);
				}
				else
				{
					DBGBREAK();
					break;
				}
			}

			if (recvFrames.endOfStream())
			{
				ASSERT(recvFrames.chainBytes() == 0);
				onRecvMsg(nodeId, recvState.streamState.streamId >> 2, recvState.recvBufChain);
			}
		}

		QMSG_PATH(QMSG_SERVICE& msgService, TOKEN pathId, MSGBUF_POOL& bufPool) : msgService(msgService), pathId(pathId), bufPool(bufPool) {}
	};

	struct QMSG_TRANSPORT
	{
		auto&& getQuicSession() { return *CONTAINING_RECORD(this, QMSG_SESSION, appSession); }

		TOKEN remoteNodeId;
		QMSG_PATH& path;

		DATASTREAM<RECV_STATE, SESSION_STACK> recvStreams;
		DATASTREAM<TRANSMIT_STATE, SESSION_STACK> transmitStreams;

		QMSG_TRANSPORT(QMSG_PATH& path) : path(path) {}

		void init() {}

		void onConnect()
		{
			recvStreams.reserve(32);
			transmitStreams.reserve(16);
		}

		RECV_STATE& getRecvState(UINT64 streamId)
		{
			auto&& activeStates = recvStreams.toRWBuffer();
			for (auto&& state : activeStates)
			{
				if (state.streamState.streamId == streamId)
				{
					return state;
				}
			}

			for (auto&& state : activeStates)
			{
				if (state.streamState.streamId == -1)
				{
					state.init(getQuicSession(), streamId);
					return state;
				}
			}

			auto&& newState = recvStreams.append();
			newState.init(getQuicSession(), streamId);
			return newState;
		}

		void onRecvStreamFrame(DATAFRAME& recvFrame)
		{
			auto&& recvState = getRecvState(recvFrame.streamId);
			recvState.streamState.onRecvFrame(recvFrame);
		}

		void forwardStreamFrames()
		{
			for (auto&& recvState : recvStreams.toRWBuffer())
			{
				recvState.streamState.handleRecvFrames(getQuicSession(), [](MBUF_READER& mbuf, QMSG_TRANSPORT& transport, RECV_STATE& recvState, QMSG_SESSION& quicSession)
					{
						transport.path.onRecvFrame(transport.remoteNodeId, recvState, mbuf);
					}, *this, recvState, getQuicSession());
			}
		}

		TRANSMIT_STATE& getTransmitState(UINT64 streamId)
		{
			for (auto&& state : transmitStreams.toRWBuffer())
			{
				if (state.streamState.streamId == streamId)
				{
					return state;
				}
			}
		}

		void routeFrames(UINT64 msgId, MBUF_READER mbuf)
		{
			STREAM_STATE sendState;
			sendState.streamId = getQuicSession().streamLimits.makeOutgoingStreamId(msgId);
			sendState._sendCredit = -1; // ignore per-stream send llimts for now

			MBUF_STREAM sendStream{ getQuicSession() };
			for (auto&& frame : mbuf.frames)
			{
				sendState.sendOffset = frame->streamOffset;
				sendStream.beginStream(sendState);
				sendStream.writeBytes(frame->dataBuf);
				sendStream.endStream();
			}
			sendStream.sendPackets();
		}
	};
	constexpr static HEXSTRING CAC_TOKEN_KEY = "ef3fb8cbb0ca4aa3a85341c0dca34740";
	constexpr static HEXSTRING CAC_TOKEN_IV = "45c008ac89a14640a707e6d95e95";
	AES_CTR cacCipher;

	SCHEDULER_INFO<>& scheduler;
	TOKEN localNodeID;

	DATASTREAM<QMSG_SESSION*, SERVICE_STACK> sessionPool;
	DATASTREAM<MSGBUF_POOL, SERVICE_STACK> msgBufPoolTable;
	DATASTREAM<QMSG_PATH, SERVICE_STACK> pathTable;

	QPACKET::PACKET_POOL packetPool;
	DATASTREAM<QUIC_SOCKET, SERVICE_STACK> socketPool;
	TOKEN signalPathID;
	QUIC_RETRY quicRetry;

	auto&& getScheduler() { return scheduler; }

	void runTask(STASK& task, NTSTATUS status, auto&& ... args)
	{
		scheduler.runTask(task, status, args ...);
	}

	QMSG_SERVICE(SCHEDULER_INFO<>& scheduler) : scheduler(scheduler) {}

	void init() {}

	constexpr static UINT32 SIGNAL_MSGBUF_SIZE = 4096;

	constexpr static UINT32 MSGBUFPOOL_MIN_SIZE = 12; // log 4096
	constexpr static UINT32 MSGBUFPOOL_COUNT = 5;
	MSGBUF_POOL& getBufPool(UINT32 size)
	{
		auto index = min(MSGBUFPOOL_COUNT, (LOG2(size) / 4));
		return msgBufPoolTable.at(index);
	}

	NTSTATUS intMsgBufPool()
	{
		UINT32 bufSize = BIT32(MSGBUFPOOL_MIN_SIZE);
		for (UINT32 i = 0; i <= MSGBUFPOOL_COUNT; i++)
		{
			auto&& bufPool = msgBufPoolTable.append(bufSize);
			bufSize *= 4;
			bufPool.init(256 >> i);
		}
		return STATUS_SUCCESS;
	}

	auto&& signalPath()
	{
		return pathTable.at(0);
	}

	QMSG_PATH& findPath(TOKEN pathId, UINT32 bufSize = 4096)
	{
		for (auto&& path : pathTable.toRWBuffer())
		{
			if (path.pathId == pathId)
			{
				return path;
			}
		}
		auto&& bufPool = getBufPool(bufSize);
		auto&& newPath = pathTable.append(*this, pathId, bufPool);
		return newPath;
	}

	QUIC_SOCKET& createSocket()
	{
		auto socketList = socketPool.toRWBuffer();
		for (auto&& socket : socketList)
		{
			if (socket.isClosed())
				return socket;
		}
		auto& newSocket = socketPool.append(*this);
		return newSocket;
	}

	QPACKET& allocPacket()
	{
		return packetPool.alloc();
	}

	QMSG_SESSION& createSession(QUIC_SOCKET& udpSocket, QMSG_PATH& path, bool isServer)
	{
		for (auto&& sessionP : sessionPool.toRWBuffer())
		{
			auto&& session = *sessionP;
			if (session.isClosed())
			{
				session.reset(session, *this, udpSocket, isServer, path);
				return session;
			}
		}
		auto&& newSession = StackAlloc<QMSG_SESSION, SERVICE_STACK>(*this, udpSocket, isServer, path);
		sessionPool.append(&newSession);
		newSession.init();
		return newSession;
	}

	QMSG_SESSION* findSession(BUFFER sourceCID)
	{
		if (sourceCID.length() != LOCAL_CID_LENGTH)
			return nullptr;

		for (auto&& sessionP : sessionPool.toRWBuffer())
		{
			auto&& quicSession = *sessionP;
			if (BUFFER(quicSession.sourceCID) == sourceCID)
			{
				return sessionP;
			}
		}

		return nullptr;
	}

	void handleSignalMsg(TOKEN fromNode, UINT64 msgId, MBUF_READER& msgBufs)
	{
		auto msg = msgBufs.readBytes(msgBufs.chainBytes());
	}

	void generateToken(BYTESTREAM& packetStream, BUFFER sourceCID, BUFFER destCID, BUFFER hostname)
	{
		auto&& tlsCert = SystemService().AKsignKey;
		ASSERT(tlsCert.certBytes);
		auto&& start = packetStream.mark();

		auto signData = WriteMany(sourceCID, destCID, hostname);
		tlsCert.signData(signData, packetStream.commitTo(ECDSA_SIGN_LENGTH));
		packetStream.writeBytes(tlsCert.certBytes);

		auto&& tokenData = packetStream.toRWBuffer(start);
		cacCipher.encrypt(tokenData);
	}

	bool acceptConnction(QUIC_SOCKET& udpSocket, QPACKET& recvPacket)
	{
		auto result = false;
		auto&& quicHeader = recvPacket.recvHeader;

		QMSG_SESSION* newSession = nullptr;
		auto&& tokenData = ByteStream(1024).writeBytesTo(quicHeader.recvToken);
		ASSERT(tokenData);

		cacCipher.encrypt(tokenData.toRWBuffer());
		
		SHA256_DATA signHash; Sha256ComputeHash(signHash, WriteMany(quicHeader.sourceCID, quicHeader.destinationCID, NameToString(SystemService().hostname)));
		auto signature = tokenData.readBytes(ECDSA_SIGN_LENGTH);

		X509_SUBJECT subjectInfo;
		auto isValid = SystemService().CAsignKey.verifySignature(tokenData, subjectInfo);

		isValid = isValid && ecdsa_verify(subjectInfo.publicKey, signHash, signature);
		if (isValid)
		{
			auto&& acceptSession = createSession(udpSocket, signalPath(), true);
			acceptSession.appSession.remoteNodeId = ServiceTokens.createID(subjectInfo.keyId.readU128());
			acceptSession.accept(recvPacket);
			result = true;
		}
		return result;
	}

	void onSocketReceive(QUIC_SOCKET& udpSocket, QPACKET& recvPacket)
	{
		auto&& quicHeader = recvPacket.parseHeader();
		if (auto quicSessionP = findSession(quicHeader.destinationCID))
		{
			auto&& quicSession = *quicSessionP;
			ASSERT(quicSession.udpSocket.remoteAddress == recvPacket.recvFrom);

			quicSession.onRecvPacket(recvPacket);
		}
		else if (quicHeader.packetType == PACKET_INITIAL)
		{
			acceptConnction(udpSocket, recvPacket);
		}
	}

	void startServer(UINT16 port)
	{
		auto&& udpSocket = createSocket();
		udpSocket.init(port);

		udpSocket.beginReceive();
	}

	void doConnect(BUFFER hostname, UINT16 port)
	{
		TOKEN hostnameToken = CreateServiceName(hostname, false);
		auto&& udpSocket = createSocket();
		udpSocket.init(hostname, port, [](PVOID context, NTSTATUS status, STASK_ARGV argv)
			{
				auto&& udpSocket = *(QUIC_SOCKET*)context;
				auto hostname = argv.read<TOKEN>(0);
				auto&& service = udpSocket.service;

				if (NT_SUCCESS(status))
				{
					auto&& msgPath = service.findPath(service.signalPathID);
					auto&& quicSession = service.createSession(udpSocket, service.signalPath(), false);
					quicSession.doConnect(hostname);
					udpSocket.beginReceive();
				}
				else
				{
					udpSocket.close();
				}
			}, &udpSocket, hostnameToken);
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

	constexpr static BUFFER ALPN = "QMSG";
	TOKEN alpnService()
	{
		return CreateServiceName(ALPN);
	}

	void start()
	{
		//labelStore.init();

		cacCipher.init(CAC_TOKEN_KEY, CAC_TOKEN_IV);
		signalPathID = ServiceTokens.createID(SIGNAL_PATHID);

		packetPool.init();
		intMsgBufPool();
		pathTable.reserve(64);
		pathTable.append(*this, signalPathID, getBufPool(SIGNAL_MSGBUF_SIZE));

		startServer(TLS_PORT);
	}

	void testLabels()
	{
		BUFFER testLabel1 = "test";
		auto label1 = ServiceTokens.createLabel(5, testLabel1);
		auto labelString = ServiceTokens.getLabel(label1);
		ServiceTokens.findLabel(5, testLabel1);
		ASSERT(testLabel1 == labelString);
	}

	void test()
	{
		testLabels();
		//doConnect("mathya-43", TLS_PORT);
	}
};

