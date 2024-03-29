
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

constexpr UINT32 BLOCK_PREAMBLE = 16;

template <typename SERVICE = STATE_SERVICE>
struct BLOCK_BUILDER
{
	struct BLOCK_STREAM
	{
		BLOCK_BUILDER& builder;
		BLOCK_STREAM(BLOCK_BUILDER& builder) : builder(builder), ioBuf(NullRef<IOBUF>()) {}

		VISUAL_DYANMIC currentDynamic{ VI_INVISIBLE, VS_BLOCK };
		IOBUF& ioBuf;

		auto&& dataStream() { return ioBuf.dataStream; }

		void init(UINT32 size = 64 * 1024)
		{
			NEW(ioBuf, builder.service.allocBuf(size, 0));
			ioBuf.dataStream.writeBytes(ZeroBytes, BLOCK_PREAMBLE);
		}

		void writeLength()
		{
			iobuf.dataStream.beWriteAtU32(0, ioBuf.dataStream.length());
		}

		IOBUF& clone()
		{
			auto&& cloneBuf = builder.service.allocBuf(ioBuf.dataStream.size(), 0);
			cloneBuf.dataStream.writeBytes(ioBuf.dataStream.toBuffer());
			return cloneBuf;
		}

		void reserve(UINT32 size)
		{
			if (dataStream().spaceLeft() < size)
			{
				NEW(ioBuf, builder.service.resizeBuf(ioBuf, dataStream().size() + size));
			}
		}

		void write(VISUAL_DYANMIC dynamic, TOKEN contour, BUFFER contourData = NULL_BUFFER, TOKEN label = Null)
		{
			reserve(contourData.length() + 16);

			auto visibility = currentDynamic.visibility == dynamic.visibility ? VI_REPEAT : dynamic.visibility;
			auto separation = currentDynamic.separation == dynamic.separation ? VS_REPEAT : dynamic.separation;

			currentDynamic = dynamic;

			VLToken.write(dataStream(), contour, contourData, label, separation, visibility);

			writeLength();
		}
	};

	SERVICE& service;

	TOKEN blockId;
	TOKEN builderId;

	HANDLE fileHandle;

	TPM_HANDLE signPrivateKey;
	EC256_PUBLICKEY signPublicKey;
	
	VISUAL_DYANMIC visualDynamic{ VI_INVISIBLE, VS_BLOCK };
	BLOCK_STREAM blockStream;

	BLOCK_BUILDER(SERVICE& service) : service(service), blockStream(*this) {}

	void init(TOKEN block, TOKEN builder)
	{
		blockId = block;
		builderId = builder;

		auto guid = ByteStream(64).writeGuid(ServiceTokens.getID(blockId));
		auto filename = WriteMany(guid, ".blk");
		File.CreateNoCache(filename, fileHandle);

		blockStream.init();

		signPrivateKey = TPM.createECDSAhandle(NULL_BUFFER, ServiceTokens.getID(blockId), signPublicKey);
	}

	BUFFER writeHeader(BYTESTREAM& outStream, BUFFER data)
	{
		auto headerDynamic = visualDynamic.moveCloser(0x10);
		VISUAL_STREAM headerStream{ headerDynamic, 1024 };

		headerStream.write(headerDynamic, blockId);
		headerStream.write(headerDynamic.moveCloser(), builderId);
		headerStream.write(headerDynamic.moveCloser(), ECKEY_TOKEN, signPublicKey);

		auto hash = Sha256ComputeHash(headerStream.toBuffer(), data);
		ECDSA_DATA signature;
		TPM.sign(signPrivateKey, hash, signature);

		headerStream.write(headerDynamic.moveCloser(), ECDSA_TOKEN, signature);

		outStream.writeBytes(headerStream.toBuffer());
	}

	void saveState()
	{
		auto&& bufCopy = blockStream.clone();

		NEW(bufCopy.ioState.task, [](PVOID context, NTSTATUS status, STASK_ARGV argv)
			{
				ASSERT(NT_SUCCESS(status));
				auto&& blockBuilder = *(BLOCK_BUILDER*)context;
				auto&& iobuf = *argv.read<PIOBUF>(0);
				auto bytesSent = argv.read<DWORD>(1);

				ASSERT(bytesSent == iobuf.dataStream.size());
				blockBuilder.service.freeBuf(iobuf);

			}, this, &bufCopy);

		File.Write(fileHandle, bufCopy);
	}

	void writeTicket(TICKET& ticket, BUFFER ticketData, BUFFER attachment)
	{
		auto&& object = ticket.getObject();

		blockStream.write(visualDynamic, object.id);
		blockStream.write(visualDynamic.moveCloser(), object.timestamp);
		blockStream.write(visualDynamic.moveCloser(), ServiceTokens.createTimestamp());

		blockStream.write(visualDynamic, ticket.header.ticketId);
		blockStream.write(visualDynamic.moveCloser(), ticket.header.bankId);
	}

	void claim(BUFFER ticketData)
	{
		auto headerDynamic = visualDynamic.moveCloser(0x10);
		auto fieldsDynamic = headerDynamic.moveCloser();

		blockStream.write(headerDynamic, blockId);
		blockStream.write(fieldsDynamic, builderId);
		blockStream.write(fieldsDynamic, ServiceTokens.createTimestamp());
		blockStream.write(fieldsDynamic, ECKEY_TOKEN, signPublicKey);

		auto hash = Sha256ComputeHash(blockStream.dataStream().toBuffer());
		ECDSA_DATA signature;
		TPM.sign(signPrivateKey, hash, signature);

		blockStream.write(fieldsDynamic, ECDSA_TOKEN, signature);
	}
};

struct OBJECT_HEADER
{
	TOKEN id;
	TOKEN fromtimestamp;
	TOKEN toTimestamp;
	TOKEN command;
	UINT32 dataOffset;

	OBJECT_HEADER(VLTOKEN& idToken) : id(idToken.contour) 
	{
		ASSERT(idToken.contour.isObject());
	}
};


struct OFFBLOCK_OBJECT
{
	TOKEN objectId;
	TOKEN timestamp;
	TOKEN diskId;
	UINT32 sectorIndex;
	UINT32 sectorCount;
	PIOBUF dataBuf = nullptr;
};

struct BLOCK_READER
{
	TOKEN blockId;
	TOKEN diskId;
	UINT32 sectorIndex;
	UINT32 sectorCount;
	PIOBUF dataBuf = nullptr;

	DATASTREAM<OBJECT_HEADER, SERVICE_STACK> objects;

	UINT32 age;

	BLOCK_READER(TOKEN blockId) : blockId(blockId)
	{
		age = GetUptimeS();
	}

	auto&& dataStream() { return dataBuf->dataStream; }
	auto&& ioState() { return dataBuf->ioState; }

	static bool validateBlock(BLOCK_READER& reader, VLBUFFER& blockData, BUFFER diskData)
	{
		auto result = false;

		auto headerTokens = blockData.readFragmentTokens();

		auto blockId = headerTokens.read().contour;
		if (reader.blockId) ASSERT(reader.blockId == blockId);

		BUFFER publicKey;
		for (auto&& token : headerTokens)
		{
			if (token.contour == ECDSA_TOKEN)
			{
				publicKey = token.contourBlob;
				break;
			}
		}

		ASSERT(publicKey);
		if (publicKey)
		{
			auto signature = diskData.shrink(ECDSA_SIGN_LENGTH);
			auto signHash = Sha256TempHash(diskData);
			result = ecdsa_verify(publicKey, signHash, signature);
		}
		return result;
	}

	static BUFFER shiftPreamble(BUFFER diskBlock)
	{
		auto preamble = diskBlock.readBytes(BLOCK_PREAMBLE);
		auto length = preamble.beReadU32() - BLOCK_PREAMBLE;

		return diskBlock.readBytes(length).rebase();
	}

	void parseSingleObject(OBJECT_HEADER& object, VLBUFFER& objectData)
	{
		auto attributeTokens = objectData.readFragmentTokens();
		object.fromtimestamp = attributeTokens.read().contour;
		object.toTimestamp = attributeTokens.read().contour;
		object.command = attributeTokens.read().contour;

		auto ticketFragment = objectData.readFragment();

		object.dataOffset = objectData.inputBuffer.mark();
	}

	void parseObjects(VLBUFFER& blockData)
	{
		while (auto objectFragment = blockData.readFragment())
		{
			auto objectToken = objectFragment.readToken();

			auto&& object = objects.append(objectToken);
			parseSingleObject(object, objectFragment);
		}
	}

	static void parseBlock(BLOCK_READER& reader, BUFFER diskData)
	{
		diskData = shiftPreamble(diskData);

		VLBUFFER blockData{ diskData };

		if (validateBlock(reader, blockData, diskData))
		{
			reader.parseObjects(blockData);
		}
	}
};