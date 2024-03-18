
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
constexpr UINT32 SECTOR_SIZE = 4096;
constexpr UINT32 CLUSTER_SIZE = 16 * 4096;

constexpr GUID STATEOS_PARTITION = { 0x5f3c4045, 0x1f16, 0x445b, { 0x91, 0x31, 0x3b, 0xa5, 0x42, 0xa9, 0x1e, 0x42 } };
// 5f3c4045-1f16-445b-9131-3ba542a91e42 
constexpr GUID MEDIA_APPID = { 0x6acc56dc, 0x5bab, 0x449a, {0x87, 0x90, 0xf8, 0xa4, 0x9d, 0x62, 0xf4, 0xd6 } };
// {B8281B3B-203F-43B8-B7A2-B866FE5A80A9}
constexpr GUID EMPTY_SECTOR_GUID = { 0xb8281b3b, 0x203f, 0x43b8, 0xb7, 0xa2, 0xb8, 0x66, 0xfe, 0x5a, 0x80, 0xa9 };

template <typename SERVICE = STATE_SERVICE>
struct DISK_VOLUME
{
	struct BLOCK_INDEX
	{
		TOKEN blockId;
		UINT32 sectorIndex;
		UINT32 sectorCount;
	};

	struct OFFBLOCK_INDEX
	{
		TOKEN objectId;
		TOKEN timestamp;
		UINT32 sectorIndex;
		UINT32 sectorCount;
	};

	struct VOLUME_STATE
	{
		U128 volumeId;
		U128 nodeId;

		UINT32 sectorSize;
		UINT32 clusterSize;

		UINT64 volumeSize;  // in bytes

		UINT64 writeTimestamp;
		UINT64 readTimestamp;

		UINT64 syncTimestamp;

		UINT64 writeHead; // byte Offset
	};

	constexpr static UINT64 DISK_BLOCK_EMPTY = BIT64(0);
	constexpr static UINT64 DISK_BLOCK_ENCRYPTED = BIT64(1);
	constexpr static UINT64 DISK_BLOCK_IN_USE = BIT64(2);

	VOLUME_STATE volumeState;

	SERVICE& service;

	HANDLE volumeHandle;
	UINT64 volumeSize;

	TOKEN volumeId;
	UINT32 sectorSize;

	BYTESTREAM stateStream;
	IOCALLBACK ioState;

	AES_CTR diskCipher;
	AES_GMAC diskGMAC;

	DATASTREAM<BLOCK_INDEX, SERVICE_STACK> blockMap;
	DATASTREAM<OFFBLOCK_INDEX, SERVICE_STACK> offblockMap;

	DISK_VOLUME(SERVICE& service) : service(service), ioState(IO_FILE_READ) {}

	bool findBlock(TOKEN blockId, BLOCK_READER& reader)
	{
		auto result = false;
		for (auto blocks = blockMap.toBuffer(); auto && block: blocks)
		{
			if (block.blockId == blockId)
			{
				reader.diskId = volumeId;
				reader.sectorIndex = block.sectorIndex;
				reader.sectorCount = block.sectorCount;
				result = true;
				break;
			}
		}
		return result;
	}

	NTSTATUS readBlock(BLOCK_READER& reader)
	{
		auto status = STATUS_UNSUCCESSFUL;

		auto blockOffset = UINT64(reader.sectorIndex) * sectorSize;
		auto blockSize = reader.sectorCount * sectorSize;
		
		reader.dataBuf = &service.allocBuf(blockSize, 0);

		NEW(reader.ioState().task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
			{
				auto&& volume = *(DISK_VOLUME*)context;
				auto&& block = *argv.read<BLOCK_READER*>(0);
				auto bytesRead = argv.read<DWORD>(1);

				block.dataStream().setCount(bytesRead);
				block.parseBlock(block, block.dataStream().toBuffer());

			}, this, &reader);

		status = File.Read(volumeHandle, blockOffset, reader.dataStream(), blockSize, reader.ioState());
		return status;
	}

	void formatVolume()
	{
		volumeState.nodeId = SystemService().getNodeId();
		volumeState.volumeSize = volumeSize;

		volumeState.sectorSize = SECTOR_SIZE;
		volumeState.clusterSize = SECTOR_SIZE;

		volumeState.writeHead = SECTOR_SIZE;
		volumeState.syncTimestamp = volumeState.writeTimestamp = volumeState.readTimestamp = GetTimestamp();

		writeEmptyBlock(SECTOR_SIZE, volumeState.volumeSize - SECTOR_SIZE);
	}

	void saveState()
	{
		stateStream.clear();

		auto firstHalf = stateStream.commitTo(SECTOR_SIZE / 2);
		auto secondHalf = stateStream.commitTo(SECTOR_SIZE / 2);

		firstHalf.writeBytes(PUINT8(&volumeState), sizeof(volumeState));
		secondHalf.writeBytes(PUINT8(&volumeState), sizeof(volumeState));

		auto encryptPart = secondHalf.toRWBuffer();
		diskCipher.encrypt(diskGMAC.multiply(volumeState.volumeId), encryptPart.toRWBuffer());

		NEW(ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
			{
				auto bytesTransferred = argv.read<DWORD>(0);
				ASSERT(bytesTransferred == SECTOR_SIZE);
			}, this);
		File.Write(volumeHandle, 0, stateStream.toBuffer(), ioState.start());
	}

	void restoreState(BUFFER savedState)
	{
		auto&& diskState = *(VOLUME_STATE*)savedState.data();
		if (true) //diskState.volumeId != volumeState.volumeId)
		{
			formatVolume();
		}
		else
		{
			savedState.shift(SECTOR_SIZE / 2);
			diskCipher.encrypt(diskGMAC.multiply(volumeState.volumeId), savedState.toRWBuffer());

			auto&& diskStateMirror = *(VOLUME_STATE*)savedState.data();
			ASSERT(diskStateMirror.volumeId == volumeState.volumeId);

			volumeState = diskState;
		}
	}

	NTSTATUS initVolume(U128 partitionId)
	{
		volumeState.volumeId = partitionId;
		volumeState.sectorSize = SECTOR_SIZE;
		volumeState.clusterSize = SECTOR_SIZE;

		NEW(ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
			{
				auto&& volume = *(DISK_VOLUME*)context;
				auto bytesTransferred = argv.read<DWORD>(0);
				volume.stateStream.setCount(bytesTransferred);

				ASSERT(bytesTransferred);
				volume.restoreState(volume.stateStream.toBuffer());
			}, this);
		return File.Read(volumeHandle, 0, stateStream.clear(), ioState);
	}

	void writeEmptyBlock(UINT64 offset, UINT64 size)
	{
		auto&& iobuf = service.allocBuf(SECTOR_SIZE, offset);
		auto&& headerStream = iobuf.dataStream.commitTo(16);

		auto flags = DISK_BLOCK_EMPTY;
		headerStream.writeVInt(size);
		headerStream.writeVInt(flags);
		headerStream.writeVInt(GetTimestamp());

		ASSERT(headerStream.count() <= 16);
		encrypt(iobuf);

		NEW(iobuf.ioState.task, [](PVOID context, NTSTATUS result, STASK_ARGV argv)
			{
				ASSERT(NT_SUCCESS(result));
				auto&& volume = *(DISK_VOLUME*)context;
				auto&& iobuf = *argv.read<PIOBUF>(0);
				auto bytesSent = argv.read<DWORD>(1);

				ASSERT(bytesSent == iobuf.dataStream.size());
				volume.service.freeBuf(iobuf);
				volume.saveState();
			}, this, &iobuf);

		File.Write(volumeHandle, iobuf);
	}

	inline void encrypt(UINT64 offset, RWBUFFER data)
	{
		auto&& iv = diskGMAC.multiply(offset + 256);
		diskCipher.encrypt(iv, data);
	}

	void encrypt(IOBUF& iobuf)
	{
		auto&& buf = iobuf.dataStream.toBuffer();
		auto dataStart = buf.data();
		while (buf)
		{
			auto&& sector = buf.readMax(SECTOR_SIZE);
			encrypt(iobuf.getOffset(sector), sector.toRWBuffer());
		}
	}

	void initCipher(BUFFER diskId)
	{
		U512 keyGenerated;
		auto key = TPM.deriveKey(TPM.ECDHhandle, diskId, keyGenerated);

		diskCipher.setKey(key.readBytes(32));
		diskCipher.setSalt(key.readBytes(16));

		diskGMAC.init(key.readU128());
	}

	PIOBUF readBlock(UINT64 offset)
	{
		auto firstSector = service.allocBuf(SECTOR_SIZE);

	}

	NTSTATUS write(UINT64 offset, RWBUFFER writeData, IOCALLBACK& ioState)
	{
		encrypt(offset, writeData);
		return File.Write(volumeHandle, offset, writeData.toBuffer(), ioState.start());
	}

	NTSTATUS init(UINT32 disk, PARTITION_INFORMATION_EX& partitionInfo)
	{
		auto status = STATUS_UNSUCCESSFUL;
		do
		{
			U128 partitionId{ partitionInfo.Gpt.PartitionId };
			volumeSize = partitionInfo.PartitionLength.QuadPart;
			auto filename = ByteStream(512).writeMany("\\\\.\\Harddisk", disk, "Partition", (UINT32)partitionInfo.PartitionNumber).toString();

			volumeHandle = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | FILE_FLAG_NO_BUFFERING | FILE_FLAG_WRITE_THROUGH, 0);
			if (volumeHandle == INVALID_HANDLE_VALUE)
			{
				status = LASTERROR();
				break;
			}

			GetCurrentScheduler().registerHandle(volumeHandle, nullptr);

			initCipher(partitionId);

			stateStream.setAddress((PUINT8)MemAlloc(SECTOR_SIZE), SECTOR_SIZE);

			status = initVolume(partitionId);
		} while (false);
		return status;
	}
};
