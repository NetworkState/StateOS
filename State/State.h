
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
struct STATE_SERVICE
{
	SERVICE_STACK serviceStack;
	SCHEDULER_INFO<> scheduler;
	DATASTREAM<DISK_VOLUME<STATE_SERVICE>, SERVICE_STACK> diskVolumes;

	IOBUF_MANAGER iobufManager;

	BLOCK_BUILDER<STATE_SERVICE> blockBuilder;

	DATASTREAM<BLOCK_READER, SESSION_STACK> blockCache;

	struct TICKETING
	{
		X509_KEY signKey;
		AES_GCM cipherKey;
		TPM_HANDLE ecdhPrivateKey;
		U512 ecdhPublicKey;
		DRBG_CTR idCounter{ TPM_COUNTER_TICKET };
		TOKEN serviceId;

		void init()
		{
			auto context = WriteMany(STATEOS_BRAND, " - TICKET");
			signKey.create(context);
			auto certBytes = File.ReadFile<GLOBAL_STACK>(TICKET_KEY_CRT);
			if (SystemService().CAsignKey.importAK(certBytes, signKey))
			{
				serviceId = ServiceTokens.createID(signKey.nodeId);
				ecdhPrivateKey = TPM.createECDHhandle(NULL_BUFFER, context, ecdhPublicKey);

				U512 keyData;
				auto keySecret = TPM.deriveKey(ecdhPrivateKey, context, keyData);
				cipherKey.init(keySecret.readBytes(32), keySecret.readBytes(32));;

				idCounter.init(keySecret);
			}
			else
			{
				TSTRING_STREAM nameStream;
				nameStream.append(SystemService().hostnameText);
				certBytes = signKey.buildCSR(false, CERT_KEYUSAGE, SystemService().hostnameText, nameStream.toBuffer());
				File.WriteFile(TICKET_KEY_CSR, certBytes);
				signKey.close();
			}
		}
	} ticketing;

	DRBG_CTR blockIdGen;

	QMSG_SERVICE msgService;

	STATE_SERVICE() : scheduler(serviceStack), msgService(scheduler), iobufManager(4096, 5), blockBuilder(*this) {}
	
	constexpr static BUFFER TICKET_KEY_CRT = "auth-ticket.crt";
	constexpr static BUFFER TICKET_KEY_CSR = "auth-ticket.csr";

	void init()
	{
		serviceStack.init(4 * 1024 * 1024, 0);
		scheduler.init();

		U512 keyGen;
		TPM.deriveKey(TPM.ECDHhandle, "BLOCK ID", keyGen);

		blockIdGen.init(keyGen);
		iobufManager.init();

		ticketing.init();

		blockCache.reserve(64);
	}

	static bool validateTicket(VLBUFFER& ticketData, BUFFER attachmentData)
	{
		auto result = false;
		if (auto bankId = ticketData.readToken())
		{
			auto signature = ticketData.readIfCloser(bankId);
			auto attachmentHash = ticketData.readIfCloser(bankId);

			auto ticketHash = Sha256TempHash(ticketData.inputBuffer, attachmentHash.contourBlob);

			result = SystemService().verifySignature(ServiceTokens.getID(bankId.contour), ticketHash, signature.contourBlob);
			if (result)
			{
				auto computedHash = Sha256TempHash(attachmentData);
				result = computedHash == attachmentHash.contourBlob;
			}
		}
		return result;
	}

	void signTicket(const TICKET& ticket, VISUAL_STREAM& ticketStream)
	{
		ASSERT(ticketing.signKey);

		auto parentDynamic = ticketStream.currentDynamic;
		auto nodeDynamic = parentDynamic.moveCloser();

		VISUAL_STREAM headerStream{ parentDynamic, 1024 };

		headerStream.write(parentDynamic, ticketing.serviceId);

		auto&& attachmentHash = Sha256TempHash(ticket.attachment);
		auto ticketHash = Sha256TempHash(ticketStream.toBuffer(), attachmentHash);

		auto signature = ticketing.signKey.signHash(ticketHash, ByteStream(64));
		headerStream.write(nodeDynamic, ECDSA_TOKEN, signature);

		if (ticket.attachment)
		{
			headerStream.write(nodeDynamic, SHA256_TOKEN, attachmentHash);
		}

		ticketStream.insert(headerStream.toBuffer());
	}

	NTSTATUS readDiskLayout(UINT32 index, PARTITION_INFORMATION_EX& partitionInfo)
	{
		auto status = STATUS_UNSUCCESSFUL;
		do
		{
			auto name = ByteStream(128).writeMany("\\??\\PhysicalDrive", index);
			OBJECT_ATTRIBUTES attrs;
			InitializeObjectAttributes(&attrs, name.toUnicodeString(), OBJ_CASE_INSENSITIVE, nullptr, nullptr);
			IO_STATUS_BLOCK ioStatus;
			HANDLE diskHandle;
			auto result = NtOpenFile(&diskHandle, GENERIC_READ, &attrs, &ioStatus, FILE_SHARE_READ | FILE_SHARE_WRITE, 0);
			if (NT_FAILED(result))
			{
				break;
			}

			auto&& ioctlOut = ByteStream(4096);
			auto ioctlRet = DeviceIoControl(diskHandle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, nullptr, 0, ioctlOut.address(), ioctlOut.spaceLeft(), (LPDWORD)&ioctlOut.setCount(), nullptr);
			if (ioctlRet == 0)
			{
				status = STATUS_IO_DEVICE_ERROR;
				CloseHandle(diskHandle);
				break;
			}

			ASSERT(ioctlOut.count() > 0);

			auto&& diskLayout = *(DRIVE_LAYOUT_INFORMATION_EX*)ioctlOut.address();
			if (diskLayout.PartitionStyle == PARTITION_STYLE_GPT)
			{
				for (UINT32 i = 0; i < diskLayout.PartitionCount; i++)
				{
					auto& partition = diskLayout.PartitionEntry[i];

					if (partition.Gpt.PartitionType == STATEOS_PARTITION)
					{
						RtlCopyMemory(&partitionInfo, &partition, sizeof(PARTITION_INFORMATION_EX));
						status = STATUS_SUCCESS;
						break;
					}
				}
			}

			CloseHandle(diskHandle);
		} while (false);
		return status;
	}

	void findVolumes()
	{
		for (UINT32 i = 0; i < 32; i++)
		{
			PARTITION_INFORMATION_EX partitionInfo;
			RtlZeroMemory(&partitionInfo, sizeof(PARTITION_INFORMATION_EX));

			auto status = readDiskLayout(i, partitionInfo);
			if (NT_SUCCESS(status))
			{
				auto&& volume = diskVolumes.append(*this);
				volume.init(i, partitionInfo);
			}
		}
	}

	IOBUF& allocBuf(UINT32 size, UINT64 ioOffset)
	{
		return iobufManager.alloc(size, ioOffset);
	}

	void freeBuf(IOBUF& iobuf)
	{
		iobufManager.free(iobuf);
	}

	IOBUF& resizeBuf(IOBUF& oldBuf, UINT32 newSize)
	{
		auto&& newBuf = iobufManager.alloc(newSize, 0);
		newBuf.dataStream.writeBytes(oldBuf.dataStream.toBuffer());

		iobufManager.free(oldBuf);
		return newBuf;
	}

	void readBlock(TOKEN blockId)
	{
		auto&& reader = blockCache.append(blockId);
		diskVolumes.at(0).readBlock(reader);
	}
};
