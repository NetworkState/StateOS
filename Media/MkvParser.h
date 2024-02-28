// Copyright (C) 2024 Network State.
// All rights reserved.


#pragma once

struct MKV_ELEMENT
{
	RTHANDLE name;
	UINT32 id;
};

constexpr MKV_ELEMENT Elements[] =
{
	{ MKV_EBML, 0x00A45DFA3},
	{ MKV_EBMLVersion, 0x0286},
	{ MKV_EBMLReadVersion, 0x02F7},
	{ MKV_EBMLMaxIdLength, 0x02F2},
	{ MKV_EBMLMaxSizeLength, 0x02F3},
	{ MKV_EBMLDocType, 0x0282},
	{ MKV_EBMLDocTypeVersion, 0x0287},
	{ MKV_EBMLDocTypeReadVersion, 0x0285},
	{ MKV_EBMLCrc32, 0x3F},
	{ MKV_EBMLVoid, 0x6C},
	{ MKV_Segment, 0x08538067},
	{ MKV_SeekHead, 0x014D9B74},
	{ MKV_Info, 0x0549A966},
	{ MKV_Cluster, 0x0F43B675},
	{ MKV_Tracks, 0x0654AE6B},
	{ MKV_Cues, 0x0C53BB6B},
	{ MKV_Attachments, 0x0941A469},
	{ MKV_Chapters, 0x0043A770},
	{ MKV_Tags, 0x0254C367},
	{ MKV_Seek, 0x0DBB},
	{ MKV_SeekID, 0x13AB},
	{ MKV_SeekPosition, 0x13AC},
	{ MKV_SegmentUID, 0x33A4},
	{ MKV_SegmentFilename, 0x3384},
	{ MKV_PrevUID, 0x1CB923},
	{ MKV_PrevFilename, 0x1C83AB},
	{ MKV_NextUID, 0x1EB923},
	{ MKV_NextFilename, 0x1E83BB},
	{ MKV_SegmentFamily, 0x0444},
	{ MKV_ChapterTranslate, 0x2924},
	{ MKV_TimecodeScale, 0x0AD7B1},
	{ MKV_Duration, 0x0489},
	{ MKV_DateUTC, 0x0461},
	{ MKV_Title, 0x3BA9},
	{ MKV_MuxingApp, 0x0D80},
	{ MKV_WritingApp, 0x1741},
	{ MKV_ChapterTranslateEditionUID, 0x29FC},
	{ MKV_ChapterTranslateCodec, 0x29BF},
	{ MKV_ChapterTranslateID, 0x29A5},
	{ MKV_ClusterTimecode, 0x67},
	{ MKV_ClusterSilentTracks, 0x1854},
	{ MKV_ClusterPosition, 0x27},
	{ MKV_ClusterPrevSize, 0x2B},
	{ MKV_SimpleBlock, 0x23},
	{ MKV_BlockGroup, 0x20},
	{ MKV_EncryptedBlock, 0x2F}, // not supported
	{ MKV_ClusterSilentTrackNumber, },
	{ MKV_Block, 0x21},
	{ MKV_BlockVirtual, 0x7FFF}, // not supported
	{ MKV_BlockAdditions, 0x35A1},
	{ MKV_BlockDuration, 0x1B},
	{ MKV_ReferencePriority, 0x7A},
	{ MKV_ReferenceBlock, 0x7B},
	{ MKV_ReferenceVirtual, 0x7D}, // not supported
	{ MKV_CodecState, 0x24},
	{ MKV_DiscardPadding, 0x35A2},
	{ MKV_Slices, 0x0E},
	{ MKV_ReferenceFrame, 0x48}, // DivX specific
	{ MKV_BlockMore, 0x26},
	{ MKV_BlockAddID, 0x6E},
	{ MKV_BlockAdditional, 0x25},
	{ MKV_TimeSlice, 0x68},
	{ MKV_SliceLaceNumber, 0x4C},
	{ MKV_SliceFrameNumber, 0x4D}, // not supported
	{ MKV_SliceBlockAddID, 0x4B}, // not supported
	{ MKV_SliceDelay, 0x4E}, // not supported
	{ MKV_SliceDuration, 0x4F}, // not supported
	{ MKV_ReferenceOffset, 0x49}, // DivX specific
	{ MKV_ReferenceTimeCode, 0x4A}, // DivX specific
	{ MKV_TrackEntry, 0x2E},
	{ MKV_TrackNumber, 0x57},
	{ MKV_TrackUID, 0x33C5},
	{ MKV_TrackType, 0x03},
	{ MKV_TrackFlagEnabled, 0x39},
	{ MKV_TrackFlagDefault, 0x08},
	{ MKV_TrackFlagForced, 0x15AA},
	{ MKV_TrackFlagLacing, 0x1C},
	{ MKV_TrackMinCache, 0x2DE7},
	{ MKV_TrackMaxCache, 0x2DF8},
	{ MKV_TrackDefaultDuration, 0x03E383},
	{ MKV_TrackDefaultDecodedFieldDuration, 0x034E7A},
	{ MKV_TrackTimecodeScale, 0x03314F},
	{ MKV_TrackOffset, 0x137F}, // not supported
	{ MKV_MaxBlockAdditionID, 0x15EE},
	{ MKV_TrackName, 0x136E},
	{ MKV_TrackLanguage, 0x02B59C},
	{ MKV_LanguageIETF, 0x02B59D},
	{ MKV_CodecID, 0x06},
	{ MKV_CodecPrivate, 0x23A2},
	{ MKV_CodecName, 0x058688},
	{ MKV_TrackAttachmentLink, 0x3446},
	{ MKV_CodecSettings, 0x1A9697}, // not supported
	{ MKV_CodecInfoURL, 0x1B4040}, // not supported
	{ MKV_CodecDownloadURL, 0x06B240}, // not supported
	{ MKV_CodecDecodeAll, 0x2A },
	{ MKV_TrackOverlay, 0x2FAB},
	{ MKV_CodecDelay, 0x16AA},
	{ MKV_SeekPreRoll, 0x16BB},
	{ MKV_TrackTranslate, 0x2624},
	{ MKV_TrackVideo, 0x60 },
	{ MKV_TrackAudio, 0x61 },
	{ MKV_TrackOperation, 0x62 },
	{ MKV_TrickTrackUID, 0x40}, // DivX specific
	{ MKV_TrickTrackSegmentUID, 0x41 }, // DivX specific
	{ MKV_TrickTrackFlag, 0x46 }, // DivX specific
	{ MKV_TrickMasterTrackUID, 0x47 }, // DivX specific
	{ MKV_TrickMasterTrackSegmentUID, 0x44 }, // DivX specific
	{ MKV_ContentEncodings, 0x2D80 },
	{ MKV_TrackTranslateEditionUID, 0x26FC },
	{ MKV_TrackTranslateCodec, 0x26BF },
	{ MKV_TrackTranslateTrackID, 0x26A5 },
	{ MKV_VideoFlagInterlaced, 0x1A },
	{ MKV_VideoFieldOrder, 0x1D },
	{ MKV_VideoStereoMode, 0x13B8 },
	{ MKV_VideoAlphaMode, 0x13C0 },
	{ MKV_OldStereoMode, 0x13B9 }, // not supported
	{ MKV_VideoPixelWidth, 0x30 },
	{ MKV_VideoPixelHeight, 0x3A },
	{ MKV_VideoPixelCropBottom, 0x14AA },
	{ MKV_VideoPixelCropTop, 0x14BB },
	{ MKV_VideoPixelCropLeft, 0x14CC },
	{ MKV_VideoPixelCropRight, 0x14DD },
	{ MKV_VideoDisplayWidth, 0x14B0 },
	{ MKV_VideoDisplayHeight, 0x14BA },
	{ MKV_VideoDisplayUnit, 0x14B2 },
	{ MKV_VideoAspectRatio, 0x14B3 },
	{ MKV_VideoColourSpace, 0x0EB524 },
	{ MKV_VideoGamma, 0x0FB523 }, // not supported
	{ MKV_VideoFrameRate, 0x0383E3 }, // not supported
	{ MKV_VideoColour, 0x15B0 },
	{ MKV_VideoProjection, 0x3670 },
	{ MKV_VideoColourMatrix, 0x15B1 },
	{ MKV_VideoBitsPerChannel, 0x15B2 },
	{ MKV_VideoChromaSubsampHorz, 0x15B3 },
	{ MKV_VideoChromaSubsampVert, 0x15B4 },
	{ MKV_VideoCbSubsampHorz, 0x15B5 },
	{ MKV_VideoCbSubsampVert, 0x15B6 },
	{ MKV_VideoChromaSitHorz, 0x15B7 },
	{ MKV_VideoChromaSitVert, 0x15B8 },
	{ MKV_VideoColourRange, 0x15B9 },
	{ MKV_VideoColourTransferCharacter, 0x15BA },
	{ MKV_VideoColourPrimaries, 0x15BB },
	{ MKV_VideoColourMaxCLL, 0x15BC },
	{ MKV_VideoColourMaxFALL, 0x15BD },
	{ MKV_VideoColourMasterMeta, 0x15D0 },
	{ MKV_VideoRChromaX, 0x15D1 },
	{ MKV_VideoRChromaY, 0x15D2 },
	{ MKV_VideoGChromaX, 0x15D3 },
	{ MKV_VideoGChromaY, 0x15D4 },
	{ MKV_VideoBChromaX, 0x15D5 },
	{ MKV_VideoBChromaY, 0x15D6 },
	{ MKV_VideoWhitePointChromaX, 0x15D7 },
	{ MKV_VideoWhitePointChromaY, 0x15D8 },
	{ MKV_VideoLuminanceMax, 0x15D9 },
	{ MKV_VideoLuminanceMin, 0x15DA },
	{ MKV_VideoProjectionType, 0x3671 },
	{ MKV_VideoProjectionPrivate, 0x3672 },
	{ MKV_VideoProjectionPoseYaw, 0x3673 },
	{ MKV_VideoProjectionPosePitch, 0x3674 },
	{ MKV_VideoProjectionPoseRoll, 0x3675 },
	{ MKV_AudioSamplingFreq, 0x35 },
	{ MKV_AudioOutputSamplingFreq, 0x38B5 },
	{ MKV_AudioChannels, 0x1F },
	{ MKV_AudioPosition, 0x3D7B }, // not supported
	{ MKV_AudioBitDepth, 0x2264 },
	{ MKV_TrackCombinePlanes, 0x63},
	{ MKV_TrackJoinBlocks, 0x69 },
	{ MKV_TrackPlane, 0x64 },
	{ MKV_TrackPlaneUID, 0x65 },
	{ MKV_TrackPlaneType, 0x66 },
	{ MKV_TrackJoinUID, 0x6D },
	{ MKV_ContentEncoding, 0x2240 },
	{ MKV_ContentEncodingOrder, 0x1031 },
	{ MKV_ContentEncodingScope, 0x1032 },
	{ MKV_ContentEncodingType, 0x1033 },
	{ MKV_ContentCompression, 0x1034 },
	{ MKV_ContentEncryption, 0x1035 },
	{ MKV_ContentCompAlgo, 0x0254 },
	{ MKV_ContentCompSettings, 0x0255 },
	{ MKV_ContentEncAlgo, 0x07E1 },
	{ MKV_ContentEncKeyID, 0x07E2 },
	{ MKV_ContentSignature, 0x07E3 },
	{ MKV_ContentSigKeyID, 0x07E4 },
	{ MKV_ContentSigAlgo, 0x07E5 },
	{ MKV_ContentSigHashAlgo, 0x07E6 },
	{ MKV_CuePoint, 0x3B },
	{ MKV_CueTime, 0x33 },
	{ MKV_CueTrackPositions, 0x37 },
	{ MKV_CueTrack, 0x77 },
	{ MKV_CueClusterPosition, 0x71 },
	{ MKV_CueRelativePosition, 0x70 },
	{ MKV_CueDuration, 0x32 },
	{ MKV_CueBlockNumber, 0x1378 },
	{ MKV_CueCodecState, 0x6A },
	{ MKV_CueReference, 0x5B },
	{ MKV_CueRefTime, 0x16 },
	{ MKV_CueRefCluster, 0x17 }, // not supported
	{ MKV_CueRefNumber, 0x135F }, // not supported
	{ MKV_CueRefCodecState, 0x6B }, // not supported
	{ MKV_Attached, 0x21A7 },
	{ MKV_FileDescription, 0x067E },
	{ MKV_FileName, 0x066E },
	{ MKV_MimeType, 0x0660 },
	{ MKV_FileData, 0x065C },
	{ MKV_FileUID, 0x06AE },
	{ MKV_FileReferral, 0x0675 }, // not supported
	{ MKV_FileUsedStartTime, 0x0661 }, // DivX specific
	{ MKV_FileUsedEndTime, 0x0662 }, // DivX specific
	{ MKV_EditionEntry, 0x05B9 },
	{ MKV_EditionUID, 0x05BC },
	{ MKV_EditionFlagHidden, 0x05BD },
	{ MKV_EditionFlagDefault, 0x05DB },
	{ MKV_EditionFlagOrdered, 0x05DD },
	{ MKV_ChapterAtom, 0x36 },
	{ MKV_ChapterUID, 0x33C4 },
	{ MKV_ChapterStringUID, 0x1654 },
	{ MKV_ChapterTimeStart, 0x11 },
	{ MKV_ChapterTimeEnd, 0x12 },
	{ MKV_ChapterFlagHidden, 0x18 },
	{ MKV_ChapterFlagEnabled, 0x0598 },
	{ MKV_ChapterSegmentUID, 0x2E67 },
	{ MKV_ChapterSegmentEditionUID, 0x2EBC },
	{ MKV_ChapterPhysicalEquiv, 0x23C3 },
	{ MKV_ChapterTrack, 0x0F },
	{ MKV_ChapterDisplay, 0x00 },
	{ MKV_ChapterProcess, 0x2944 },
	{ MKV_ChapterTrackNumber, 0x09 },
	{ MKV_ChapterString, 0x05 },
	{ MKV_ChapterLanguage, 0x037C },
	{ MKV_ChapLanguageIETF, 0x037D },
	{ MKV_ChapterCountry, 0x037E },
	{ MKV_ChapterProcessCodecID, 0x2955 },
	{ MKV_ChapterProcessPrivate, 0x050D },
	{ MKV_ChapterProcessCommand, 0x2911 },
	{ MKV_ChapterProcessTime, 0x2922 },
	{ MKV_ChapterProcessData, 0x2933 },
	{ MKV_Tag, 0x3373 },
	{ MKV_TagTargets, 0x23C0 },
	{ MKV_TagSimple, 0x27C8 },
	{ MKV_TagTargetTypeValue, 0x28CA },
	{ MKV_TagTargetType, 0x23CA },
	{ MKV_TagTrackUID, 0x23C5 },
	{ MKV_TagEditionUID, 0x23C9 },
	{ MKV_TagChapterUID, 0x23C4 },
	{ MKV_TagAttachmentUID, 0x23C6 },
	{ MKV_TagName, 0x05A3 },
	{ MKV_TagLangue, 0x047A },
	{ MKV_TagLanguageIETF, 0x047B },
	{ MKV_TagDefault, 0x0484 },
	{ MKV_TagString, 0x0487 },
	{ MKV_TagBinary, 0x0485 },
};

constexpr RTHANDLE MKV_MASTER_ELEMENTS[] = { MKV_EBML, MKV_Segment, MKV_SeekHead, MKV_Seek, MKV_Info, MKV_Cluster, MKV_Tracks,
MKV_Attachments, MKV_Attached, MKV_Chapters, MKV_ChapterTranslate, MKV_ClusterSilentTracks, MKV_Tags,
MKV_TrackEntry, MKV_BlockGroup, MKV_BlockAdditions, MKV_BlockMore, MKV_Slices, MKV_TimeSlice, MKV_ReferenceFrame,
MKV_TrackTranslate, MKV_TrackVideo, MKV_VideoColour, MKV_VideoProjection, MKV_TrackAudio, MKV_TrackOperation,
MKV_TrackCombinePlanes, MKV_TrackPlane, MKV_TrackJoinBlocks, MKV_ContentEncodings, MKV_ContentEncoding,
MKV_ContentCompression, MKV_ContentEncryption, MKV_Cues, MKV_CuePoint, MKV_CueTrackPositions, MKV_CueReference,
MKV_EditionEntry, MKV_ChapterAtom, MKV_ChapterTrack, MKV_ChapterDisplay, MKV_ChapterProcess, MKV_ChapterProcessCommand,
MKV_Tag, MKV_TagTargets, MKV_TagSimple, };

constexpr bool IsMasterElement(RTHANDLE id)
{
	for (auto element : MKV_MASTER_ELEMENTS)
	{
		if (element == id)
			return true;
	}
	return false;
}

struct MKV_MASTER_ELEMENT
{
	FILE_READER& fileReader;
	INT64 bytesLeft;
	RTHANDLE elementName;

	MKV_MASTER_ELEMENT(RTHANDLE name, FILE_READER& reader, UINT64 size) : elementName(name), fileReader(reader), bytesLeft(size)
	{
		ASSERT(size > 0);
	}

	PUINT8 read(UINT32 count = 1)
	{
		ASSERT(bytesLeft >= count);
		PUINT8 data = nullptr;
		if (bytesLeft > 0)
		{
			data = fileReader.read(count);
		}
		bytesLeft -= count;

		return data;
	}

	BUFFER readData(UINT32 length)
	{
		auto data = read(length);
		return { data, length };
	}

	UINT8 readByte()
	{
		auto data = read();
		if (data == nullptr)
		{
			return 0;
		}
		auto readByte = *data;
		return readByte;
	}

	UINT64 readVInt(UINT8 lengthByte)
	{
		UINT64 value;
		UINT32 valueLength = 0;
		for (int i = 0; i < 8; i++)
		{
			UINT8 pattern = 0x80 >> i;
			if (lengthByte & pattern)
			{
				value = lengthByte & ~pattern;
				valueLength = i;
				value <<= (valueLength * 8);
				break;
			}
		}

		for (int i = valueLength - 1; i >= 0; i--)
		{
			UINT64 byte = *read();
			value |= (byte << (i * 8));
		}
		return value;
	}

	UINT64 readVInt()
	{
		auto firstByte = readByte();
		return readVInt(firstByte);
	}

	RTHANDLE readElementId()
	{
		if (this->bytesLeft <= 0)
			return Undefined;

		auto firstByte = readByte();
		if (firstByte == 0x80)
		{
			read();
			return readElementId();
		}
		auto id = readVInt(firstByte);

		for (auto& element : Elements)
		{
			if (element.id == id)
			{
				return element.name;
			}
		}
		return Undefined;
	}

	UINT64 readDataLength()
	{
		auto firstByte = readByte();
		return readVInt(firstByte);
	}

	MKV_MASTER_ELEMENT readMasterElement(RTHANDLE childElement, UINT64 size)
	{
		this->bytesLeft -= size;
		return MKV_MASTER_ELEMENT(childElement, this->fileReader, size);
	}

	template <typename FUNC, typename ... ARGS>
	void readElements(FUNC callback, ARGS&& ... args)
	{
		while (auto id = readElementId())
		{
			auto length = readDataLength();
			callback(id, length, args ...);
		}
	}
};

constexpr UINT8 MKV_XIPH_LACING = 0x02;
constexpr UINT8 MKV_FIXED_SIZE_LACING = 0x04;
constexpr UINT8 MKV_EBML_LACING = 0x06;
constexpr UINT8 MKV_LACING_MASK = 0x06;

void ReadCluster(MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& cluster)
{
	auto& volume = SyncService().getWriteVolume();

	UINT64 clusterTimeCode = 0;
	while (auto id = cluster.readElementId())
	{
		auto length = cluster.readDataLength();
		if (id == MKV_ClusterTimecode)
		{
			auto data = cluster.readData((UINT32)length);
			clusterTimeCode = data.readUIntBE((UINT32)length);
			LogInfo("Import clusterTime: %d", clusterTimeCode);
		}
		else if (id == MKV_SimpleBlock)
		{
			auto block = cluster.readMasterElement(id, length);
			auto trackNumber = block.readVInt();

			auto header = block.readData(3);
			UINT64 timeCode = header.readBE<UINT16>();
			timeCode += clusterTimeCode;

			auto flags = header.readByte();

			if (flags & MKV_LACING_MASK)
			{
				// XXX TODO: add support for lacing.
			}

			auto& track = mediaParser.findTrack((UINT32)trackNumber);
			ASSERT(track);

			if (track)
			{
				if (track.commandStream.count() == 0)
				{
					WriteCommandHeader(track.commandStream, MEDIA_APPID, mediaParser.id, 0, mediaParser.timestamp, SYNC_frame);
					track.visualStream.format(track.commandStream);

					track.commandStream.writeVisualToken(nullptr, clusterTimeCode, TOKENTYPE::NUMBER, VSIZE::MEDIUM, VSPAN::WORD);
					track.commandStream.writeVisualToken<SCHEDULER_STACK>(VISUAL_TOKEN(SYNC_cluster_time, VSIZE::SMALL, VSPAN::COLON));

					track.commandStream.writeLengthAt(CommandHeaerLength);
				}
				track.totalBytes += block.bytesLeft;
				track.maxPacketSize += block.bytesLeft;
				auto& dataStream = track.commandStream;
				auto offset = dataStream.saveOffset(4);

				dataStream.writeInt<UINT64>(timeCode);

				while (block.bytesLeft > 0)
				{
					auto toRead = min(block.bytesLeft, 512 * 1024);
					auto readData = block.readData((UINT32)toRead);

					dataStream.writeStream(readData);
				}

				offset.writeLength();
			}
		}
		else
		{
			//LogInfo("Unknown LEN:%d", length);
			cluster.readData((UINT32)length);
		}
	}

	for (auto& track : mediaParser.mediaTracks.toBufferNoConst())
	{
		if (track.commandStream.count() > 0)
		{
			track.commandStream.writeAtBE<UINT32>(0, (UINT32)track.commandStream.count());
			volume.writeData(track.commandStream.toBuffer());
			track.commandStream.clear();
			track.maxPacketSize = 0;
		}
	}
}

void ReadElements(MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& master)
{
	master.readElements([](TOKEN name, UINT64 length, MEDIA_PARSER& mediaParser, MKV_MASTER_ELEMENT& master)
		{
			if (IsMasterElement(name))
			{
				auto childElement = master.readMasterElement(name, length);
				if (name == MKV_TrackEntry)
				{
					auto& track = mediaParser.mediaTracks.append();
					track.visualStream.writeSpan(VSPAN::ITEM);
					ReadElements(mediaParser, childElement);
				}
				else if (name == MKV_Tracks)
				{
					ReadElements(mediaParser, childElement);
					WriteMetadata(mediaParser);
				}
				else if (name == MKV_Cluster)
				{
					//LogInfo("Cluster: %d, BytesLeft: %d", childElement.bytesLeft, master.bytesLeft);
					ReadCluster(mediaParser, childElement);
				}
				else
				{
					ReadElements(mediaParser, childElement);
				}
			}
			else
			{
				auto data = master.readData((UINT32)length);
				if (master.elementName == MKV_Info)
				{
					auto& visualStream = mediaParser.metadataStream;

					if (name == MKV_Title)
					{
						visualStream.writeValue(String.parseLiteral<SCHEDULER_STACK>(data), VSIZE::LARGE, VSPAN::WORD);
					}
					else if (name == MKV_SegmentUID)
					{
						ASSERT(data.length() == sizeof(GUID));
						mediaParser.id = data.readGuid();
						visualStream.writeValue(CreateGuidToken<SCHEDULER_STACK>(mediaParser.id), VSIZE::XSMALL, VSPAN::WORD);
						visualStream.writeAttr(SYNC_id, VSIZE::XXSMALL, VSPAN::COLON);
					}
					else if (name == MKV_TimecodeScale)
					{
						auto value = data.readUIntBE((UINT32)length);
						mediaParser.timecodeScale = value;
					}
					else if (name == MKV_Duration)
					{
						ASSERT(data.length() == 8);
						auto number = data.readBE<double>();
						visualStream.writeValueAttr(CreateNumberToken<SCHEDULER_STACK>((INT64)number), SYNC_duration);
					}
					else if (name == MKV_DateUTC)
					{
						auto value = data.readUIntBE((UINT32)length) / 100; // to 100ns resolution
						auto systemTime = MkvToSystemTime(value);
						visualStream.writeValueAttr(CreateNumberToken<SCHEDULER_STACK>(systemTime), SYNC_date);
					}
				}
				else if (master.elementName == MKV_TrackEntry)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_TrackType)
					{
						auto typeData = data.readByte();
						track.type = typeData == 0x01 ? SYNC_video
							: typeData == 0x02 ? SYNC_audio
							: typeData == 0x03 ? SYNC_subtitle
							: SYNC_unknown;

						track.visualStream.writeValue(track.type);
					}
					else if (name == MKV_TrackNumber)
					{
						track.trackId = data.readByte();
					}
					else if (name == MKV_CodecID)
					{
						auto mkvCodecId = String.parseLiteral<SCHEDULER_STACK>(data);
						auto codecId = mkvCodecId == MKV_V_MPEG4_ISO_AVC ? SYNC_h264 :
							mkvCodecId == MKV_A_VORBIS ? SYNC_vorbis :
							mkvCodecId == MKV_A_OPUS ? SYNC_opus : SYNC_unknown;

						LogInfo("Coded ID = 0x%x", codecId.getShortName());
						track.visualStream.writeValue(codecId);
					}
					else if (name == MKV_CodecPrivate)
					{
						track.codecPrivate = CreateBlobToken<SCHEDULER_STACK>(data);
					}
				}
				else if (master.elementName == MKV_TrackVideo)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_VideoPixelWidth)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto videoSize = value == 1920 ? MEDIA_1080p
							: value == 4096 ? MEDIA_4k
							: value == 1280 ? MEDIA_720p
							: value == 720 ? MEDIA_480p
							: SYNC_unknown;

						track.visualStream.writeValue(videoSize);
					}
					if (name == MKV_VideoPixelHeight)
					{
					}
				}
				else if (master.elementName == MKV_TrackAudio)
				{
					auto& track = mediaParser.mediaTracks.last();
					if (name == MKV_AudioSamplingFreq)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto frequency = value == 48000 ? MEDIA_48000hz
							: value == 96000 ? MEDIA_96000hz
							: value == 19200 ? MEDIA_192000hz
							: value == 22500 ? MEDIA_22500hz
							: SYNC_unknown;

						track.visualStream.writeValue(frequency);
					}
					else if (name == MKV_AudioChannels)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto channels = value == 6 ? MEDIA_5_1
							: value == 1 ? MEDIA_mono
							: value == 2 ? MEDIA_stereo
							: SYNC_unknown;

						ASSERT(channels != SYNC_unknown);
						track.visualStream.writeValue(channels);
					}
					else if (name == MKV_AudioBitDepth)
					{
						auto value = data.readUIntBE((UINT32)length);
						auto bitDepth = value == 32 ? MEDIA_32bit
							: value == 24 ? MEDIA_24bit
							: value == 16 ? MEDIA_16bit
							: value == 8 ? MEDIA_8bit
							: SYNC_unknown;

						ASSERT(bitDepth != SYNC_unknown);
						track.visualStream.writeValue(bitDepth);
					}
				}

			}
		}, mediaParser, master);
}

void ImportMkvFile(MEDIA_PARSER& mediaParser, USTRING filename)
{
	auto status = STATUS_SUCCESS;
	do
	{
		FILE_READER fileReader;

		mediaParser.clear();
		mediaParser.timestamp = GetStateOsTime();

		mediaParser.metadataStream.writeSpan(VSPAN::SECTION);

		status = fileReader.open(filename);
		if (!NT_SUCCESS(status))
			break;

		auto masterElement = MKV_MASTER_ELEMENT(NULL_NAME, fileReader, fileReader.fileSize);
		ReadElements(mediaParser, masterElement);

		MergeMetadata(mediaParser);

		fileReader.Close();

		LogInfo("ImportMkvFile: Done with %s", filename.data());
	} while (false);
}

struct MEDIA_PARSER
{
	struct MEDIA_TRACK
	{
		TOKEN type;
		UINT32 trackId;
		TOKEN codecPrivate;
		VISUALSTREAM<SCHEDULER_STACK> visualStream;
		STREAM_BUILDER<UINT8, SCHEDULER_STACK, 1> commandStream;

		UINT64 maxPacketSize = 0;
		UINT64 totalBytes = 0;
		explicit operator bool() const { return IsValidRef(*this); }
	};

	GUID id;
	UINT64 timecodeScale = 0;

	UINT64 timestamp;
	VISUALSTREAM<SCHEDULER_STACK> metadataStream;;

	STREAM_BUILDER<MEDIA_TRACK, SCHEDULER_STACK, 4> mediaTracks;

	DISK_OFFSET metadataDiskOffset;

	auto& findTrack(UINT32 trackId)
	{
		for (auto& track : mediaTracks.toBufferNoConst())
		{
			if (track.trackId == trackId)
			{
				return track;
			}
		}
		return NullRef<MEDIA_TRACK>();
	}

	void clear()
	{
		mediaTracks.clear();
		metadataStream.stream.clear();
	}
};

