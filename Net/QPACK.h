
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct H3_FIELD
{
    TOKEN name;
    TOKEN value;
};

inline UINT8 BHSI(UINT8 x)
{
    auto offset = _lzcnt_u32(UINT32(x) << 24);
    return UINT8(0x80 >> offset);
}

constexpr bool GetNextBit(UINT8 bitMask, UINT8 value)
{
    return value & (bitMask >> 1) ? true : false;
}

using H3_HEADERS = STREAM_READER<H3_FIELD>;

#include "QPACK_constants.h"

struct QPACK
{
    template <typename STREAM>
    struct BIT_BUILDER
    {
        UINT8 partialByte = 0;
        UINT8 partialBits = 0;

        STREAM& byteStream;
        BIT_BUILDER(STREAM& inStream) : byteStream(inStream) {}

        void finish()
        {
            if (partialBits > 0)
            {
                byteStream.writeByte(partialByte);
            }
            partialBits = 0;
        }

        void writeByte(UINT8 value)
        {
            ASSERT(partialBits == 0);
            byteStream.writeByte(value);
        }

        void writeBits(UINT8 value, UINT8 width) // MSB aligned (left)
        {
            ASSERT(width < 8);
            UINT8 bitCount = partialBits + width;

            if (bitCount >= 8)
            {
                byteStream.writeByte((value >> partialBits) | partialByte);
                partialBits = bitCount - 8;
                partialByte = value << (width - partialBits);
            }
            else
            {
                partialByte |= (value >> partialBits);
                partialBits = bitCount;
            }
        }

        void writeBitFlag(bool flag)
        {
            UINT8 bit = flag ? 1 : 0;
            partialByte |= (bit << (7 - partialBits));
            partialBits++;
        }

        void writeCode(const BITPATTERN bitPattern)
        {
            ASSERT(partialBits == 0);
            writeBits(bitPattern.code, _mm_popcnt_u32(bitPattern.mask));
        }

        UINT8 bitsLeft() { return 8 - partialBits; }

        void writeInteger(UINT32 value, UINT8 bitsExpected = 0)
        {
            auto bits = bitsLeft();
            ASSERT(bitsExpected == 0 || bitsExpected == bits);

            auto mask = MASK32(bits);
            byteStream.writeByte(partialByte | (UINT8)min(mask, value));
            if (value >= mask)
            {
                value -= mask;
                do
                {
                    auto byte = UINT8(value & 0x7F);
                    value >>= 7;
                    byteStream.writeByte(byte | (value ? 0x80 : 0));
                } while (value);
            }
            partialBits = partialByte = 0;
        }

        void writeInteger(const BITPATTERN prefix, UINT32 value)
        {
            writeCode(prefix);
            writeInteger(value);
        }

        void writeBytes(BUFFER data)
        {
            ASSERT(partialBits == 0);
            byteStream.writeBytes(data);
        }

        void writeString(TOKEN value)
        {
            auto valueString = SessionTokens.toString(value);
            writeBitFlag(false); // no huffman
            writeInteger(valueString.length());
            writeBytes(valueString);
        }

        BUFFER toBuffer()
        {
            ASSERT(partialBits == 0);
            return byteStream.toBuffer();
        }
    };

    struct BIT_READER
    {
        const UINT8* data;
        UINT32 start, end; // in bits

        BIT_READER(BUFFER inData)
        {
            data = inData.data();
            start = 0;
            end = inData.length() * 8;
        }

        UINT8 readEncoderCode()
        {
            ASSERT((start % 8) == 0);
        }

        UINT32 shadow32bit()
        {
            UINT8 shadowBits[4]{ 0xFF, 0xFF, 0xFF, 0xFF };
            auto bytes = min(ROUND8(length()) / 8, 4);
            auto offset = start >> 3;
            RtlCopyMemory(shadowBits, &data[offset], bytes);
            return _byteswap_ulong(*(UINT32*)shadowBits);
        }

        UINT32 peekBits(UINT8 bitCount)
        {
            UINT32 int32bit = shadow32bit();
            auto mask = ROR32(MASK32(bitCount), bitCount + (start & 0x07));
            return _pext_u32(int32bit, mask);
        }

        UINT32 readBits(UINT8 bitCount)
        {
            auto value = peekBits(bitCount);
            start += bitCount;
            return value;
        }

        bool readBitFlag()
        {
            return readBits(1) ? true : false;
        }

        UINT8 bitsLeft() { return start & 0x07; }

        UINT32 length()
        {
            return end - start;
        }

        UINT32 lengthBytes()
        {
            ASSERT(bitsLeft() == 0);
            return (end - start) >> 3;
        }

        UINT8 peekByte()
        {
            ASSERT(bitsLeft() == 0);
            return data[start >> 3];
        }

        BUFFER readBytes(UINT32 byteCount)
        {
            ASSERT((start & 0x07) == 0);
            ASSERT((length() >> 3) >= byteCount);
            if ((length() >> 3) >= byteCount)
            {
                BUFFER bytes{ data + (start >> 3), byteCount };
                start += (byteCount << 3);
                return bytes;
            }
            else
            {
                return NULL_BUFFER;
            }
        }

        UINT32 decodeInteger()
        {
            UINT32 value = -1;
            do
            {
                if (length() == 0)
                    break;

                auto maskBits = 8 - (start & 0x07);
                value = readBits(maskBits);
                auto prefixMask = MASK32(maskBits);
                if (prefixMask == value)
                {
                    auto int32 = _byteswap_ulong(shadow32bit());
                    auto contigBits = _pext_u32(int32, 0x80808080);
                    contigBits = _tzcnt_u32(~contigBits) + 1;

                    ASSERT(contigBits < 3);
                    if (lengthBytes() < contigBits)
                    {
                        value = -1;
                        break;
                    }
                    UINT32 extractMask = 0x7F7F7F7F >> ((4 - contigBits) * 8);
                    value = _pext_u32(int32, extractMask) + prefixMask;
                    readBytes(contigBits);
                }
            } while (false);
            return value;
        }

        BUFFER readString()
        {
            BUFFER stringValue;
            auto isHuffman = readBitFlag();
            auto stringLength = decodeInteger();
            if (stringLength != -1 && lengthBytes() >= stringLength)
            {
                stringValue = readBytes(stringLength);
                if (isHuffman) stringValue = decodeHuffmanString(stringValue);
            }
            return stringValue;
        }

        TOKEN readName()
        {
            auto stringValue = readString();
            return SessionTokens.createName(stringValue);
        }

        TOKEN readValue(TOKEN name)
        {
            TOKEN value;
            auto stringValue = readString();
            if (name == QPACK_date)
            {
                auto dateTime = String.parseHttpDate(stringValue); // in ms
                return SessionTokens.createDateTime(dateTime / 1000);
            }
            else if (name == QPACK_content_length)
            {
                return SessionTokens.createNumber(String.toNumber(stringValue));
            }
            else
            {
                return SessionTokens.createName(stringValue);
            }
        }

        bool matchCode(BITPATTERN code)
        {
            if (code.match(peekByte()))
            {
                start += _mm_popcnt_u32(code.mask);
                return true;
            }
            return false;
        }

        BITPATTERN matchHeaderCode()
        {
            auto codeByte = peekByte();
            auto code = HEADER_INDEXED_DYNAMIC.match(codeByte) ? HEADER_INDEXED_DYNAMIC
                : HEADER_INDEXED_STATIC.match(codeByte) ? HEADER_INDEXED_STATIC
                : HEADER_INDEXED_POSTBASE.match(codeByte) ? HEADER_INDEXED_POSTBASE
                : HEADER_NAME_INDEXED_DYNAMIC.match(codeByte) ? HEADER_NAME_INDEXED_DYNAMIC
                : HEADER_NAME_INDEXED_STATIC.match(codeByte) ? HEADER_NAME_INDEXED_STATIC
                : HEADER_NAME_INDEXED_POSTBASE.match(codeByte) ? HEADER_NAME_INDEXED_POSTBASE
                : HEADER_NOT_INDEXED.match(codeByte) ? HEADER_NOT_INDEXED : NULL_BITPATTERN;
            start += _mm_popcnt_u32(code.mask);
            return code;
        }
        explicit operator bool() const { return end > start; }
    };

    constexpr static bool IS_NOT_COMPRESSED(TOKEN name) { return name == QPACK_content_length || name == QPACK_date || name == QPACK_etag; }

    constexpr static UINT32 DYNAMIC_TABLE_MAX_SIZE = 65536;
    constexpr static UINT32 DYNAMIC_TABLE_MAX_ENTRIES = 65536 / 32;

    struct DYNAMIC_TABLE
    {
        UINT32 maxEntries = DYNAMIC_TABLE_MAX_ENTRIES;
        UINT32 writeOffset;
        UINT32 pendingInserts = 0;
        H3_FIELD fieldTable[DYNAMIC_TABLE_MAX_ENTRIES * 2];

        UINT32 getCapacity()
        {
            return maxEntries * 32;
        }

        UINT32 getInsertCount()
        {
            return writeOffset;
        }

        void setCapacity(UINT32 bytes)
        {
            if (bytes < (maxEntries * 32))
            {
                maxEntries = bytes / 32;
            }
            else DBGBREAK();
        }

        UINT32 write(TOKEN name, TOKEN value)
        {
            auto position = writeOffset;
            auto&& field = getField(writeOffset++);

            field.name = name;
            field.value = value;

            return position;
        }

        QPFIELD duplicateField(QPFIELD& field)
        {
            QPFIELD command{ ENCODE_DUPLICATE, writeOffset - field.index };

            auto&& entry = getField(field.index);
            field.index = write(entry.name, entry.value);
            return command;
        }

        QPFIELD writeField(QPFIELD& field)
        {
            QPFIELD command;
            command.name = field.name;
            command.value = field.value;
            if (field.code == HEADER_NAME_INDEXED_STATIC)
            {
                command.code = ENCODE_INSERT_NAME_INDEX_STATIC;
                command.index = field.index;
            }
            else if (field.code == HEADER_NAME_INDEXED_DYNAMIC)
            {
                command.code = ENCODE_INSERT_NAME_INDEX_DYNAMIC;
                command.index = writeOffset - field.index;
            }
            else
            {
                ASSERT(field.code == HEADER_NOT_INDEXED);
                command.code = ENCODE_INSERT_LITERAL_NAME;
                command.index = 0;
            }

            field.index = write(field.name, field.value);
            field.code = HEADER_INDEXED_DYNAMIC;

            return command;
        }

        void writeCommand(const QPFIELD& command)
        {
            if (command.code == ENCODE_DUPLICATE)
            {
                auto&& entry = getField(writeOffset - command.index);
                write(entry.name, entry.value);
            }
            else if (command.code == ENCODE_INSERT_NAME_INDEX_DYNAMIC)
            {
                auto&& entry = getField(writeOffset - command.index);
                write(entry.name, command.value);
            }
            else if (command.code == ENCODE_INSERT_NAME_INDEX_STATIC)
            {
                write(QPACK_STATIC[command.index].name, command.value);
            }
            else DBGBREAK();
        }

        H3_FIELD& getField(UINT32 absoluteIndex)
        {
            return fieldTable[absoluteIndex % maxEntries];
        }

        UINT32 find(TOKEN name, TOKEN value)
        {
            auto rangeEnd = writeOffset > maxEntries ? writeOffset - maxEntries : 1;
            for (UINT32 i = writeOffset; i > rangeEnd; i--)
            {
                auto&& field = getField(i - 1);
                if (field.name == name && field.value == value)
                {
                    return i;
                }
            }
            return -1;
        }

        INT32 setDrainPoint(UINT32 encodeCount = 16, UINT32 encodeBytes = 16 * 64)
        {
            auto sizeLimit = getCountAtSize(getCapacity() - encodeBytes);
            auto countLimit = maxEntries - encodeCount;
            return writeOffset - min(sizeLimit, countLimit);
        }

        UINT32 getCountAtSize(UINT32 capacity)
        {
            UINT32 limit = maxEntries;
            UINT32 totalSize = 0;
            for (UINT32 i = 0, j = min(writeOffset, maxEntries); i < j; i++)
            {
                auto&& field = getField(writeOffset - i);
                auto fieldSize = 32 + GetNameLength(field.name);
                fieldSize += GetNameLength(field.value);
                if ((totalSize + fieldSize) > capacity)
                {
                    limit = i + 1;
                    break;
                }
            }
            return limit;
        }
    };

    struct ENCODER
    {
        STREAM_STATE recvState;
        STREAM_STATE sendState;

        DYNAMIC_TABLE dynamicTable;

        void parseCommands(BUFFER data)
        {
            BIT_READER dataReader{ data };
            while (dataReader)
            {
                if (dataReader.matchCode(DECODE_INSERT_COUNT_INCREMENT))
                {
                    auto count = dataReader.decodeInteger();
                }
                else if (dataReader.matchCode(DECODE_SECTION_ACK))
                {
                    auto streamId = dataReader.decodeInteger();
                }
                else if (dataReader.matchCode(DECODE_STREAM_CANCELLATION))
                {
                    auto streamId = dataReader.decodeInteger();
                }
                else DBGBREAK();
            }
        }

        template <typename BITSTREAM>
        void writeNameValue(BITSTREAM& outStream, BUFFER nameString, BUFFER valueString)
        {
            outStream.writeCode(HEADER_NOT_INDEXED);

            outStream.writeBitFlag(false);
            outStream.writeInteger(nameString.length());
            outStream.writeBytes(nameString);

            outStream.writeBitFlag(false); 
            outStream.writeInteger(valueString.length());
            outStream.writeBytes(valueString);
        }

        UINT32 getSectionBytes(H3_HEADERS section)
        {
            UINT32 byteCount = 0;
            for (auto&& field : section)
            {
                byteCount += GetNameLength(field.name);
                byteCount += GetNameLength(field.value);
                byteCount += 8;
            }
            return byteCount;
        }

        struct SECTION_STATE
        {
            UINT32 base;
            DATASTREAM<QPFIELD, SCHEDULER_STACK> headerStream;
            UINT64 streamId;
            INT32 drainPoint;
            ENCODER& encoder;

            SECTION_STATE(ENCODER& encoder) : encoder(encoder) {}

            void init(UINT32 fieldCount = 16)
            {
                base = encoder.dynamicTable.writeOffset;
                drainPoint = encoder.dynamicTable.setDrainPoint();
                headerStream.clear().reserve(fieldCount);
            }

            void addField(QPFIELD fieldIn)
            {
                auto field = encoder.encodeField(fieldIn);
                if (field.isDynamic())
                {
                    ASSERT(field.isPostBase() == false);
                    if (field.index >= base)
                    {
                        field.index -= base;
                        field.code = field.isNameIndexed() ? HEADER_NAME_INDEXED_POSTBASE : HEADER_INDEXED_POSTBASE;
                    }
                    else if (drainPoint > 0 && INT32(field.index) < drainPoint)
                    {
                        field.code = field.code == HEADER_INDEXED_DYNAMIC ? HEADER_INDEXED_POSTBASE : HEADER_NAME_INDEXED_POSTBASE;
                        field.index = encoder.dynamicTable.writeOffset - base;
                        auto command = encoder.dynamicTable.duplicateField(field);
                        encoder.commandStream.append(command);
                    }
                    else
                    {
                        field.index = base - field.index - 1;
                    }
                }
                headerStream.append(field);
            }

            template <typename STREAM>
            void formatField(STREAM& frameByteStream, const QPFIELD& field)
            {
                BIT_BUILDER<STREAM> frameStream{ frameByteStream };

                frameStream.writeCode(field.code);
                if (field.isIndexed())
                {
                    frameStream.writeInteger(field.index);
                    if (field.isNameIndexed())
                    {
                        frameStream.writeString(field.value);
                    }
                }
                else
                {
                    frameStream.writeString(field.name);
                    frameStream.writeString(field.value);
                }
            }

            template <typename STREAM>
            void formatSection(STREAM& outStream)
            {
                BIT_BUILDER<STREAM> encodeStream{ outStream };
                encodeStream.writeByte(encoder.dynamicTable.getInsertCount());
                encodeStream.writeBitFlag(1);
                encodeStream.writeInteger(encoder.dynamicTable.getInsertCount() - base);
                for (auto&& field : headerStream.toBuffer())
                {
                    formatField(outStream, field);
                }
            }
        };

        auto&& newSection(UINT32 fieldCount = 16)
        {
            auto&& section = StackAlloc<SECTION_STATE, SCHEDULER_STACK>(*this);
            section.init(fieldCount);
            return section;
        }

        UINT32 beginEncode()
        {
            return dynamicTable.writeOffset;
        }
        
        DATASTREAM<QPFIELD, SCHEDULER_STACK> commandStream;

        QPFIELD encodeField(const QPFIELD& fieldIn)
        {
            QPFIELD field = fieldIn;
            if (field.isNotIndexed() || field.isNameIndexed())
            {
                auto match = dynamicTable.find(field.name, field.value);
                if (match != -1)
                {
                    field.code = HEADER_INDEXED_DYNAMIC;
                    field.index = match;
                }
                else
                {
                    if (IS_NOT_COMPRESSED(field.name) == false)
                    {
                        auto command = dynamicTable.writeField(field);
                        commandStream.append(command);
                    }
                }
            }
            return field;
        }

        template <typename STREAM>
        void formatCommand(STREAM& encoderStream, const QPFIELD& command)
        {
            BIT_BUILDER<STREAM> outStream{ encoderStream };
            outStream.writeCode(command.code);
            if (command.code == ENCODE_DUPLICATE)
            {
                outStream.writeInteger(command.index);
            }
            else
            {
                if (command.code == ENCODE_INSERT_LITERAL_NAME)
                {
                    outStream.writeString(command.name);
                }
                else
                {
                    outStream.writeInteger(command.index);
                }
                outStream.writeString(command.value);
            }
        }

        template <typename STREAM>
        void formatCommands(STREAM& outStream)
        {
            auto commands = commandStream.toBuffer();
            if (commands)
            {
                outStream.beginStream(sendState);
                for (auto&& command : commands)
                {
                    formatCommand(outStream, command);
                }
                outStream.endStream();
            }
            commandStream.clear();
        }

        void sendSection(SECTION_STATE& section, BYTESTREAM& outStream)
        {
            BIT_BUILDER<BYTESTREAM> encodeStream{ outStream };
            encodeStream.writeByte(dynamicTable.getInsertCount());
            encodeStream.writeBitFlag(1);
            encodeStream.writeInteger(dynamicTable.getInsertCount() - section.base);

            section.formatSection(outStream);
        }
    };


    struct DECODER
    {
        STREAM_STATE recvState;
        STREAM_STATE sendState;

        DYNAMIC_TABLE table;

        void populateField(QPFIELD& recvField, UINT32 base)
        {
            if (recvField.isDynamic())
            {
                recvField.index = recvField.isPostBase() ? base + recvField.index + 1 : base - recvField.index;
                ASSERT(recvField.index < table.writeOffset);
                auto&& tableField = table.getField(recvField.index);
                recvField.name = tableField.name;
                recvField.value = tableField.value;
            }
            else
            {
                recvField.name = QPACK_STATIC.at(recvField.index).name;
                recvField.value = QPACK_STATIC.at(recvField.index).value;
            }
        }

        auto parseHeader(BUFFER frame)
        {
            DATASTREAM<QPFIELD, SCHEDULER_STACK> headerStream;
            headerStream.reserve(16);
            BIT_READER frameReader{ frame };
            auto insertCount = frameReader.decodeInteger();
            if (insertCount <= table.writeOffset)
            {
                auto sign = frameReader.readBitFlag();
                ASSERT(sign);
                auto baseOffset = frameReader.decodeInteger();
                auto base = sign ? insertCount - baseOffset - 1 : insertCount + baseOffset;

                while (frameReader)
                {
                    QPFIELD recvField;
                    recvField.code = frameReader.matchHeaderCode();
                    if (recvField.isIndexed())
                    {
                        recvField.index = frameReader.decodeInteger();
                        populateField(recvField, base);
                    }
                    if (recvField.isNameIndexed())
                    {
                        recvField.value = frameReader.readValue(recvField.name);
                    }
                    else if (recvField.isNotIndexed())
                    {
                        recvField.name = frameReader.readName();
                        recvField.value = frameReader.readValue(recvField.name);
                    }
                    headerStream.append(recvField);
                }
            }
            return headerStream.toBuffer();
        }

        void parseCommands(BUFFER& frame) // from peer encoder
        {
            BIT_READER frameReader{ frame };

            while (frameReader)
            {
                auto successful = false;
                auto restorePoint = frame.mark();
                QPFIELD command;
                do
                {
                    if (frameReader.matchCode(ENCODE_SET_TABLE_CAPACITY))
                    {
                        command.code = ENCODE_SET_TABLE_CAPACITY;
                        command.index = frameReader.decodeInteger();
                        if (command.index == -1) break;
                    }
                    else if (frameReader.matchCode(ENCODE_INSERT_NAME_INDEX))
                    {
                        auto isStatic = frameReader.readBitFlag();
                        command.code = isStatic ? ENCODE_INSERT_NAME_INDEX_STATIC : ENCODE_INSERT_NAME_INDEX_DYNAMIC;
                        command.index = frameReader.decodeInteger();
                        if (command.index == -1) break;

                        command.value = frameReader.readName();
                        if (!command.value) break;
                    }
                    else if (frameReader.matchCode(ENCODE_INSERT_LITERAL_NAME))
                    {
                        command.code = ENCODE_INSERT_LITERAL_NAME;
                        command.name = frameReader.readName();
                        if (!command.name) break;

                        command.value = frameReader.readName();
                        if (!command.value) break;
                    }
                    else if (frameReader.matchCode(ENCODE_DUPLICATE))
                    {
                        command.code = ENCODE_DUPLICATE;
                        command.index = frameReader.decodeInteger();
                        if (command.index == -1) break;
                    }
                    else 
                    {
                        DBGBREAK();
                        break;
                    }
                    table.writeCommand(command);
                    successful = true;
                } while (false);
                if (!successful)
                {
                    frame.restore(restorePoint);
                    break;
                }
            }
        }
    };

    template <typename STREAM>
    void encodeHuffmanString(STREAM&& outStream, BUFFER text)
    {
        BITBUILDER bitStream{ outStream };
        while (text)
        {
            auto inByte = text.readByte();
            auto&& entry = huff_sym_table[inByte];

            bitStream.writeBits(entry.code, entry.nbits);
        }
    }

    static BUFFER decodeHuffmanString(BUFFER huffmanData)
    {
        DBGBREAK(); // debug!
        auto&& outStream = ByteStream(huffmanData.length());

        BIT_READER inStream{ huffmanData };
        UINT8 state = 0;
        while (inStream)
        {
            auto in4Bit = inStream.readBits(4);
            auto&& map = huff_decode_table[state];
            auto&& entry = map[in4Bit];

            state = entry.state;
            if (entry.flags & NGHTTP2_HUFF_SYM)
            {
                outStream.writeByte(entry.sym);
            }
            ASSERT((entry.flags & NGHTTP2_HUFF_INVALID_CHARS) == 0);
        }

        return outStream.toBuffer();
    }
};
using QPREADER = STREAM_READER<const QPFIELD>;
QPFIELD FindField(QPREADER section, TOKEN name)
{
    QPFIELD match;
    for (auto&& field : section)
    {
        if (field.name == name)
        {
            match = field;
            break;
        }
    }
    return match;
}

using FIELD_SECTION = QPACK::ENCODER::SECTION_STATE;
