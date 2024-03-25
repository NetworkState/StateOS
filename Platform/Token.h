
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

#include "Types.h"	
using TOKEN_BUFFER = STREAM_READER<const TOKEN>;

template <typename STACK>
struct LABEL_STORE
{
    constexpr static UINT64 DICT_INDEX_MASK = BITFIELD(10, 32);
    constexpr static UINT32 MAX_LABEL_DICT = 1024;

    struct UPDATE_LOG
    {
        LABEL_STORE& labelStore;

        TOKEN startTimestamp;
        DATASTREAM<TOKEN, STACK> newTokens;
        UINT64 bytesAdded;

        void onCreate(TOKEN nameToken, BUFFER nameText)
        {
            newTokens.append(nameToken);
            bytesAdded += nameText.length();
        }

        UINT64 logSize()
        {
            return bytesAdded + newTokens.count() * 8;
        }

        BUFFER exportLog(BYTESTREAM& logStream)
        {
            auto start = logStream.mark();
            auto tokens = newTokens.toBuffer();
            for (auto&& token: tokens)
            {
                logStream.writeVInt(token.toUInt64());
                auto nameText = get(token);
                logStream.writeVInt(nameText.length());
                logStream.writeBytes(nameText);
            }
            return logStream.toBuffer(start);
        }

        void reset()
        {
            startTimestamp = Null;
        }

        void start()
        {
            startTimestamp = Tokens.createTiemstamp();
            newTokens.clear();
        }

        void importLog(BUFFER logData)
        {
            while (logData)
            {
                auto number = logData.readVInt();
                auto nameToken = TOKEN(number);

                ASSERT(logData);
                auto length = (UINT32)logData.readVInt();

                ASSERT(logData.length() >= length);
                auto nameText = logData.readBytes(length);

                auto dictIndex = nameToken.getField(DICT_INDEX_MASK);
                auto newToken = labelStore.create(dictIndex, nameText);
                ASSERT(nameToken == newToken);
            }
        }

        UPDATE_LOG(LABEL_STORE& labelStore) : labelStore(labelStore) {}
    };

    using LABEL_DICT = AVX3_DICT<STACK, 4, 64>;
    DATASTREAM<LABEL_DICT*, STACK> labelDictStream;

    UPDATE_LOG updateLog;

    void init()
    {
        labelDictStream.commit(MAX_LABEL_DICT, nullptr);
    }

    LABEL_DICT& getDict(UINT32 index)
    {
        ASSERT(index < MAX_LABEL_DICT);
        if (labelDictStream.at(index) == nullptr)
        {
            auto&& newDict = StackAlloc<LABEL_DICT, STACK>();
            newDict.init();
            labelDictStream.at(index) = &newDict;
        }
        return *labelDictStream.at(index);
    }

    TOKEN toLabelToken(UINT64 nameIndex, TOKENFLAGS tokenFlags, UINT32 dictIndex)
    {
        auto labelToken = TOKEN(TOKEN_LABEL, tokenFlags, nameIndex);
        labelToken.setField(DICT_INDEX_MASK, dictIndex);
        return labelToken;
    }

    TOKEN toNameToken(TOKEN labelToken)
    {
        return labelToken.toToken32();
    }

    TOKEN create(UINT32 dictIndex, BUFFER labelText)
    {
        ASSERT(labelText);

        CACHE_LINE avxLine;
        auto&& dict = getDict(dictIndex);
        UINT32 nameIndex;
        TOKENFLAGS tokenFlags = TOKEN_NOFLAGS;
        if (auto parsedName = Dict.ParseName(labelText, avxLine))
        {
            nameIndex = dict.writeName(parsedName);
        }
        else
        {
            nameIndex = dict.longnameDict.writeName(labelText);
            tokenFlags = TF_LONGNAME;
        }
        auto token = toLabelToken(nameIndex, tokenFlags, dictIndex);;
        updateLog.onCreate(token, labelText);
        return token;
    }

    TOKEN find(UINT32 dictIndex, BUFFER labelText)
    {
        ASSERT(labelText);

        CACHE_LINE avxLine;
        auto&& dict = getDict(dictIndex);
        UINT32 nameIndex;
        TOKENFLAGS tokenFlags = TOKEN_NOFLAGS;
        if (auto parsedName = Dict.ParseName(labelText, avxLine))
        {
            nameIndex = dict.matchName(parsedName);
        }
        else
        {
            nameIndex = dict.longnameDict.findName(labelText);
            tokenFlags = TF_LONGNAME;

        }
        return nameIndex ? toLabelToken(nameIndex, tokenFlags, dictIndex) : TOKEN();
    }

    BUFFER get(TOKEN token)
    {
        UINT32 dictIndex = (UINT32)token.getField(DICT_INDEX_MASK);
        auto&& dict = getDict(dictIndex);

        auto nameToken = toNameToken(token);
        return Dict.getName(dict, nameToken);
    }

    LABEL_STORE() : updateLog(*this) {}
};

template <typename STACK, TOKENTYPE IDTYPE>
struct ID_TOKEN
{
    constexpr static UINT32 ID_ENTRIES = 256;
    constexpr static UINT32 ID_STREAMS = 256;

    using ID_STREAM = DATASTREAM<U128, STACK>;
    ID_STREAM idStreams[ID_STREAMS];

    constexpr static auto BYTE13_MASK = BITFIELD(8, 20);
    constexpr static auto BYTE14_MASK = BITFIELD(8, 12);
    constexpr static auto BUCKET_MASK = BITFIELD(8, 4);
    constexpr static auto INDEX_MASK = BITFIELD(8, 28);

    constexpr static TOKEN CREATE_ID(const U128& id, UINT8 bucket)
    {
        return TOKEN(_pdep_u64(id.u8[13], BYTE13_MASK) | _pdep_u64(id.u8[14], BYTE14_MASK) 
            | _pdep_u64(bucket, BUCKET_MASK) | _pdep_u64(id.u8[15], INDEX_MASK) | UINT64(IDTYPE));
    }

    ID_TOKEN() {}

    void init()
    {
        for (UINT32 i = 0; i < ID_STREAMS; i++)
        {
            idStreams[i].reserve(ID_ENTRIES);
        }
    }

    bool compareID(const U128& first, const U128& second) const
    {
        return RtlCompareMemory(first.u8, second.u8, 15) == 15;
    }

    TOKEN findID(const U128& id) const
    {
        TOKEN token = Null;

        auto bucketIndex = id.u8[15];
        auto&& idStream = idStreams[bucketIndex].toBuffer();

        for (UINT32 i = 0, j = idStream.length(); i < j; i++)
        {
            auto&& idFound = idStream.at(i);
            if (idFound.u8[14] == id.u8[14] && idFound.u8[13] == id.u8[13])
            {
                if (compareID(idFound, id))
                {
                    token = CREATE_ID(idFound, bucketIndex);
                    break;
                }
            }
        }

        return token;
    }

    TOKEN createID(const U128& id)
    {
        auto token = findID(id);
        if (!token)
        {
            auto bucketIndex = id.u8[15];
            auto&& idStream = idStreams[bucketIndex].toBuffer();

            UINT8 index = 0;
            for (UINT32 i = 0, j = idStream.length(); i < j; i++)
            {
                auto&& idFound = idStream.at(i);
                if (idFound.u8[14] == id.u8[14] && idFound.u8[13] == id.u8[13])
                {
                    index++;
                }
            }

            auto&& newId = idStreams[bucketIndex].append(id);
            newId.u8[15] = index;

            token = CREATE_ID(newId, bucketIndex);
        }
        return token;
    }

    U128 getID(const TOKEN token) const
    {
        U128 result;
        auto tokenValue = token.toUInt64();

        auto bucket = UINT8(_pext_u64(tokenValue, BUCKET_MASK));
        UINT8 b14 = UINT8(_pext_u64(tokenValue, BYTE14_MASK));
        UINT8 b13 = UINT8(_pext_u64(tokenValue, BYTE13_MASK));
        UINT8 index = UINT8(_pext_u64(tokenValue, INDEX_MASK));

        auto&& idStream = idStreams[bucket].toBuffer();

        for (UINT32 i = 0, j = idStream.length(); i < j; i++)
        {
            auto&& idFound = idStream.at(i);
            if (idFound.u8[14] == b14 && idFound.u8[13] == b13 && idFound.u8[15] == index)
            {
                result = idFound;
                break;
            }
        }
        ASSERT(result.isNotZero());
        if (result.isNotZero())
            result.u8[15] = bucket;

        return result;
    }
};

template <typename STACK>
struct TOKEN_OPS
{
    TOKEN createName(BUFFER string)
    {
        return Dict.CreateName<STACK>(string);
    }

    U128 getID(TOKEN token)
    {
        return STACK::GetCurrent().idTokens.getID(token);
    }

    TOKEN createID(BUFFER idString)
    {
        U128 id;
        ASSERT(String.parseID(idString, id));
        return STACK::GetCurrent().idTokens.createID(id);
    }

    TOKEN findID(BUFFER data)
    {
        auto&& id = data.readU128();
        return STACK::GetCurrent().idTokens.findID(id);
    }

    TOKEN createID(const U128& id)
    {
        return STACK::GetCurrent().idTokens.createID(id);
    }

    TOKEN generateID()
    {
        U128 idBytes;
        Random.getBytes(idBytes.u8);

        return createID(idBytes);
    }

    TOKEN createObject(U128 id)
    {
        STACK::GetCurrent().objectTokens.createID(id);
    }

    TOKEN findObject(U128 id)
    {
        return STACK::GetCurrent().objectTokens.findID(id);
    }

    U128 getObject(TOKEN token)
    {
        ASSERT(token.isObject());
        return STACK::GetCurrent().objectTokens.getID(token);
    }

    constexpr static UINT64 MAX_NUMBER = BITFIELD(48, 0);

    TOKEN createNumber(UINT64 input, TOKENTYPE type = TOKEN_NUMBER)
    {
        ASSERT(input < MAX_NUMBER);
        return TOKEN(type, input);
    }

    UINT64 getNumber(TOKEN token)
    {
        return token.getValue64();
    }

    TOKEN createDateTime(UINT64 dateTime) // in seconds
    {
        auto dateTimeOrigin = STACK::GetCurrent().dateTimeOrigin;
        return createNumber(dateTime - dateTimeOrigin, TOKEN_DATE);
    }

    INT64 getDateTime(TOKEN token)
    {
        ASSERT(token.isDate());
        return getNumber(token) + STACK::GetCurrent().dateTimeOrigin;
    }

    TOKEN currentTime()
    {
        return createDateTime(GetTimeS());
    }

    TOKEN createTimestamp()
    {
        return createNumber(GetTimestamp(), TOKEN_TIMESTAMP);
    }

    UINT64 getTimestamp(TOKEN token)
    {
        ASSERT(token.getType() == TOKEN_TIMESTAMP);
        auto timestamp = getNumber(token);
        return timestamp;
    }

    BUFFER toString(TOKEN token)
    {
        BUFFER result;
        if (token.isName())
        {
            result = NameToString(token);
        }
        else if (token.isNumber())
        {
            auto number = Tokens.getNumber(token);
            result = ByteStream(64).writeString(number);
        }
        else if (token.isDate())
        {
            ASSERT(token.getStackType() == SESSION_STACK::STACKTYPE);
            result = String.formatHttpDate(ByteStream(64), getDateTime(token) * TICKS_PER_SECOND);

        }
        return result;
    }

    TOKEN createLabel(UINT8 dictIndex, BUFFER labelText)
    {
        auto&& labelStore = STACK::GetCurrent().labelStore;
        return labelStore.create(dictIndex, labelText);
    }

    TOKEN findLabel(UINT8 dictIndex, BUFFER labelText)
    {
        auto&& labelStore = STACK::GetCurrent().labelStore;
        return labelStore.find(dictIndex, labelText);
    }

    BUFFER getLabel(TOKEN token)
    {
        auto&& labelStore = STACK::GetCurrent().labelStore;
        return labelStore.get(token);
    }
};

template <typename STACK>
TOKEN_OPS<STACK>& TokenOps();

