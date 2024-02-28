
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
#include "Types.h"

constexpr static UINT8 CC_JSON_WHITESPACE = 0x10;
constexpr static UINT8 CC_JSON_NAME = 0x01;
constexpr static UINT8 CC_JSON_SEPARATOR = 0x02;
constexpr static UINT8 CC_JSON_OPERATOR = 0x04;
constexpr static UINT8 CC_JSON_QUOTE = 0x08;
constexpr static UINT8 CC_JSON_END_QUOTE = 0x20;
constexpr static UINT8 CC_JSON_NON_QUOTE = 0x40;
constexpr static UINT8 CC_JSON_UNKNOWN = 0x80;

constexpr static UINT8 JSON_CS_NAME[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ$_";
constexpr static UINT8 JSON_CS_OPERATOR[] = "<>=!+-%/*&^~?|";
constexpr static UINT8 JSON_CS_SEPARATOR[] = "\\{}[]().,;:'";
constexpr static UINT8 JSON_CS_QUOTE[] = "\"";
constexpr static UINT8 JSON_CS_WHITESPACE[] = "\r\n\t ";

using CACHE_LINE = UINT8[64];

using CACHE_LINE_BUFFER = STREAM_READER<const CACHE_LINE>;
constexpr UINT8 CACHELINE_QWORDS = sizeof(CACHE_LINE) / sizeof(UINT64);

struct CC_JSON_MAP
{
    UINT8 data[128] = { 0 };
    constexpr CC_JSON_MAP()
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = CC_JSON_UNKNOWN;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JSON_CS_NAME); i++)
        {
            data[JSON_CS_NAME[i]] = CC_JSON_NAME;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JSON_CS_OPERATOR); i++)
        {
            data[JSON_CS_OPERATOR[i]] = CC_JSON_OPERATOR;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JSON_CS_SEPARATOR); i++)
        {
            data[JSON_CS_SEPARATOR[i]] = CC_JSON_SEPARATOR;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JSON_CS_QUOTE); i++)
        {
            data[JSON_CS_QUOTE[i]] = CC_JSON_QUOTE;
        }
        for (UINT8 i = 0; i < ARRAYSIZE(JSON_CS_WHITESPACE); i++)
        {
            data[JSON_CS_WHITESPACE[i]] = CC_JSON_WHITESPACE;
        }
    }
};
constexpr static CC_JSON_MAP JSON_MAP;

struct CC_JSON_QUOTE_MAP
{
    UINT8 data[128] = { 0 };
    constexpr CC_JSON_QUOTE_MAP()
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = CC_JSON_NON_QUOTE;
        }
        data['"'] = CC_JSON_END_QUOTE;
        data['\\'] = CC_JSON_END_QUOTE;
    }
};
constexpr static CC_JSON_QUOTE_MAP JSON_QUOTE_MAP;

struct CC_JSON_ESCAPE_SEQ
{
    UINT8 data[128] = { 0 };
    constexpr CC_JSON_ESCAPE_SEQ()
    {
        for (UINT8 i = 0; i < 128; i++)
        {
            data[i] = i;
        }
        data['n'] = '\n';
        data['r'] = '\r';
        data['t'] = '\t';
        data['b'] = '\b';
        data['f'] = '\f';
        data['\\'] = '\\';
        data['"'] = '"';
    }
};
constexpr static CC_JSON_ESCAPE_SEQ CC_JSON_ESCAPE;

struct M512_PERMUTE
{
    UINT8 u8[64];
    constexpr M512_PERMUTE(UINT8 start = 0)
    {
        for (UINT32 i = 0; i < 64; i++)
        {
            u8[i] = UINT8(i + start);
        }
    }

    inline __m512i get(UINT64 mask = -1, UINT8 origin = 0) const
    {
        return _mm512_maskz_expandloadu_epi8(mask, u8 + origin);
    }
};
extern "C" M512_PERMUTE PERMUTE0;

inline UINT8 POPCNT(UINT64 x) { return (UINT8)_mm_popcnt_u64(x); }
inline UINT8 POPCNT(UINT32 x) { return (UINT8)_mm_popcnt_u32(x); }
inline UINT8 POPCNT(UINT16 x) { return (UINT8)_mm_popcnt_u32(x); }
constexpr static UINT32 ZREG_BYTES = 64;

struct M512_REG
{
    __m512i reg;
    __mmask64 mask = 0;

    M512_REG()
    {
        reg = _mm512_set1_epi64(0);
    }
    inline UINT32 count() const { return UINT32(POPCNT(mask)); }

    void loadText(BUFFER string)
    {
        auto toRead = min(string.length(), ZREG_BYTES);
        reg = _mm512_maskz_loadu_epi8(MASK(toRead), string.data());
        mask = MASK(toRead);
    }

    UINT64 shiftText(BUFFER text, UINT32 shift)
    {
        auto perm = _mm512_add_epi8(_mm512_loadu_epi8(PERMUTE0.u8), _mm512_set1_epi8(shift));
        M512_REG nextReg;
        nextReg.loadText(text);

        ASSERT(POPCNT(mask) >= (64 - shift));
        reg = _mm512_permutex2var_epi8(reg, perm, nextReg.reg);
        return min(64, (64 - shift) + nextReg.count());
    }

    __m512i permuteTo(const UINT8(&map)[128])
    {
        return _mm512_maskz_permutex2var_epi8(mask, _mm512_loadu_epi8(map), reg, _mm512_loadu_epi8(map + 64));
    }

    void permute(const UINT8(&map)[128])
    {
        reg = _mm512_maskz_permutex2var_epi8(mask, _mm512_loadu_epi8(map), reg, _mm512_loadu_epi8(map + 64));
    }

    void shift(UINT64 offset)
    {
        mask <<= offset;
        reg = _mm512_maskz_permutexvar_epi8(mask, PERMUTE0.get(mask, (UINT8)offset), reg);
    }

    __m512i shiftTo(UINT64 offset)
    {
        auto newMask = mask << offset;
        return _mm512_maskz_permutexvar_epi8(newMask, PERMUTE0.get(newMask, (UINT8)offset), reg);
    }

    void store(PVOID address)
    {
        _mm512_storeu_epi8(address, reg);
    }
    explicit operator bool() const { return mask != 0; }
};

struct PERM_REVERSE_ST
{
    UINT8 data[64];
    constexpr PERM_REVERSE_ST()
    {
        for (UINT32 i = 0; i < 64; i++)
        {
            data[63 - i] = i;
        }
    }

    inline __m512i get(UINT64 mask) const
    {
        auto reg = _mm512_loadu_epi8(data);
        return _mm512_sub_epi8(reg, _mm512_set1_epi8(64 - UINT8(_mm_popcnt_u64(mask))));
    }
};
constexpr PERM_REVERSE_ST PERM_REVERSE;

struct ASCII_TOUPPER_ST
{
    UINT8 data[128];
    constexpr ASCII_TOUPPER_ST()
    {
        for (UINT32 i = 0; i < 128; i++)
        {
            data[i] = ToUpper(i);
        }
    }
};
constexpr ASCII_TOUPPER_ST ASCII_TOUPPER;

struct ASCII_TOLOWER_ST
{
    UINT8 data[128];
    constexpr ASCII_TOLOWER_ST()
    {
        for (UINT32 i = 0; i < 128; i++)
        {
            data[i] = ToLower(i);
        }
    }
};
extern "C"  ASCII_TOLOWER_ST ASCII_TOLOWER;
struct ASCII_VOWEL_ST
{
    UINT8 data[128] = { 0 };
    constexpr ASCII_VOWEL_ST()
    {
        data['a'] = 1;
        data['e'] = 1;
        data['i'] = 1;
        data['o'] = 1;
        data['u'] = 1;
    }
};
extern "C" ASCII_VOWEL_ST ASCII_VOWEL;

struct HEXNUMBER_ST
{
    UINT8 data[128];
    constexpr HEXNUMBER_ST()
    {
        for (UINT32 i = 0; i < 128; i++)
        {
            data[i] = 0xFF;
        }

        for (UINT8 ch = '0'; ch <= '9'; ch++)
        {
            data[ch] = ch - '0';
        }

        for (UINT8 ch = 'A'; ch <= 'F'; ch++)
        {
            data[ch] = 10 + (ch - 'A');
        }

        for (UINT8 ch = 'a'; ch <= 'f'; ch++)
        {
            data[ch] = 10 + (ch - 'a');
        }
    }
};
constexpr HEXNUMBER_ST HEX_TO_NUMBER;

constexpr UINT64 POW(UINT8 base, UINT8 power)
{
    UINT64 value = 1;
    for (UINT8 i = 0; i < power; i++)
    {
        value = value * base;
    }
    return value;
}

struct DECIMAL_MULT_ST
{
    UINT32 data[16];
    constexpr DECIMAL_MULT_ST()
    {
        for (UINT32 i = 0; i < 8; i++)
        {
            data[i] = UINT32(POW(10, i));
            data[i + 8] = UINT32(POW(10, i));
        }
    }

    inline __m512i get() const
    {
        return _mm512_loadu_epi32(data);
    }
};
constexpr DECIMAL_MULT_ST DECIMAL_MULT;

struct DECIMAL_ORDER_MAP_ST
{
    UINT32 data[16];
    constexpr DECIMAL_ORDER_MAP_ST()
    {
        data[15] = data[7] = 1;
        for (UINT32 i = 0; i <= 6; i++)
        {
            data[7 - i - 1] = data[7 - i] * 10;
            data[15 - i - 1] = data[15 - i] * 10;
        }
    }
};
constexpr DECIMAL_ORDER_MAP_ST DECIMAL_ORDER_MAP;

struct HEX_ORDER_MAP_ST
{
    UINT32 data[16];
    constexpr HEX_ORDER_MAP_ST()
    {
        data[7] = data[15] = 1;
        for (UINT32 i = 0; i <= 6; i++)
        {
            data[7 - i - 1] = data[7 - i] * 16;
            data[15 - i - 1] = data[15 - i] * 16;
        }
    }
};
constexpr HEX_ORDER_MAP_ST HEX_ORDER_MAP;

struct HEX_MULT_ST
{
    UINT32 data[16];
    constexpr HEX_MULT_ST()
    {
        for (UINT32 i = 0; i < 8; i++)
        {
            data[i] = UINT32(POW(16, i));
            data[i + 8] = UINT32(POW(16, i));
        }
    }

    inline __m512i get() const
    {
        return _mm512_loadu_epi32(data);
    }
};
constexpr HEX_MULT_ST HEX_MULT;

constexpr UINT8 INLINE_ALPHA_UPPER[] = "SCPAMBDRLFEHGIOTXYZVWKUNJQ";
constexpr UINT8 INLINE_ALPHA_LOWER[] = "scpambdrlfehgiotxyzvwkunjq";
constexpr UINT8 INLINE_NUMBERS[] = "0123456789";
constexpr UINT8 INLINE_ASCII_SYMBOLS[] = "-!'$%()*+,./:;=?@&<>#\"";
constexpr UINT8 INLINE_SPACE[] = "_\n\r\t ";

struct ASCII_INLINE_MAP
{
    UINT8 data[128]{ 0 };
    UINT8 r_data[128]{ 0 };
    constexpr ASCII_INLINE_MAP()
    {
        UINT8 index = 1;
        for (UINT32 i = 0; i < ARRAYSIZE(INLINE_ALPHA_LOWER) - 1; i++)
        {
            data[INLINE_ALPHA_UPPER[i]] = index;
            data[INLINE_ALPHA_LOWER[i]] = index;
            r_data[index] = INLINE_ALPHA_LOWER[i];
            index++;
        }
        for (UINT32 i = 0; i < ARRAYSIZE(INLINE_NUMBERS) - 1; i++)
        {
            data[INLINE_NUMBERS[i]] = index;
            r_data[index] = INLINE_NUMBERS[i];
            index++;
        }
        for (UINT32 i = 0; i < ARRAYSIZE(INLINE_SPACE) - 1; i++)
        {
            data[INLINE_SPACE[i]] = index;
            r_data[index] = INLINE_SPACE[i];
            index++;
        }
        for (UINT32 i = 0; i < ARRAYSIZE(INLINE_ASCII_SYMBOLS) - 1; i++)
        {
            data[INLINE_ASCII_SYMBOLS[i]] = index;
            r_data[index] = INLINE_ASCII_SYMBOLS[i];
            index++;
        }
    }
};
constexpr ASCII_INLINE_MAP ASCII_INLINE;

struct CC_MAP
{
    UINT8 data[128]{ 0 };
    template <UINT32 SZ>
    constexpr CC_MAP(const char (&map)[SZ])
    {
        for (UINT32 i = 0; i < SZ; i++)
        {
            data[map[i]] = 1;
        }
    }

    CC_MAP(const BUFFER map)
    {
        for (UINT32 i = 0; i < map.length(); i++)
        {
            data[map.at(i)] = map.at(i);
        }
    }
    __mmask64 match(const M512_REG& text) const
    {
        auto matchReg = _mm512_maskz_permutex2var_epi8(text.mask, _mm512_loadu_epi8(data), text.reg, _mm512_loadu_epi8(data + 64));
        auto matchMask = _mm512_mask_testn_epi8_mask(text.mask, matchReg, matchReg);
        return MASK(_tzcnt_u64(matchMask));
    }
};

constexpr CC_MAP CC_ALPHANUMERIC = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
constexpr CC_MAP CC_NUMERIC = "0123456789";
constexpr CC_MAP CC_HEXNUMBER = "0123456789abcdefABCDEF";
constexpr CC_MAP CC_VOWEL = "aeiou";
constexpr CC_MAP CC_WHITESPACE = " \t\r\n";

inline __m512i permute(const __m512i& text, const UINT64 mask, const UINT8(&map)[128])
{
    return _mm512_maskz_permutex2var_epi8(mask, _mm512_loadu_epi8(map), text, _mm512_loadu_epi8(map + 64));
}

inline UINT32 loadRegister(BUFFER string, __m512i& reg)
{
    auto toRead = min(string.length(), ZREG_BYTES);
    reg = _mm512_maskz_loadu_epi8(MASK(toRead), string.data());
    return toRead;
}

inline __m512i shiftReg(const __m512i& reg, const UINT8 shift, UINT64 mask = -1)
{
    return _mm512_maskz_compress_epi8(mask << shift, reg);
}

inline __m512i shiftOverReg(__m512i& reg, const UINT8 shift, UINT64 mask = -1)
{
    mask <<= shift;
    auto perm = PERMUTE0.get(mask, 0);
    return _mm512_mask_permutexvar_epi8(reg, mask, perm, reg);
}

inline UINT32 shiftText(BUFFER text, __m512i& textReg, UINT32 shift = 64)
{
    auto perm = _mm512_add_epi8(_mm512_loadu_epi8(PERMUTE0.u8), _mm512_set1_epi8(shift));
    __m512i nextReg;
    auto count = loadRegister(text, nextReg);

    textReg = _mm512_permutex2var_epi8(textReg, perm, nextReg);
    return (64 - shift) + count;
}

constexpr UINT8 DICT_LANECOUNT(UINT32 length)
{
    auto laneCount = UINT8(ROUNDTO(length * 6, 8) / 8);
    laneCount = UINT8(ROUNDTO(laneCount + 1, 4) / 4);
    return laneCount;
}

template <typename STACK>
struct LONGNAME_DICT
{
    struct NAME_INDEX
    {
        UINT32 prefix;
        UINT32 token;
    };

    DATASTREAM<BYTESTREAM, STACK> bucketStream;
    DATASTREAM<NAME_INDEX, STACK, 64, 128> indexStream;

    void init()
    {
        indexStream.reserve(64);
    }

    constexpr static UINT32 TOKEN_BUCKET_MASK = BITFIELD32(3, 0);
    constexpr static UINT32 TOKEN_OFFSET_MASK = BITFIELD32(17, 3);

    UINT32 makeName(UINT32 bucket, UINT32 offset)
    {
        return _pdep_u32(bucket, TOKEN_BUCKET_MASK) | _pdep_u32(offset, TOKEN_OFFSET_MASK);
    }

    BUFFER getName(UINT32 nameIndex)
    {
        auto bucket = _pext_u32(nameIndex, TOKEN_BUCKET_MASK);
        auto&& nameStream = bucketStream.at(bucket).toBuffer();
        nameStream.shift(_pext_u32(nameIndex, TOKEN_OFFSET_MASK));

        auto length = (UINT32)nameStream.readVInt();
        return nameStream.readBytes(length);
    }

    UINT32 writeName(UINT32 bucket, BYTESTREAM& nameStream, BUFFER nameString)
    {
        auto start = nameStream.mark();
        nameStream.writeVInt(nameString.length());
        nameStream.writeBytes(nameString);
        return makeName(bucket, start);
    }

    UINT32 getPrefix(BUFFER nameString)
    {
        auto a = _pdep_u32(nameString.length(), 0xFF);
        auto b = _pdep_u32(nameString.last(), 0xFF00);
        auto c = _pdep_u32(nameString.at(0), 0xFF0000);
        auto d = _pdep_u32(nameString.at(1), 0xFF000000);
        return a | b | c | d;
    }

    void writeIndex(UINT32 nameToken, BUFFER nameString)
    {
        indexStream.append(getPrefix(nameString), nameToken);
    }
    
    constexpr static UINT32 BUCKET_BYTES = 64 * 1024;
    BYTESTREAM& addBucket()
    {
        auto address = (PUINT8)StackAlloc<STACK>(BUCKET_BYTES);
        auto&& outStream = bucketStream.append(address, BUCKET_BYTES);
        outStream.beWriteU32(0xDEADBEEF);
        return outStream;
    }

    UINT32 writeName(BUFFER nameString)
    {
        UINT32 nameIndex = -1;
        auto nameLength = nameString.length();
        auto&& buckets = bucketStream.toRWBuffer();
        for (UINT32 i = 0; i < buckets.length(); i++)
        {
            auto&& nameStream = buckets.at(i);
            if (buckets[i].spaceLeft() > (nameLength + 2))
            {
                nameIndex = writeName(i, nameStream, nameString);
                break;
            }
        }

        if (nameIndex == -1)
        {
            auto&& nameStream = addBucket();
            nameIndex = writeName(bucketStream.count() - 1, nameStream, nameString);
        }
        
        writeIndex(nameIndex, nameString);
        return nameIndex;
    }

    bool matchName(UINT32 nameToken, BUFFER nameString)
    {
        auto matchString = getName(nameToken);
        return matchString == nameString;
    }

    UINT32 findName(BUFFER nameString)
    {
        auto prefix = UINT64(getPrefix(nameString));
        auto prefixReg = _mm512_set1_epi64(prefix);

        auto&& indexTable = indexStream.toRWBuffer();
        for (UINT32 i = 0; i < indexTable.length(); i += CACHELINE_QWORDS)
        {
            UINT8 loadMask = MASK8(min(indexTable.length(), CACHELINE_QWORDS));
            auto lineReg = _mm512_maskz_loadu_epi64(loadMask, &indexTable.at(i));
            auto maskReg = _mm512_maskz_and_epi64(loadMask, _mm512_set1_epi64(MAXUINT32), lineReg);

            auto matchMask = _mm512_mask_cmpeq_epi64_mask(loadMask, maskReg, prefixReg);

            while (matchMask)
            {
                auto&& nameIndex = indexTable.at(i + _tzcnt_u32(matchMask));
                if (matchName(nameIndex.token, nameString))
                    return nameIndex.token;

                matchMask = _blsr_u32(matchMask);
            }
        }
        return 0;
    }

    UINT32 createName(BUFFER nameString)
    {
        auto nameToken = findName(nameString);
        if (!nameToken)
            nameToken = writeName(nameString);

        return nameToken;
    }
};

template <typename STACK, UINT8 BUCKETS = 8, UINT8 BUCKETSIZE = 32, UINT8 STYLE32LINES = 32, UINT8 STYLE64LINES = 16>
struct AVX3_DICT
{
    using CACHE_LINE_STREAM = DATASTREAM<CACHE_LINE, STACK, 64, 64>;

    constexpr static UINT64 MOVE_3TO4_MASK = 0x7777777777777777;
    constexpr static UINT64 MOVE_4TO3_MASK = 0x7777777777777777;

    constexpr static UINT32 TOKEN_BUCKET_MASK = BITFIELD32(3, 0);
    constexpr static UINT32 TOKEN_LANE_MASK = BITFIELD32(4, 3);
    constexpr static UINT32 TOKEN_LINE_MASK = BITFIELD32(13, 7);
    constexpr static UINT32 TOKEN_STYLE_MASK = BITFIELD32(4, 20);

    constexpr static UINT32 STYLE_ALL_CAPS = 0x0F;
    constexpr static UINT32 STYLE_NAME = 0x01;

    CACHE_LINE_STREAM nameStream[BUCKETS];
    CACHE_LINE_STREAM style32Stream;
    CACHE_LINE_STREAM style64Stream;

    LONGNAME_DICT<STACK> longnameDict;

    void init(UINT32 bucketSize = BUCKETSIZE)
    {
        for (UINT32 i = 0; i < BUCKETS; i++)
        {
            nameStream[i].reserve(bucketSize);
            auto&& line = nameStream[i].append();
            *(UINT32*)line = _byteswap_ulong(0xDEADBEEF);
        }
        style32Stream.reserve(STYLE32LINES);
        style64Stream.reserve(STYLE64LINES);
        longnameDict.init();
    }

    inline UINT32 getBucket(UINT32 namePrefix)
    {
        auto index = _pext_u32(namePrefix, 0x3C000);
        return (index % BUCKETS);
    }

    inline UINT32 getBucket(BUFFER nameBytes)
    {
        return getBucket(nameBytes.readU32());
    }

    static UINT32 EXTEND_MASK(UINT32 mask, UINT8 bits) { return mask | (MASK32(bits) << _tzcnt_u32(mask)); }

    __m512i extractName(__m512i& laneReg, UINT16 mask, UINT32& prefix)
    {
        mask = (UINT16)_blsi_u32(mask);
        _mm512_mask_compressstoreu_epi32(&prefix, mask, laneReg);
        mask = EXTEND_MASK(mask, (UINT8)_pext_u32(prefix, 0xF0));
        return _mm512_maskz_compress_epi32(mask, laneReg);
    }
    
    static UINT32 makeName(UINT32 bucket, UINT32 line, UINT32 lane)
    {
        ASSERT(bucket < 8);
        ASSERT(lane < 16);
        ASSERT(line < 8000);

        return _pdep_u32(bucket, TOKEN_BUCKET_MASK) | _pdep_u32(line, TOKEN_LINE_MASK) | _pdep_u32(lane, TOKEN_LANE_MASK);
    }

    static void parseNameToken(UINT32 value, UINT32& bucket, UINT32& line, UINT32& offset)
    {
        bucket = _pext_u32(value, TOKEN_BUCKET_MASK);
        line = _pext_u32(value, TOKEN_LINE_MASK);
        offset = _pext_u32(value, TOKEN_LANE_MASK);
    }

    UINT32 matchName(BUFFER nameBytes)
    {
        auto namePrefix = *(UINT32*)nameBytes.data();
        auto namePrefixReg = _mm512_set1_epi32(namePrefix);
        auto bucket = getBucket(namePrefix);
        auto nameMask = MASK(nameBytes.length());
        auto nameReg = _mm512_maskz_loadu_epi8(nameMask, nameBytes.data());

        auto nameLines = nameStream[bucket].toRWBuffer();
        for (UINT32 i = 0; i < nameLines.length(); i++)
        {
            auto lineReg = _mm512_loadu_epi32(nameLines.at(i));
            auto matchMask = _mm512_cmpeq_epu32_mask(lineReg, namePrefixReg);
            while (matchMask)
            {
                auto matchReg = shiftReg(lineReg, UINT8(_tzcnt_u64(matchMask) * 4));
                if (_mm512_mask_cmpeq_epu8_mask(nameMask, nameReg, matchReg) == nameMask)
                {
                    return makeName(bucket, i, _tzcnt_u32(matchMask));
                }
                matchMask = _blsr_u32(matchMask);
            }
        }
        return 0;
    }

    UINT32 writeName(BUFFER nameBytes)
    {
        auto laneCount = DICT_LANECOUNT(nameBytes[0]); // >> 4;
        auto bucket = getBucket(nameBytes);
        auto&& nameLines = nameStream[bucket].toRWBuffer();
        for (UINT32 i = 0; i < nameLines.length(); i++)
        {
            auto laneReg = _mm512_loadu_epi8(nameLines[i]);
            UINT32 emptyLanes = _mm512_testn_epi32_mask(laneReg, laneReg);
            if (POPCNT(emptyLanes) >= laneCount)
            {
                RtlCopyMemory(nameLines[i] + _tzcnt_u32(emptyLanes) * 4, nameBytes.data(), laneCount * 4);
                return makeName(bucket, i, _tzcnt_u32(emptyLanes));
            }
        }
        auto&& newLine = nameStream[bucket].append();
        RtlCopyMemory(newLine, nameBytes.data(), laneCount * 4);
        return makeName(bucket, nameLines.length(), 0);
    }

    inline UINT64 extract64(__m512i& reg, UINT8 mask) // vmovq
    {
        UINT64 value;
        _mm512_mask_compressstoreu_epi64(&value, _blsi_u32(mask), reg);
        return value;
    }

    constexpr UINT64 U64_LOW32(UINT64 x) { return x & MAXUINT32; }
    constexpr UINT64 U64_HI32(UINT64 x) { return x >> 32; }

    UINT64 getStyle32(CACHE_LINE_BUFFER styleLines, UINT64 index)
    {
        ASSERT((index >> 32) == 0);
        auto patternReg = _mm512_set1_epi64(MAXUINT32);
        auto indexReg = _mm512_set1_epi64(index);
        for (UINT32 i = 0; i < styleLines.length(); i++)
        {
            auto styleReg = _mm512_loadu_epi64(styleLines[i]);
            auto matchReg = _mm512_and_epi64(styleReg, patternReg);
            if (auto mask = _mm512_cmpeq_epu64_mask(matchReg, indexReg))
            {
                return extract64(styleReg, mask) >> 32;
            }
        }
        return 0;
    }

    UINT32 findStyle(UINT32 nameToken, UINT64 styleBits)
    {
        UINT32 styleToken = 0;
        UINT64 pattern = UINT64(nameToken) | (styleBits << 32);
        auto patternReg = _mm512_set1_epi64(pattern);
        auto maskReg = _mm512_set1_epi64(MAXUINT64 ^ TOKEN_STYLE_MASK);
        auto style32Lines = style32Stream.toBuffer();
        auto style64Lines = style64Stream.toBuffer();
        for (UINT32 i = 0; i < style32Lines.length(); i++)
        {
            auto lineReg = _mm512_loadu_epi64(style32Lines[i]);
            if (_mm512_testn_epi64_mask(lineReg, lineReg)) break;

            auto matchReg = _mm512_and_epi64(lineReg, maskReg);
            if (auto match = _mm512_cmpeq_epi64_mask(matchReg, patternReg))
            {
                auto matchPrefix = extract64(lineReg, match);
                if (BYTECOUNT(styleBits) > 4)
                {
                    auto hiBits = styleBits >> 32;
                    if (getStyle32(style64Lines, matchPrefix & MAXUINT32) != hiBits)
                        continue;
                }
                styleToken = UINT32(matchPrefix);
                break;
            }
        }
        return styleToken;
    }

    void writeStyle32(CACHE_LINE_STREAM& lineStream, UINT64 value)
    {
        auto&& lines = lineStream.toRWBuffer();
        for (UINT32 i = 0; i < lines.length(); i++)
        {
            auto lineReg = _mm512_loadu_epi64(lines[i]);
            auto lineMask = _mm512_testn_epi64_mask(lineReg, lineReg);
            if (lineMask)
            {
                lineReg = _mm512_mask_set1_epi64(lineReg, (UINT8)_blsi_u32(lineMask), value);
                _mm512_storeu_epi64(lines[i], lineReg);
                return;
            }
        }

        auto&& newLine = lineStream.append();
        *(UINT64*)newLine = value;
    }

    UINT32 writeStyle(UINT32 nameToken, UINT64 styleBits)
    {
        UINT64 namePrefix = nameToken;
        ASSERT(_pext_u64(namePrefix, TOKEN_STYLE_MASK) == 0);

        if (styleBits == -1)
            return nameToken | _pdep_u32(STYLE_ALL_CAPS, TOKEN_STYLE_MASK);
        else if (styleBits == 1)
            return nameToken | _pdep_u32(STYLE_NAME, TOKEN_STYLE_MASK);
            
        auto stylePrefix = findStyle(nameToken, styleBits);
        if (stylePrefix)
        {
            ASSERT(0); // shouldn't happen
            return stylePrefix;
        }

        for (UINT64 index = 2; index < 15; index++)
        {
            auto nextPrefix = namePrefix | _pdep_u64(index, TOKEN_STYLE_MASK); // namePrefix | index << 4;
            if (getStyle32(style32Stream.toBuffer(), nextPrefix) == 0)
            {
                UINT64 value = (styleBits << 32) | nextPrefix;
                writeStyle32(style32Stream, value);
                if (styleBits = styleBits >> 32)
                {
                    value = (styleBits << 32) | nextPrefix;
                    writeStyle32(style64Stream, value);
                }
                stylePrefix = UINT32(nextPrefix);
                break;
            }
        }
        return stylePrefix;
    }

    UINT64 getStyle(UINT32 nameToken, BUFFER nameString)
    {
        UINT64 styleBits;
        auto styleIndex = _pext_u32(nameToken, TOKEN_STYLE_MASK);
        if (styleIndex == STYLE_ALL_CAPS)
        {
            styleBits = -1;
        }
        else if (styleIndex == STYLE_NAME)
        {
            styleBits = 1;
        }
        else
        {
            styleBits = getStyle32(style32Stream.toBuffer(), nameToken);
            if (nameString.length() > 32)
            {
                styleBits |= (getStyle32(style64Stream.toBuffer(), nameToken) << 32);
            }
        }
        return styleBits;
    }

    BUFFER getNameBytes(UINT32 nameToken)
    {
        UINT32 bucket, line, offset;
        parseNameToken(nameToken, bucket, line, offset);

        auto&& lines = nameStream[bucket].toRWBuffer();
        auto address = PUINT8(lines.at(line)) + offset * 4;

        return { address, UINT32(DICT_LANECOUNT(address[0])) * 4 };
    }

    UINT32 getNameLength(UINT32 nameToken)
    {
        UINT32 bucket, line, offset;
        parseNameToken(nameToken, bucket, line, offset);

        auto&& lines = nameStream[bucket].toRWBuffer();
        auto address = PUINT8(lines.at(line)) + offset * 4;
        return address[0];
    }
};

struct AVX3_STRING
{
    void toLower(RWBUFFER text)
    {
        auto toRead = min(text.length(), ZREG_BYTES);
        auto&& textReg = _mm512_maskz_loadu_epi8(MASK(toRead), text.data());
        auto textMask = MASK(toRead);
        textReg = permute(textReg, textMask, ASCII_TOLOWER.data);
        _mm512_mask_compressstoreu_epi8(text.data(), textMask, textReg);
    }

    UINT64 toNumber(BUFFER text, UINT8 base)
    {
        UINT64 number = -1;
        auto textMask = MASK(text.length());
        auto textReg = _mm512_maskz_loadu_epi8(textMask, text.data());
        textReg = permute(textReg, textMask, HEX_TO_NUMBER.data);
        if (_mm512_mask_cmplt_epu8_mask(textMask, textReg, _mm512_set1_epi8(base)))
        {
            auto numberMask = UINT16(textMask);
            auto numberReg = _mm512_maskz_cvtepu8_epi32(numberMask, _mm512_castsi512_si128(textReg));

            auto multiReg = _mm512_maskz_compress_epi32(ROR16(numberMask, POPCNT(numberMask)),
                _mm512_loadu_epi32(base == 10 ? DECIMAL_ORDER_MAP.data : HEX_ORDER_MAP.data));
            numberReg = _mm512_maskz_mullo_epi32(numberMask, numberReg, multiReg);

            auto maskLo = 0xFF00 >> (_lzcnt_u32(numberMask) - 16);
            UINT64 numberLo = _mm512_mask_reduce_add_epi32(maskLo, numberReg);
            UINT64 numberHi = _mm512_mask_reduce_add_epi32(maskLo ^ numberMask, numberReg);

            number = (numberHi * POW(base, 8)) + numberLo;
        }
        return number;
    }

    bool toNumber(BUFFER text, UINT64& number)
    {
        auto isNumber = false;
        number = -1;

        do
        {
            number = toNumber(text, 10);
            if (number != -1)
            {
                isNumber = true;
                break;
            }

            if (text.length() > 18)
                break;

            bool isNegative = false;
            if (text.peek() == '-')
            {
                isNegative = true;
                text.shift();
            }

            if (text.peek() == '+')
                text.shift();

            auto textMask = MASK(text.length());
            auto textReg = _mm512_maskz_loadu_epi8(textMask, text.data());
            textReg = permute(textReg, textMask, ASCII_TOLOWER.data);

            auto isHex = _mm512_mask_cmpeq_epu8_mask(3, textReg, _mm512_maskz_loadu_epi8(3, "0x")) == 3;
            if (isHex)
            {
                text.shift(2);
                number = toNumber(text, 16);
                isNumber = number != -1;
                break;
            }
        } while (false);
        return isNumber;
    }

    BUFFER splitString(BUFFER text, BUFFER inPattern)
    {
        BUFFER outText = text;
        ASSERT(inPattern.length() < 8);
        while (text)
        {
            auto pattern = inPattern;
            auto toRead = min(text.length(), ZREG_BYTES);
            auto textReg = _mm512_maskz_loadu_epi8(MASK(toRead), text.data());

            auto matchMask = MASK(toRead - (pattern.length() - 1));
            auto charReg = _mm512_set1_epi8(pattern.readByte());
            matchMask = _mm512_mask_cmpeq_epu8_mask(matchMask, textReg, charReg);

            while (pattern && matchMask)
            {
                matchMask >>= 1;
                charReg = _mm512_set1_epi8(pattern.readByte());
                matchMask = _mm512_mask_cmpeq_epu8_mask(matchMask, textReg, charReg);
            }

            if (matchMask && pattern.length() == 0)
            {
                auto offset = (UINT8) (_tzcnt_u64(matchMask) + 1) - inPattern.length();
                text.shift(offset);

                outText.shift(INT32(outText.data() - text.data()));
                break;
            }
            text.shift(toRead);
        }

        return outText;
    }

    UINT64 permuteText(const BUFFER text, const CC_MAP& permuteMap)
    {
        auto textMask = MASK(text.length());
        auto textReg = _mm512_maskz_loadu_epi8(textMask, text.data());
        auto matchReg = permute(textReg, MASK(text.length()), permuteMap.data);
        return _mm512_test_epi8_mask(matchReg, matchReg);
    }

    UINT64 permuteTextEnd(const BUFFER tail, const CC_MAP& permuteMap)
    {
        auto tailMask = ROR64(MASK(tail.length()), tail.length());
        auto tailReg = _mm512_maskz_expandloadu_epi8(tailMask, tail.data());
        auto matchReg = permute(tailReg, tailMask, CC_WHITESPACE.data);
        tailMask = _mm512_test_epi8_mask(matchReg, matchReg);
        return tailMask;
    }

    template <typename BUF>
    BUFFER trimSpaces(BUF&& textArg)
    {
        BUFFER inText = textArg;
        const auto head = inText.clone().readMax(ZREG_BYTES);
        auto headMatch = permuteText(head, CC_WHITESPACE);
        headMatch = RUNNING_MASK(headMatch);
        if (headMatch)
        {
            inText.shift(POPCNT(headMatch));
        }

        auto tail = inText.revReadMax(ZREG_BYTES);
        auto tailMask = permuteTextEnd(tail, CC_WHITESPACE);
        if (tailMask && _lzcnt_u64(tailMask) == 0)
        {
            tailMask ^= (tailMask | (tailMask >> 1));
            inText.shrink(tailMask ? UINT8(_lzcnt_u64(tailMask)) : tail.length());
        }
        return inText;
    }

    BUFFER splitAny(BUFFER& inText, BUFFER separators)
    {
        auto&& separatorMap = CC_MAP(separators);
        auto outText = inText;

        while (inText)
        {
            auto toRead = min(inText.length(), ZREG_BYTES);
            auto textReg = _mm512_maskz_loadu_epi8(MASK(toRead), inText.data());

            auto matchReg = permute(textReg, MASK(toRead), separatorMap.data);
            auto matchMask = _mm512_test_epi8_mask(matchReg, matchReg);

            if (matchMask)
            {
                outText = outText.readBytes((UINT8)_tzcnt_u64(matchMask));
                matchMask ^= (matchMask | (matchMask << 1));
                inText.shift(UINT8(_tzcnt_u64(matchMask)));
                break;
            }
            inText.shift(toRead);
        }
        return outText;
    }

    void parseDate(BUFFER dateString)
    {

    }
};

extern AVX3_STRING PString;
