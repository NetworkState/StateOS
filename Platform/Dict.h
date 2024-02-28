
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once
struct DICT_OPS
{
    constexpr static UINT32 NAMESTRING_MAX = 64;
    constexpr static UINT64 MOVE_3TO4_MASK = 0x7777777777777777;
    constexpr static UINT64 MOVE_4TO3_MASK = 0x7777777777777777;

    constexpr static UINT32 INLINE_NAME_MASK = BITFIELD32(24, 4);
    constexpr static UINT32 INLINE_STYLE_MASK = BITFIELD32(4, 28);

    static UINT32 getInlineName(TOKEN token)
    {
        ASSERT(token.isInlineName());
        return _pext_u32(token.toUInt32(), INLINE_NAME_MASK);
    }

    static UINT8 getInlineStyle(TOKEN token)
    {
        ASSERT(token.isInlineName());
        return (UINT8)_pext_u32(token.toUInt32(), INLINE_STYLE_MASK);
    }

    static TOKEN makeInlineName(UINT32 value, UINT8 style)
    {
        auto tokenValue = _pdep_u32(value, INLINE_NAME_MASK) | _pdep_u32(style, INLINE_STYLE_MASK) | UINT32(TOKEN_INLINE_NAME);
        return TOKEN(tokenValue);
    }

    UINT64 GetStyleBits(BUFFER nameString)
    {
        ASSERT(nameString.length() < NAMESTRING_MAX);
        auto nameMask = MASK(min(nameString.length(), NAMESTRING_MAX));
        auto nameReg = _mm512_maskz_loadu_epi8(MASK(nameString.length()), nameString.data());
        auto lowerReg = permute(nameReg, nameMask, ASCII_TOLOWER.data);
        auto styleBits = _mm512_mask_cmpneq_epi8_mask(nameMask, nameReg, lowerReg);
        if (styleBits)
        {
            auto upperReg = permute(nameReg, nameMask, ASCII_TOUPPER.data);
            styleBits = _mm512_mask_cmpneq_epu8_mask(nameMask, nameReg, upperReg) ? styleBits : -1;
        }
        return styleBits;
    }

    BUFFER applyStyleBits(BUFFER nameString, UINT64 styleBits)
    {
        auto nameMask = MASK(nameString.length());
        auto nameReg = _mm512_maskz_loadu_epi8(nameMask, nameString.data());

        auto styleReg = permute(nameReg, styleBits, ASCII_TOUPPER.data);
        nameReg = _mm512_mask_mov_epi8(nameReg, styleBits, styleReg);

        _mm512_mask_storeu_epi8((PUINT8)nameString.data(), nameMask, nameReg);

        return nameString;
    }

    BUFFER ParseName(BUFFER nameString, BYTESTREAM encodeStream)
    {
        if (nameString.length() >= NAMESTRING_MAX)
            return NULL_BUFFER;

        auto nameReg = _mm512_set1_epi64(0);
        auto nameLength = UINT8(nameString.length());
        auto nameMask = MASK(nameLength);

        auto lastByte = nameString.shrink().readByte();
        auto encodeReg = _mm512_maskz_set1_epi8(1, lastByte);
        encodeReg = _mm512_mask_expandloadu_epi8(encodeReg, MASK(nameString.length()) << 1, nameString.data());
        encodeReg = permute(encodeReg, -1, ASCII_INLINE.data);
        auto mapMask = _mm512_test_epi8_mask(encodeReg, encodeReg);
        if (mapMask != nameMask) // Found bytes not part of this charset.
            return NULL_BUFFER;

        for (UINT32 i = 0; i < 4; i++)
        {
            auto byteReg = _mm512_and_epi32(_mm512_set1_epi32(0xFF << (i * 8)), encodeReg);
            byteReg = _mm512_srli_epi32(byteReg, i * 2);
            nameReg = _mm512_or_epi32(byteReg, nameReg);
        }
        nameReg = _mm512_maskz_compress_epi8(MOVE_4TO3_MASK, nameReg);
        encodeStream.writeByte(nameLength);
        auto encodeBytes = (DICT_LANECOUNT(nameLength) * 4) - 1;
        _mm512_mask_compressstoreu_epi8(encodeStream.commit(encodeBytes), MASK(encodeBytes), nameReg);
        return encodeStream.toBuffer();
    }

    BUFFER FormatName(BUFFER nameBytes)
    {
        auto&& outStream = ByteStream(NAMESTRING_MAX);
        auto decodeReg = _mm512_maskz_loadu_epi8(MASK(nameBytes.length()), nameBytes.data());
        decodeReg = shiftReg(decodeReg, 1);
        auto nameReg = _mm512_set1_epi64(0);
        decodeReg = _mm512_maskz_expand_epi8(MOVE_3TO4_MASK, decodeReg);
        for (UINT32 i = 0; i < 4; i++)
        {
            auto reg = _mm512_and_epi32(_mm512_set1_epi32(0x3F), decodeReg);
            reg = _mm512_slli_epi32(reg, i * 8);
            nameReg = _mm512_or_epi32(reg, nameReg);
            decodeReg = _mm512_srli_epi32(decodeReg, 6);
        }
        auto nameMask = _mm512_test_epi8_mask(nameReg, nameReg);
        nameReg = permute(nameReg, nameMask, ASCII_INLINE.r_data);
        auto stringLength = (UINT8)POPCNT(nameMask);
        _mm512_mask_compressstoreu_epi8(outStream.commit(stringLength - 1), nameMask & (nameMask << 1), nameReg);
        _mm512_mask_compressstoreu_epi8(outStream.commit(1), 1, nameReg);
        return outStream.toBuffer();
    }

    BUFFER FormatName(UINT32 nameValue)
    {
        nameValue = _pdep_u32(nameValue, 0x3F3F3F3F);
        auto nameReg = _mm512_maskz_set1_epi32(1, nameValue);
        auto nameMask = _mm512_test_epi8_mask(nameReg, nameReg);
        nameReg = permute(nameReg, nameMask, ASCII_INLINE.r_data);

        auto&& outStream = ByteStream(NAMESTRING_MAX);
        _mm512_mask_compressstoreu_epi8(outStream.commit(POPCNT(nameMask) - 1), nameMask & (nameMask << 1), nameReg);
        _mm512_mask_compressstoreu_epi8(outStream.commit(1), 1, nameReg);
        return outStream.toBuffer();
    }

    UINT32 getPrefix(BUFFER nameBytes) { return *(UINT32*)nameBytes.data(); }

    template <typename STACK>
    TOKEN findCustomName(BUFFER nameBytes, UINT64 styleBits)
    {
        TOKEN matchToken;
        if (nameBytes.length() <= 4)
        {
            auto prefix = nameBytes.readU32() >> 8;
            matchToken = makeInlineName(prefix, UINT8(styleBits));
        }
        else if (auto matchIndex = STACK::GetCurrent().nameDict.matchName(nameBytes))
        {
            if (styleBits)
            {
                if (auto styleIndex = STACK::GetCurrent().nameDict.findStyle(matchIndex, styleBits))
                {
                    matchIndex = styleIndex;
                }
            }
            matchToken = TOKEN(TOKEN_NAME, STACK::STACKTYPE, matchIndex);
        }
        return matchToken;
    }

    bool IS_STYLE_TOKEN(TOKEN token)
    {
        return token.getValue() & AVX3_DICT<GLOBAL_STACK>::TOKEN_STYLE_MASK;
    }

    UINT32 FindToken(TOKEN token, STREAM_READER<const TOKEN> tokenList)
    {
        UINT16 match1 = 0, match2 = 0;
        auto listMask = (UINT16)MASK(min(tokenList.length(), 16));
        auto listReg = _mm512_maskz_loadu_epi32(listMask, tokenList.data());
        match1 = _mm512_mask_cmpeq_epu32_mask(listMask, listReg, _mm512_set1_epi32(token.toUInt32()));
        tokenList.shift(POPCNT(listMask));

        listMask = (UINT16)MASK(min(tokenList.length(), 16));
        listReg = _mm512_maskz_loadu_epi32(listMask, tokenList.data());
        match2 = _mm512_mask_cmpeq_epu32_mask(listMask, listReg, _mm512_set1_epi32(token.toUInt32()));
        tokenList.shift(POPCNT(listMask));

        ASSERT(tokenList.length() == 0);

        UINT32 match = (match2 << 16) | match1;
        return match ? _tzcnt_u32(match) : -1;
    }

    UINT32 ArrayFind(TOKEN token, TOKENBUFFER tokenArray)
    {
        auto tokenReg = _mm512_set1_epi32(token.toUInt32());
        while (tokenArray)
        {
            UINT16 match[4];

            auto buffer1 = tokenArray.readMax(16);
            auto listReg1 = _mm512_maskz_loadu_epi32(MASK16(buffer1.length()), buffer1.data());
            match[0] = _mm512_cmpeq_epu32_mask(listReg1, tokenReg);

            auto buffer2 = tokenArray.readMax(16);
            auto listReg2 = _mm512_maskz_loadu_epi32(MASK16(buffer2.length()), buffer2.data());
            match[1] = _mm512_cmpeq_epu32_mask(listReg2, tokenReg);

            auto buffer3 = tokenArray.readMax(16);
            auto listReg3 = _mm512_maskz_loadu_epi32(MASK16(buffer3.length()), buffer3.data());
            match[2] = _mm512_cmpeq_epu32_mask(listReg3, tokenReg);

            auto buffer4 = tokenArray.readMax(16);
            auto listReg4 = _mm512_maskz_loadu_epi32(MASK16(buffer4.length()), buffer4.data());
            match[3] = _mm512_cmpeq_epu32_mask(listReg4, tokenReg);

            if (auto match64 = *(UINT64*)match)
            {
                return (UINT32)_tzcnt_u64(match64);
            }
        }
        return -1;
    }

    template <typename STACK>
    TOKEN CreateName(BUFFER nameString, bool caseSensitive = true)
    {
        TOKEN nameToken;
        do
        {
            if (nameString.length() == 0)
            {
                nameToken = NULL_NAME;
                break;
            }

            CACHE_LINE outBuffer;
            auto nameBytes = ParseName(nameString, outBuffer);
            if (nameBytes.length() == 0)
            {
                auto&& nameDict = STACK::GetCurrent().nameDict;
                auto nameIndex = nameDict.longnameDict.createName(nameString);
                nameToken = TOKEN(TOKEN_NAME, TF_LONGNAME | STACK::STACKTYPE, nameIndex);
                break;
            }

            UINT64 styleBits = caseSensitive ? GetStyleBits(nameString) : 0;

            auto&& baseDict = GlobalStack().nameDict;
            nameToken = findCustomName<GLOBAL_STACK>(nameBytes, styleBits);
            if (nameToken.isInlineName() || (nameToken && (styleBits == 0 || IS_STYLE_TOKEN(nameToken))))
            {
                break;
            }

            if (nameToken && styleBits)
            {
                auto nameIndex = baseDict.writeStyle(nameToken.getValue(), styleBits);
                nameToken = TOKEN(TOKEN_NAME, GLOBAL_STACK::STACKTYPE, nameIndex);
                break;
            }

            auto&& customDict = STACK::GetCurrent().nameDict;
            if (STACK::STACKTYPE != TF_GLOBAL)
            {
                nameToken = findCustomName<STACK>(nameBytes, styleBits);
                if (nameToken && (styleBits == 0 || (styleBits && IS_STYLE_TOKEN(nameToken))))
                {
                    break;
                }

                if (nameToken && styleBits)
                {
                    auto nameIndex = customDict.writeStyle(nameToken.getValue(), styleBits);
                    nameToken = TOKEN(TOKEN_NAME, STACK::STACKTYPE, nameIndex);
                    break;
                }
            }

            auto nameIndex = customDict.writeName(nameBytes);
            if (styleBits)
            {
                nameIndex = customDict.writeStyle(nameIndex, styleBits);
            }
            nameToken = TOKEN(TOKEN_NAME, STACK::STACKTYPE, nameIndex);
        } while (false);
        return nameToken;
    }

    bool IsLongName(TOKEN nameToken)
    {
        return bool(nameToken.getFlags() & TF_LONGNAME);
    }

    template<typename DICT>
    BUFFER getName(DICT& nameDict, TOKEN nameToken)
    {
        auto nameIndex = nameToken.getValue();
        if (IsLongName(nameToken))
        {
            return nameDict.longnameDict.getName(nameIndex);
        }
        BUFFER nameString;
        auto nameBytes = nameDict.getNameBytes(nameIndex);
        nameString = FormatName(nameBytes);
        if (auto styleBits = nameDict.getStyle(nameIndex, nameString))
        {
            nameString = applyStyleBits(nameString, styleBits);
        }
        return nameString;
    }

    template <typename STACK>
    BUFFER getName(TOKEN nameToken)
    {
        ASSERT(nameToken.isName()); // not inline
        auto nameIndex = nameToken.getValue();

        auto&& nameDict = STACK::GetCurrent().nameDict;
        return getName(nameDict, nameToken);
    }

    template <typename STACK>
    UINT32 getNameLength(TOKEN nameToken)
    {
        ASSERT(nameToken.isName()); // not inline
        auto nameIndex = nameToken.getValue();

        auto&& nameDict = STACK::GetCurrent().nameDict;
        if (IsLongName(nameToken))
        {
            return nameDict.longnameDict.getName(nameIndex).length();
        }
        return nameDict.getNameLength(nameIndex);
    }

    BUFFER GetName(TOKEN nameToken)
    {
        BUFFER nameString;

        if (nameToken.getValue() == 0)
        {
            return NULL_BUFFER;
        }
        if (nameToken.isInlineName())
        {
            nameString = FormatName(getInlineName(nameToken));
            if (auto styleBits = getInlineStyle(nameToken))
            {
                applyStyleBits(nameString, styleBits);
            }
        }
        else
        {
            auto stackType = nameToken.getStackType();
            if (stackType == TF_GLOBAL)
            {
                nameString = getName<GLOBAL_STACK>(nameToken);
            }
            else if (stackType == TF_SESSION)
            {
                nameString = getName<SESSION_STACK>(nameToken);
            }
            else if (stackType == TF_SERVICE)
            {
                nameString = getName<SERVICE_STACK>(nameToken);
            }
            else DBGBREAK();
        }
        return nameString;
    }

    UINT32 GetNameLength(TOKEN nameToken)
    {
        UINT32 nameLength = 0;
        if (nameToken.isInlineName())
        {
            auto nameValue = _pdep_u32(getInlineName(nameToken), 0x3F3F3F3F);
            auto nameReg = _mm512_maskz_set1_epi32(1, nameValue);
            auto nameMask = _mm512_test_epi8_mask(nameReg, nameReg);
            nameLength = POPCNT(nameMask);
        }
        else
        {
            auto stackType = nameToken.getStackType();
            if (stackType == TF_GLOBAL)
            {
                nameLength = getNameLength<GLOBAL_STACK>(nameToken);
            }
            else if (stackType == TF_SESSION)
            {
                nameLength = getNameLength<SESSION_STACK>(nameToken);
            }
            else if (stackType == TF_SERVICE)
            {
                nameLength = getNameLength<SERVICE_STACK>(nameToken);
            }
            else DBGBREAK();
        }
        return nameLength;
    }

    template <typename STACK>
    TOKEN FindName(BUFFER nameString, bool caseSensitive = true)
    {
        if (nameString.length() == 0)
            return NULL_NAME;

        if (nameString.length() >= NAMESTRING_MAX)
        {
            if (auto nameIndex = STACK::GetCurrent().nameDict.longnameDict.findName(nameString))
            {
                ASSERT((nameIndex & 0xFFF00000) == 0);
                return TOKEN(TOKEN_NAME, TF_LONGNAME | STACK::STACKTYPE, nameIndex);
            }
        }

        CACHE_LINE outBuffer;
        auto nameBytes = ParseName(nameString, outBuffer);
        UINT64 styleBits = caseSensitive ? GetStyleBits(nameString) : 0;

        auto nameToken = findCustomName<GLOBAL_STACK>(nameBytes, styleBits);
        if (!nameToken && (STACK::STACKTYPE != TF_GLOBAL))
            nameToken = findCustomName<STACK>(nameBytes, styleBits);

        return nameToken;
    }
};

inline DICT_OPS Dict;
inline TOKEN CreateName(BUFFER nameString, bool caseSensitive)
{
    return Dict.CreateName<GLOBAL_STACK>(nameString, caseSensitive);
}

inline TOKEN FindName(BUFFER nameString)
{
    return Dict.FindName<GLOBAL_STACK>(nameString);
}

inline BUFFER GetName(TOKEN token)
{
    return Dict.GetName(token);
}

inline BUFFER NameToString(TOKEN token)
{
    return Dict.GetName(token);
}

inline TOKEN CreateSessionName(BUFFER nameString, bool isCaseSensitive)
{
    return Dict.CreateName<SESSION_STACK>(nameString, isCaseSensitive);
}

inline TOKEN CreateServiceName(BUFFER nameString, bool isCaseSensitive)
{
    return Dict.CreateName<SERVICE_STACK>(nameString, isCaseSensitive);
}

template <>
inline TOKEN CreateCustomName<SESSION_STACK>(BUFFER nameString, bool isCaseSensitive)
{
    return Dict.CreateName<SESSION_STACK>(nameString, isCaseSensitive);
}

template <>
inline TOKEN CreateCustomName<SERVICE_STACK>(BUFFER nameString, bool isCaseSensitive)
{
    return Dict.CreateName<SERVICE_STACK>(nameString, isCaseSensitive);
}

inline UINT32 GetNameLength(TOKEN name)
{
    return Dict.GetNameLength(name);
}
