
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

#include "pch.h"
#pragma warning( disable : 4146) // it's ok to assign a -ve number to unsigned
#pragma warning( disable: 26813)

#define DBGBREAK()		DebugBreak()
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define NT_FAILED(Status) (((NTSTATUS)(Status)) < 0)
#define VERIFY_STATUS	if (!NT_SUCCESS(status)) { DBGBREAK(); break; }
#define VERIFY(_x_) if (!_x_) {DBGBREAK(); break;}
#define ASSERT(_x_)		assert(_x_)
#define LASTERROR() NTSTATUS_FROM_WIN32(GetLastError())

constexpr UINT32 BIT32(UINT8 x) { return UINT32(1) << x; }
constexpr UINT64 BIT64(UINT8 x) { return UINT64(1) << x; }
constexpr UINT16 BIT16(UINT8 x) { return UINT16(1) << x; }

constexpr UINT32 LARGE_PAGE_SIZE = 2 * 1024 * 1024;
extern UINT32 LargePageSize;
extern bool LargePageSupport;

constexpr bool IS_ALIGNED(UINT64 value, UINT32 alignment) { return (value & (alignment - 1)) == 0; }
constexpr bool IS_PAGEALIGNED(UINT64 value) { return (value & (4096 - 1)) == 0; }

void print(auto&& ... args)
{
    char tempString[512];
    sprintf_s(tempString, args ...);
    OutputDebugStringA(tempString);
}

void LogError(auto&& ... args)
{
    print(args ...);
}

constexpr UINT32 ROUND16(UINT64 x) { return (x + 15) & -16; }
constexpr UINT64 ROUNDTO(UINT64 x, UINT64 base) { return (x + base - 1) & -base; }
constexpr UINT64 ROUND8(UINT64 x) { return (x + 7) & -8; }
constexpr UINT64 ROUND4(UINT64 x) { return (x + 3) & -4; }

constexpr UINT64 ROR64(UINT64 SRC, UINT8 y) { return (SRC >> y) | (SRC << (64 - y)); }
constexpr UINT32 ROR32(UINT32 SRC, UINT8 y) { return (SRC >> y) | (SRC << (32 - y)); }
constexpr UINT16 ROR16(UINT16 SRC, UINT8 y) { return (SRC >> y) | (SRC << (16 - y)); }
constexpr UINT32 ROR8(UINT8 SRC, UINT8 y) { return (SRC >> y) | (SRC << (8 - y)); }

inline UINT8 LOG2(UINT64 value) { return UINT8(64 - _lzcnt_u64(value)) + UINT8(_mm_popcnt_u64(value) > 1); }

constexpr UINT8 BYTECOUNT(UINT64 x) { return x ? UINT8(ROUND8(64 - _lzcnt_u64(x)) / 8) : 1; }
constexpr UINT8 NIBBLECOUNT(UINT64 x) { return x ? UINT8(ROUND4(64 - _lzcnt_u64(x)) / 4) : 1; }
constexpr UINT8 WORDCOUNT(UINT64 x) { return x ? UINT8(ROUND16(64 - _lzcnt_u64(x)) / 16) : 1; }

constexpr UINT64 MASK(UINT64 count) {
    if (count >= 64)
        return -1;

    return (1ull << count) - 1;
}

constexpr UINT32 MASK32(UINT8 count) {
    if (count >= 32)
        return -1;

    return (1u << count) - 1;
}

constexpr UINT8 MASK8(UINT8 count)
{
    if (count >= 8)
        return -1;

    return (UINT8(1) << count) - 1;
}

constexpr UINT16 MASK16(UINT8 count)
{
    if (count >= 16)
        return -1;

    return (UINT16(1) << count) - 1;
}

constexpr UINT64 HIMASK(UINT64 count) {
    return ROR64(MASK(count), UINT8(count));
}

constexpr UINT64 RUNNING_MASK(UINT64 value) { // contiguous bits from bit position 0
    return value & (~(value + 1));
}

constexpr UINT64 HI_RUNNING_MASK(UINT64 value) {
    value ^= (value | (value << 1));
    return HIMASK(_lzcnt_u64(value));
}

constexpr bool SIGN_SWITCHED(INT16 first, INT16 second) {
    return (first & 0x8000) ^ (second & 0x8000);
}

constexpr bool SIGN_SWITCHED(double first, double second) {
    return ((first < 0) && (second > 0)) || ((first > 0) && (second < 0));
}

constexpr UINT64 TICKS_PER_MS = 10000;
constexpr UINT64 TICKS_PER_SECOND = TICKS_PER_MS * 1000;

// 01/01/1970 00:00:00
constexpr UINT64 UnixTimeOrigin = 0x19db1ded53e8000 / TICKS_PER_MS;
constexpr UINT64 UnixTimeOriginSeconds = 0x19db1ded53e8000 / TICKS_PER_SECOND;

// 02/20/2020 20:20:20.20
constexpr UINT64 TIMESTAMP_ORIGIN = 0x01d5e82b2c34e740 / TICKS_PER_MS;

inline UINT64 GetTicks()
{
    UINT64 timeValue;
    GetSystemTimePreciseAsFileTime((LPFILETIME)&timeValue);
    return timeValue;
}

extern UINT64 TicksAtStartup;

inline UINT64 GetUptimeUS() { return (GetTicks() - TicksAtStartup) / 10; }
inline UINT32 GetUptimeS() { return UINT32(GetUptimeUS() / TICKS_PER_SECOND); }

inline UINT64 GetTime()
{
    return GetTicks() / TICKS_PER_MS;
}

inline UINT64 GetTimeS()
{
    return GetTicks() / TICKS_PER_SECOND;
}

inline UINT32 GetUnixTime()
{
    return UINT32(GetTimeS() - UnixTimeOriginSeconds);
}

inline UINT64 GetTimestamp()
{
    return GetTime() - TIMESTAMP_ORIGIN;
}

constexpr UINT32 MS_PER_SEC = 1000;
constexpr UINT32 US_PER_SEC = MS_PER_SEC * 1000;
constexpr UINT32 MS_PER_HOUR = (1000 * 60 * 60);
constexpr UINT32 MS_PER_DAY = MS_PER_HOUR * 24;
constexpr UINT32 SEC_PER_DAY = MS_PER_DAY / 1000;

struct CLOCK 
{
    UINT64 startTime;

    void reset()
    {
        startTime = GetTicks();
    }

    UINT64 elapsedTime() // in milliseconds	,
    {
        return (GetTicks() - startTime) / TICKS_PER_MS;
    }
};

struct SCLOCK
{
    UINT32 startTime;
    void reset()
    {
        startTime = UINT32(GetTicks() / TICKS_PER_SECOND);
    }

    UINT32 elapsedTime() // in seconds,
    {
        return UINT32(GetTicks() / TICKS_PER_SECOND) - startTime;
    }
};

extern CLOCK SystemClock;
extern SCLOCK SecondsClock;

constexpr UINT32 ROUND_TO(UINT32 number, UINT32 base) { return (number + base - 1) & ~(base - 1); }

template <typename T, typename ... ARGS>
inline T& NEW(T& address, ARGS&& ... args)
{
    new (&address) T(args ...);
    return address;
}

#define VARGS(_T_) template <std::convertible_to<_T_> ... ARGS>

#include "Memory.h"

constexpr UINT16 TLS_PORT = 443;
constexpr UINT16 HTTP_PORT = 80;
constexpr UINT16 RTSP_PORT = 554;
constexpr UINT16 RTSPS_PORT = 322;
constexpr UINT16 RTMP_PORT = 1935;

#define NULLPTR 0x00000BAD

template <typename T>
constexpr T &NullRef()
{
    return *(T *)NULLPTR;
}

template <typename T>
constexpr bool IsNullRef(T &value)
{
    return &value == (T *)NULLPTR;
}

template <typename T>
constexpr bool IsValidRef(T& value)
{
    return &value != (T*)NULLPTR;
}

template <typename T>
UINT32 SWAP32(T x) { return _byteswap_ulong(UINT32(x)); }

template <typename T>
UINT16 SWAP16(T x) { return _byteswap_ushort(UINT16(x)); }

constexpr UINT64 BITFIELD(UINT8 bits, UINT8 offset) { return MASK(bits) << offset; }
constexpr UINT32 BITFIELD32(UINT8 bits, UINT8 offset) { return MASK32(bits) << offset;}

enum class TOKENTYPE : UINT8
{
    TOKEN_INLINE_NAME = 0x01,
    TOKEN_SCRIPT = 0x02,
    TOKEN_KEYDATA = 0x03,
    TOKEN_NAME = 0x04,
    TOKEN_TIMESTAMP = 0x05,
    TOKEN_ID = 0x06,
    TOKEN_DATE = 0x07,
    TOKEN_BLOB = 0x08,
    TOKEN_NUMBER = 0x09,
    TOKEN_SYMBOL = 0x0A,
    TOKEN_LABEL = 0x0B,
    TOKEN_CONSTANT = 0x0D,
    TOKEN_TERROR = 0x0E,
    TOKEN_OBJECT = 0x0F,
};
using enum TOKENTYPE;

enum class TOKENFLAGS : UINT8
{
    TOKEN_NOFLAGS = 0,

    TF_GLOBAL = 0x00,
    TF_MODULE = 0x01,
    TF_SERVICE = 0x02,
    TF_SESSION = 0x03,
    TF_SCHEDULER = 0x04,

    TF_GTAG = 0x01,
    TF_SHA256 = 0x02,
    TF_ECDSA = 0x04,

    TF_SDP = 0x01, // script

    TF_LONGNAME = 0x08,

    TF_JS_OPERATOR = 0x01, // symbol
    TF_JS_KEYWORD = 0x02,
};
DEFINE_ENUM_FLAG_OPERATORS(TOKENFLAGS);
using enum TOKENFLAGS;

constexpr UINT8 TOKEN_TYPEBITS = 8;
constexpr UINT64 TOKEN_FLAG_MASK = BITFIELD(4, 4);

struct TOKEN
{
    UINT64 token;
    constexpr static UINT64 IS_64BIT = BIT64(63);
    constexpr static UINT64 VALUE32_MASK = BITFIELD(24, 8);
    constexpr static UINT64 VALUE64_MASK = BITFIELD(48, 8);

    constexpr bool is64bit() const { return bool(token & IS_64BIT); }

    constexpr TOKEN() : TOKEN(TOKEN_TERROR, TOKEN_NOFLAGS, 0) {}

    constexpr TOKEN(const TOKENTYPE type, const UINT32 value) : TOKEN(type, TOKEN_NOFLAGS, value) {}
    constexpr TOKEN(const TOKENTYPE type, const int value) : TOKEN(type, TOKEN_NOFLAGS, UINT32(value)) {}
    constexpr TOKEN(const TOKENTYPE type, const UINT64 value) : TOKEN(type, TOKEN_NOFLAGS, value) {}

    constexpr TOKEN(const TOKENTYPE type, const TOKENFLAGS flags, UINT32 value) : token((value << 8) | UINT8(type) | (UINT8(flags) << 4)) { ASSERT((value >> 24) == 0); }
    constexpr TOKEN(const TOKENTYPE type, const TOKENFLAGS flags, int value) : TOKEN(type, flags, UINT32(value)) {}
    constexpr TOKEN(const TOKENTYPE type, const TOKENFLAGS flags, const UINT64 value) : token((value << 8) | UINT8(type) | (UINT8(flags) << 4) | IS_64BIT) { ASSERT((value >> 48) == 0); }

    constexpr TOKEN(const UINT32 pattern) : token(pattern) {}
    constexpr TOKEN(const UINT64 pattern) : token(pattern | IS_64BIT) { ASSERT((pattern >> 48) == 0); }

    constexpr TOKENTYPE getType() const { return (TOKENTYPE)UINT8(token & 0x0F); }
    constexpr TOKENFLAGS getFlags() const { return (TOKENFLAGS)getFlagBits(); }
    constexpr UINT8 getFlagBits() const { return UINT8((token & 0xF0) >> 4); }

    constexpr UINT32 getValue() const { ASSERT(is64bit() == false); return UINT32((token & VALUE32_MASK) >> 8); }
    constexpr UINT64 getValue64() const { ASSERT(is64bit()); return (token & VALUE64_MASK) >> 8; }
    void setValue(UINT32 newValue) { ASSERT(!is64bit()); token = (newValue << 8) | UINT8(token); }

    constexpr UINT32 toUInt32() const { ASSERT(is64bit() == false); return UINT32(token); }
    constexpr UINT64 toUInt64() const { ASSERT(is64bit()); return token & ~IS_64BIT; }

    TOKEN toToken32() { return TOKEN(UINT32(toUInt64())); }

    constexpr bool isName() const { return getType() == TOKEN_NAME; }
    constexpr bool isInlineName() const { return getType() == TOKEN_INLINE_NAME; }
    constexpr bool isString() const { return getType() == TOKEN_NAME || getType() == TOKEN_INLINE_NAME; }
    constexpr bool isObject() const { return getValue() != 0 && getType() == TOKEN_OBJECT; }
    constexpr bool isNumber() const { return getType() == TOKEN_NUMBER; }
    constexpr bool isDate() const { return getType() == TOKEN_DATE; }
    constexpr bool isBlob() const { return getType() == TOKEN_BLOB; }
    constexpr bool isId() const { return getType() == TOKEN_ID; }
    constexpr bool isTimestamp() const { return getType() == TOKEN_TIMESTAMP; }
    constexpr bool isDateTime() const { return getType() == TOKEN_DATE; }
    constexpr bool isError() const { return getType() == TOKEN_TERROR; }
    constexpr bool isConstant() const { return getType() == TOKEN_CONSTANT; }
    constexpr bool isScript() const { return getType() == TOKEN_SCRIPT; }
    constexpr bool isSdp() const { return getType() == TOKEN_SCRIPT && getFlags() == TF_SDP; }

    constexpr static UINT64 KEYWORD_MASK = BITFIELD(8, 8);
    constexpr static UINT64 SCOPE_MASK = BITFIELD(16, 16);

    void setField(UINT64 mask, UINT64 value) { token = (token & ~mask) | _pdep_u64(value, mask); }
    UINT64 getField(UINT64 mask) { return _pext_u64(token, mask); }

    UINT8 getKeyword() { ASSERT(isScript()); return UINT8(getField(KEYWORD_MASK)); }
    UINT8 getScope() { ASSERT(isScript()); return UINT8(getField(SCOPE_MASK)); }
    void setScope(UINT32 scope) { ASSERT(isScript()); setField(SCOPE_MASK, scope); }
    static TOKEN createScript(TOKENFLAGS type, UINT8 keyword, UINT16 scope)
    {
        auto value = _pdep_u64(scope, SCOPE_MASK) | _pdep_u64(keyword, KEYWORD_MASK) | _pdep_u64(UINT64(type), TOKEN_FLAG_MASK) | UINT64(TOKEN_SCRIPT);
        return TOKEN(value);
    }

    constexpr static UINT64 NAME_MASK = MAXUINT64 ^ 0x0F00;
    constexpr static UINT64 INLINE_NAME_MASK = MAXUINT64 ^ 0xF0;

    constexpr UINT64 compareValue() const
    {
        return isName() ? token & NAME_MASK :
            isInlineName() ? token & INLINE_NAME_MASK : token;
    }

    constexpr bool operator == (const TOKEN other) const { return compareValue() == other.compareValue(); }
    constexpr bool operator != (const TOKEN other) const { return compareValue() != other.compareValue(); }

    operator bool() const
    {
        bool invalid = isError() || _pext_u64(token, VALUE64_MASK) == 0;
        return !invalid;
    }

    constexpr TOKENFLAGS getStackType() { return TOKENFLAGS(token & 0x70); }
};

constexpr auto Undefined = TOKEN(TOKEN_TERROR, 0x01);
constexpr auto Null = TOKEN(TOKEN_TERROR, 0x02);
constexpr auto TypeError = TOKEN(TOKEN_TERROR, 0x03);
constexpr auto NULL_NAME = TOKEN(TOKEN_NAME, 0);
constexpr auto Blob = TOKEN(TOKEN_BLOB, 0);

constexpr auto SHA256_TOKEN = TOKEN(TOKEN_KEYDATA, TF_SHA256, 0);
constexpr auto GTAG_TOKEN = TOKEN(TOKEN_KEYDATA, TF_GTAG, 0);
constexpr auto ECDSA_TOKEN = TOKEN(TOKEN_KEYDATA, TF_ECDSA, 0);
constexpr auto ECKEY_TOKEN = TOKEN(TOKEN_KEYDATA, TF_ECDSA, 0);

constexpr auto Nan = TOKEN(TOKEN_TERROR, 0x04);
constexpr auto False = TOKEN(TOKEN_TERROR, 0x05);

constexpr auto True = TOKEN(TOKEN_CONSTANT, 0x01);
constexpr auto Namespace = TOKEN(TOKEN_CONSTANT, 0x04);

template <typename T, const UINT32 arraySize>
constexpr INT32 ArrayFind(const T(&array)[arraySize], T value)
{
    for (UINT32 i = 0; i < arraySize; i++)
    {
        if (array[i] == value)
            return i;
    }
    return -1;
}

template <typename T, const UINT32 arraySize>
bool ArrayExists(const T(&array)[arraySize], T value)
{
    return ArrayFind(array, value) != -1;
}

struct THREAD_STACK
{
    STACK_MEMORY memory;
    THREAD_STACK() {}
};

struct alignas(4) U96
{
    union
    {
        UINT8  u8[12];
        UINT16 u16[6];
        UINT32 u32[3];
    };

    void setU32(UINT32 x, UINT32 y, UINT32 z) { u32[0] = x; u32[1] = y; u32[2] = z; }
    U96() { u32[0] = u32[1] = u32[2] = 0; }

    bool operator == (U96& other) { return u32[0] == other.u32[0] && u32[1] == other.u32[1] && u32[2] == other.u32[2]; }
    void operator = (const U96& other) { u32[0] = other.u32[0]; u32[1] = other.u32[1]; u32[2] = other.u32[2]; };

    explicit operator bool() { return u32[0] && u32[1] && u32[2]; }
};
constexpr UINT32 U96_BYTES = 12;

struct alignas(8) U128
{
    union
    {
        UINT8  u8[16];
        UINT16 u16[8];
        UINT32 u32[4];
        UINT64 u64[2];
    };

    U128() { u64[0] = u64[1] = 0; }
    constexpr U128(UINT64 a1, UINT64 a2) { u64[0] = a1; u64[1] = a2; }
    U128(const U128& other) { *this = other; }
    U128(const GUID& guid)
    {
        u32[0] = SWAP32(guid.Data1);
        u16[2] = SWAP16(guid.Data2);
        u16[3] = SWAP16(guid.Data3);
        RtlCopyMemory(&u8[8], guid.Data4, 8);
    }

    GUID toGuid() const
    {
        GUID guid;
        guid.Data1 = SWAP32(u32[0]);
        guid.Data2 = SWAP16(u16[2]);
        guid.Data3 = SWAP16(u16[3]);
        RtlCopyMemory(guid.Data4, &u8[8], 8);
        return guid;
    }

    void zero() { u64[0] = u64[1] = 0; }
    constexpr bool isZero() const { return u64[0] == 0 && u64[1] == 0; }
    constexpr bool isNotZero() const { return u64[0] != 0 || u64[1] != 0; }

    bool compare(U128& other) const
    {
        return u64[0] == other.u64[0] && u64[1] == other.u64[1];
    }

    bool operator == (const U128& other) const { return u64[0] == other.u64[0] && u64[1] == other.u64[1]; }
    void operator = (const U128& other) { u64[0] = other.u64[0]; u64[1] = other.u64[1]; };

    void Xor(const U128& other) { u64[0] ^= other.u64[0]; u64[1] ^= other.u64[1]; }
    explicit operator bool() const { return isNotZero(); }
};
constexpr UINT32 U128_BYTES = 16;

struct alignas(16) U256
{
    union
    {
        UINT8  u8[32];
        UINT16 u16[16];
        UINT32 u32[8];
        UINT64 u64[4];
    };

    U256() { u64[0] = u64[1] = 0; u64[2] = u64[3] = 0; }
    constexpr U256(UINT64 a1, UINT64 a2, UINT64 a3, UINT64 a4) { u64[0] = a1; u64[1] = a2; u64[2] = a3; u64[3] = a4; }
    U256(const U256& other) { *this = other; }

    void zero() { u64[0] = u64[1] = u64[2] = u64[3] = 0; }
    constexpr bool isZero() const { return u64[0] == 0 && u64[1] == 0 && u64[2] == 0 && u64[3] == 0; }
    constexpr bool isNotZero() const { return u64[0] != 0 || u64[1] != 0 || u64[2] != 0 || u64[3] != 0; }
    
    bool compare(const U256& other) const
    {
        return u64[0] == other.u64[0] && u64[1] == other.u64[1] && u64[2] == other.u64[2] && u64[3] == other.u64[3];
    }

    bool operator == (const U256& other) const { return compare(other); }
    void operator = (const U256& other) { u64[0] = other.u64[0]; u64[1] = other.u64[1]; u64[2] = other.u64[2]; u64[3] = other.u64[3]; };
    explicit operator bool() const { return isNotZero(); }
};
constexpr UINT32 U256_BYTES = 32;
constexpr U256 U256_ZERO{ 0, 0, 0, 0 };

struct alignas(16) U512
{
    union
    {
        UINT8  u8[64];
        UINT16 u16[32];
        UINT32 u32[16];
        UINT64 u64[8];
        U128   u128[4];
        U256   u256[2];
    };

    U512() { u256[0].zero(); u256[1].zero(); }
    U512(const U512& other) { *this = other; }

    void zero() { u64[0] = u64[1] = u64[2] = u64[3] = 0; }
    constexpr bool isZero() const { return u256[0].isZero() && u256[1].isZero(); }
    constexpr bool isNotZero() const { return u256[0].isNotZero() || u256[1].isNotZero(); }

    bool compare(const U512& other) const
    {
        return u256[0] == other.u256[0] && u256[1] == other.u256[1];
    }

    bool operator == (const U512& other) const { return compare(other); }
    void operator = (const U512& other) { u256[0] = other.u256[0]; u256[1] = other.u256[1]; };
    explicit operator bool() const { return isNotZero(); }
};
constexpr UINT32 U512_BYTES = 64;
constexpr UINT32 U512_QWORDS = 8;

struct alignas(16) U1024
{
    union
    {
        UINT8  u8[128];
        UINT16 u16[64];
        UINT32 u32[32];
        UINT64 u64[16];
        U128   u128[8];
        U256   u256[4];
        U512   u512[2];
    };

    U1024() { u512[0].zero(); u512[1].zero(); }
    U1024(const U1024& other) { *this = other; }

    void zero() { u64[0] = u64[1] = u64[2] = u64[3] = 0; }
    constexpr bool isZero() const { return u512[0].isZero() && u512[1].isZero(); }
    constexpr bool isNotZero() const { return u512[0].isNotZero() || u512[1].isNotZero(); }

    bool compare(const U1024& other) const
    {
        return u512[0] == other.u512[0] && u512[1] == other.u512[1];
    }

    bool operator == (const U1024& other) const { return compare(other); }
    void operator = (const U1024& other) { u512[0] = other.u512[0]; u512[1] = other.u512[1]; };
    explicit operator bool() const { return isNotZero(); }
};
constexpr UINT32 U1024_BYTES = 128;
constexpr UINT32 U1024_QWORDS = 16;

#include "Stream.h"

template <typename ... ARGS>
void Debug(ARGS&& ... args)
{
    auto str = ByteStream(1024).writeMany(args ...);
    LogInfo("%s", str.data());
}

constexpr UINT32 STRING_SIZE = 258;

using STRING_READER = STREAM_READER<const UINT8>;

template <UINT32 SZ>
using LOCAL_STREAM = TBYTESTREAM<SZ>;

constexpr USTRING DATA_DIRECTORY = ".\\";
constexpr USTRING STATEOS_BRAND = "StateOS v3";

#include "BaseNames.h"
#include "AVX3Parser.h"
#include "Token.h"

struct GLOBAL_STACK
{
    constexpr static TOKENFLAGS STACKTYPE = TF_GLOBAL;
    inline static GLOBAL_STACK* CurrentStack = nullptr;
    STACK_MEMORY memory;

    BYTESTREAM blobStream;
    ID_TOKEN<GLOBAL_STACK, TOKEN_ID> idTokens;
    AVX3_DICT<GLOBAL_STACK> nameDict;
    GLOBAL_STACK() {}

    BUFFER computerName;

    static GLOBAL_STACK& GetCurrent() { return *CurrentStack; }

    void init(UINT32 staticSize, UINT32 dynamicSize = 0)
    {
        ASSERT(CurrentStack == nullptr);
        CurrentStack = this;
        memory.init(staticSize, dynamicSize);
        nameDict.init();
        blobStream.setAddress((PUINT8)StackAllocNoLock(memory, 4096), 4096);
    }
};

inline GLOBAL_STACK& GlobalStack() { return GLOBAL_STACK::GetCurrent(); };

inline AVX3_DICT<GLOBAL_STACK>& GlobalDict() { return GlobalStack().nameDict; }
inline auto TokenGetID(TOKEN token) { return GlobalStack().idTokens.getID(token); }
inline TOKEN_OPS<GLOBAL_STACK> Tokens;

struct SCHEDULER_STACK;
struct SCHEDULER_STACK
{
    constexpr static TOKENFLAGS STACKTYPE = TF_SCHEDULER;
    STACK_MEMORY memory;
    BYTESTREAM blobStream;
    SCHEDULER_STACK(){}

    void clear()
    {
        memory.clear();
    }

    inline static thread_local SCHEDULER_STACK* CurrentStack;
    static void SetCurrent(SCHEDULER_STACK& newStack) { CurrentStack = &newStack; }
    static SCHEDULER_STACK& GetCurrent() { ASSERT(CurrentStack); return *CurrentStack; }
    static void ResetCurrent() { CurrentStack = nullptr; }

    void init(UINT32 staticSize, UINT32 dynamicSize)
    {
        memory.init(staticSize, dynamicSize);
        blobStream.setAddress((PUINT8)StackAllocNoLock(memory, 4096), 4096);
    }
};
const auto GetSchedulerStack = SCHEDULER_STACK::GetCurrent;
const auto SetSchedulerStack = SCHEDULER_STACK::SetCurrent;

template<> void* StackAlloc<SCHEDULER_STACK>(UINT32 size);

inline BYTESTREAM ByteStream(UINT32 size)
{
    return BYTESTREAM{ (PUINT8)StackAlloc<SCHEDULER_STACK>(size), size };
}

inline PVOID TempAlloc(UINT32 size)
{
    return StackAlloc<SCHEDULER_STACK>(size);
}
using TSTRING_STREAM = DATASTREAM<BUFFER, SCHEDULER_STACK>;

template <typename T>
using TDATASTREAM = DATASTREAM<T, SCHEDULER_STACK>;

struct SESSION_STACK
{
    constexpr static TOKENFLAGS STACKTYPE = TF_SESSION;
    STACK_MEMORY memory;

    AVX3_DICT<SESSION_STACK> nameDict;

    BYTESTREAM blobStream;

    UINT64 dateTimeOrigin;
    SESSION_STACK() {}

    inline static thread_local SESSION_STACK* CurrentStack;
    static void SetCurrent(SESSION_STACK& newStack) { CurrentStack = &newStack; }
    static SESSION_STACK& GetCurrent() { ASSERT(CurrentStack); return *CurrentStack; }
    static void ResetCurrent() { CurrentStack = nullptr; }

    void clear()
    {
        memory.clear();
    }

    void free()
    {
        clear();
        memory.free();
    }

    void init(UINT32 staticSize, UINT32 dynamicSize = 0)
    {
        SetCurrent(*this);
        dateTimeOrigin = GetTimeS() - (SEC_PER_DAY * 7);
        memory.init(staticSize, dynamicSize);
        nameDict.init();
        blobStream.setAddress((PUINT8)StackAllocNoLock(memory, 4096), 4096);
    }
};
inline TOKEN_OPS<SESSION_STACK> SessionTokens;
const auto GetSessionStack = SESSION_STACK::GetCurrent;
const auto SetSessionStack = SESSION_STACK::SetCurrent;

struct SERVICE_STACK
{
    constexpr static TOKENFLAGS STACKTYPE = TF_SERVICE;
    STACK_MEMORY memory;
    UINT64 dateTimeOrigin;
    ID_TOKEN<SERVICE_STACK, TOKEN_ID> idTokens;
    ID_TOKEN<SERVICE_STACK, TOKEN_OBJECT> objectTokens;
    AVX3_DICT<SERVICE_STACK> nameDict;
    LABEL_STORE<SERVICE_STACK> labelStore;
    BYTESTREAM blobStream;

    SERVICE_STACK() {}

    inline static thread_local SERVICE_STACK* CurrentStack;
    static void SetCurrent(SERVICE_STACK& newStack) { CurrentStack = &newStack; }
    static SERVICE_STACK& GetCurrent() { ASSERT(CurrentStack); return *CurrentStack; }
    static void ResetCurrent() { CurrentStack = nullptr; }

    void init(UINT32 staticSize, UINT32 dynamicSize = 0)
    {
        SetCurrent(*this);
        memory.init(staticSize, dynamicSize);
        dateTimeOrigin = GetTimeS() - (SEC_PER_DAY * 7);
        nameDict.init();
        labelStore.init();
        blobStream.setAddress((PUINT8)StackAllocNoLock(memory, 4096), 4096);
    }
};
inline TOKEN_OPS<SERVICE_STACK> ServiceTokens;
template<> void* StackAlloc<SERVICE_STACK>(UINT32 size);
const auto SetServiceStack = SERVICE_STACK::SetCurrent;
const auto GetServiceStack = SERVICE_STACK::GetCurrent;

template <typename T>
inline STREAM_READER<T> ServiceBufAlloc(UINT32 count, auto&& ... args)
{
    DATASTREAM<T, SERVICE_STACK> dataStream;
    return dataStream.commit(count).toRWBuffer();
}

extern TOKEN CreateName(BUFFER nameString, bool caseSensitive = true);
extern TOKEN FindName(BUFFER nameString);
extern BUFFER GetName(TOKEN token);
extern BUFFER NameToString(TOKEN token);
extern TOKEN CreateSessionName(BUFFER nameString, bool isCaseSensitive = true);
extern TOKEN CreateServiceName(BUFFER nameString, bool isCaseSensitive = true);
extern UINT32 GetNameLength(TOKEN name);

template <typename STACK>
TOKEN CreateCustomName(BUFFER nameString, bool isCaseSensitive = true);

#include "Scheduler.h"

template <typename STRM>
void Print(STRM&& printStream, auto&& ... args)
{
    printStream.writeMany(args ...);
    OutputDebugStringA(printStream.toBuffer().toString());
    OutputDebugStringA("\n");
}

void LogInfo(auto&& ... args)
{
    auto elapsedTime = SystemClock.elapsedTime();
    print("%02d:%02d:%03d ", (elapsedTime / 60000) % 60, (elapsedTime / 1000) % 60, elapsedTime % 1000);
    auto&& printStream = ByteStream(512);
    Print(printStream, args ...);
}

void LogInfo(BYTESTREAM& printStream, auto&& ... args)
{
    printStream.clear();
    auto elapsedTime = SystemClock.elapsedTime();
    print("%02d:%02d:%03d ", (elapsedTime / 60000) % 60, (elapsedTime / 1000) % 60, elapsedTime % 1000);
    Print(printStream, args ...);
}

struct PROCESSOR_INFO
{
    SERVICE_STACK* appStack;
    SESSION_STACK* sessionStack;
    SCHEDULER_STACK* schedulerStack;
    UINT32 currentQueue;
};

extern PROCESSOR_INFO ProcessorInfo[MAX_PROCESSOR_COUNT];

extern NTSTATUS InitPlatform();

typedef struct _rgb_color {
    unsigned char r, g, b;    /* Channel intensities between 0 and 255 */
} RGB, * PRGB;

struct HSV
{
    UINT32 value;

    HSV() { this->value = 0xFFFFFFFF; }

    constexpr HSV(UINT32 val) : value(val & 0xFFFFFF) {}
    constexpr HSV(UINT8 hue, UINT8 sat, UINT8 val) : value(hue << 16 | sat << 8 | val) {}

    HSV(HSV& other)
    {
        //ASSERT(other.value != 0xFFFFFFFF);
        this->value = other.value;
    }

    HSV(HSV* other) : HSV(*other) {};

    UINT8 hue() { return (UINT8)((this->value & 0xFF0000) >> 16); };
    UINT8 sat() { return (UINT8)((this->value & 0xFF00) >> 8); };
    UINT8 val() { return (UINT8)(this->value & 0xFF); };

    explicit operator bool() { return this->value != 0xFFFFFFFF; }

    bool operator ==(HSV other)
    {
        return this->value == other.value;
    }
};

template <typename T>
T* APPEND_LINK(T** link, T& node)
{
    T* prev = nullptr;
    while (*link)
    {
        prev = *link;
        link = &(*link)->next;
    }
    *link = &node;
    return prev;
}

template <typename T>
T* LAST_LINK(T** link)
{
    T* prev = nullptr;
    while (*link)
    {
        prev = *link;
        link = &(*link)->next;
    }
    return prev;
}

template <typename T>
bool REMOVE_LINK(T** nextLink, T& node)
{
    for (; *nextLink; nextLink = &(*nextLink)->next)
    {
        if (*nextLink == &node)
        {
            *nextLink = node.next;
            return true;
        }
    }
    return false;
}

enum class VL_VISIBILITY : UINT8
{
    VI_REPEAT = 0,
    VI_INVISIBLE = 64,
};
using enum VL_VISIBILITY;
constexpr bool operator !(VL_VISIBILITY value) { return value == VL_VISIBILITY::VI_REPEAT; }

enum class VL_SEPARATION : UINT8
{
    VS_REPEAT = 0,

    VS_TOP = 0x01,
    VS_SECTION = 0x0B,
    VS_CHAPTER = 0x0D,
    VS_PAGE = 0x0F,

    VS_PARA = 0x10,
    VS_PHRASE = 0x20,
    VS_WORD = 0x30,

    VS_WORD_LARGE = VS_WORD,
    VS_WORD_MEDIUM = VS_WORD + 4,
    VS_WORD_SMALL = VS_WORD + 8,

    VS_BLOCK = VS_PARA,
    VS_BLOCK_TAB1 = VS_BLOCK + 1,
    VS_BLOCK_TAB2 = VS_BLOCK + 2,
    VS_BLOCK_TAB3 = VS_BLOCK + 3,
    VS_BLOCK_TAB4 = VS_BLOCK + 4,
};
using enum VL_SEPARATION;
constexpr bool operator !(VL_SEPARATION value) { return value == VL_SEPARATION::VS_REPEAT; }

struct VLTOKEN
{
    TOKEN contour;
    BUFFER contourBlob;

    TOKEN label;

    VL_VISIBILITY visibility = VI_REPEAT;
    VL_SEPARATION separation = VS_REPEAT;

    VLTOKEN(TOKEN contour, TOKEN label, VL_SEPARATION separation = VS_REPEAT, VL_VISIBILITY visibility = VI_REPEAT) : contour(contour), label(label), separation(separation), visibility(visibility){}
    VLTOKEN() : contour(Undefined), label(Null) {}

    inline static UINT8 BSHR(UINT64& value, UINT8 bits = 8)
    {
        ASSERT(bits <= 8);
        UINT8 result = UINT8(value & MASK(bits));
        value >>= bits;
    }

    static void writeToken(BYTESTREAM& dataStream, TOKEN token, BUFFER tokenData = NULL_BUFFER)
    {
        auto tokenType = token.getType();
        if (tokenType == TOKEN_ID)  
        {
            auto id = ServiceTokens.getID(token);
            dataStream.writeVInt(UINT64(TOKEN_ID));
            dataStream.writeBytes(id);
        }
        else if ((tokenType == TOKEN_TIMESTAMP) || (tokenType == TOKEN_DATE) || (tokenType == TOKEN_NUMBER))
        {
            dataStream.writeVInt(token.toUInt64());
        }
        else if (tokenType == TOKEN_BLOB)
        {
            ASSERT(tokenData);
            dataStream.writeVInt(token.toUInt64());
            dataStream.writeVInt(tokenData.length());
            dataStream.writeBytes(tokenData);
        }
        else if (tokenType == TOKEN_KEYDATA)
        {
            ASSERT(tokenData);
            auto length = token.getFlagBits() * 16;
            dataStream.writeVInt(token.toUInt64());
            dataStream.writeBytes(tokenData);
        }
        else if (tokenType == TOKEN_LABEL)
        {
            dataStream.writeVInt(token.toUInt64());
        }
        else DBGBREAK();
    }

    static void write(BYTESTREAM& outStream, TOKEN contour, BUFFER contourData, TOKEN label, VL_SEPARATION separation = VS_REPEAT, VL_VISIBILITY visibility = VI_REPEAT)
    {
        UINT32 header = (UINT32(visibility) << ((!!separation) * 8)) | UINT8(separation);

        header = (header << 1) | UINT32(label ? 1 : 0);
        outStream.writeVInt(header);

        writeToken(outStream, contour, contourData);
        if (label) writeToken(outStream, label);
    }

    void write(BYTESTREAM& dataStream)
    {
        UINT32 header = (UINT32(visibility) << (bool(separation) * 8)) | UINT8(separation);

        header = (header << 1) | UINT32(label ? 1 : 0);
        dataStream.writeVInt(header);

        writeToken(dataStream, contour, contourBlob);
        if (label) writeToken(dataStream, label);
    }

    void parseToken(BUFFER inputData, TOKEN& token, BUFFER& tokenData)
    {
        token = TOKEN(inputData.readVInt());

        if (auto tokenType = token.getType(); tokenType == TOKEN_ID)
        {
            auto idBytes = inputData.readU128();
            token = ServiceTokens.createID(idBytes);
        }
        else if (tokenType == TOKEN_KEYDATA)
        {
            auto length = token.getFlagBits() * 16;
            tokenData = inputData.readBytes(length);
        }
        else if (tokenType == TOKEN_BLOB)
        {
            tokenData = inputData.readVData();
        }
    }

    static VLTOKEN parse(auto&& tokenData)
    {
        VLTOKEN token;

        UINT64 header = tokenData.readVInt();
        auto isLabel = (bool)BSHR(header, 1);

        token.visibility = VL_VISIBILITY(BSHR(header, 8));
        if (header)
        {
            token.separation = (VL_SEPARATION)(UINT8)token.visibility;
            token.visibility = (VL_VISIBILITY)BSHR(header, 8);
        }
        ASSERT(header == 0);

        token.parseToken(tokenData, token.contour, token.contourBlob);

        if (isLabel)
        {
            BUFFER blob;
            token.parseToken(tokenData, token.label, blob);
            ASSERT(!blob);
        }
        return token;
    }

    static VLTOKEN peek(BUFFER tokenData)
    {
        return parse(tokenData.clone());
    }

    bool isCloser(const VLTOKEN& other) const
    {
        auto thisSeparation = UINT8(separation);
        return thisSeparation > UINT8(other.separation);
    }

    explicit operator bool() const { return bool(contour); }
};

inline VLTOKEN VLToken;

struct VISUAL_DYANMIC
{
    VL_VISIBILITY visibility = VI_REPEAT;
    VL_SEPARATION separation = VS_REPEAT;

    VISUAL_DYANMIC moveCloser(UINT8 increment = 1) const
    {
        return { visibility, VL_SEPARATION(UINT8(separation) + increment) };
    }
};

template <typename STACK = SCHEDULER_STACK>
struct VLSTREAM
{
    BYTESTREAM dataStream;
    VISUAL_DYANMIC currentDynamic;

    VLSTREAM(VISUAL_DYANMIC dynamic, UINT32 initSize = 64 * 1024) : currentDynamic(dynamic)
    {
        dataStream.setAddress((PUINT8)StackAlloc<STACK>(initSize), initSize);
    }

    static VL_SEPARATION getBlockSeparation(UINT8 indent)
    {
        return VL_SEPARATION(UINT8(VS_BLOCK) + indent);
    }

    static VISUAL_DYANMIC moveCloser(VISUAL_DYANMIC dynamic, UINT8 increment = 1)
    {
        dynamic.separation =  VL_SEPARATION(UINT8(dynamic.separation) + increment);
        return dynamic;
    }

    void write(VISUAL_DYANMIC dynamic, TOKEN contour, BUFFER contourData = NULL_BUFFER, TOKEN label = Null)
    {
        auto visibility = currentDynamic.visibility == dynamic.visibility ? VI_REPEAT : dynamic.visibility;
        auto separation = currentDynamic.separation == dynamic.separation ? VS_REPEAT : dynamic.separation;

        currentDynamic = dynamic;

        VLToken.write(dataStream, contour, contourData, label, separation, visibility);
    }

    void insert(BUFFER data, UINT32 offset = 0)
    {
        dataStream.insert(0, data.length());
        dataStream.writeBytesAt(0, data);
    }

    auto toBuffer() { return dataStream.toBuffer(); }
};
using VISUAL_STREAM = VLSTREAM<>;

struct VLBUFFER
{
    BUFFER inputBuffer;
    VLBUFFER(BUFFER inputBuffer) : inputBuffer(inputBuffer) {}

    VISUAL_DYANMIC dynamic;

    VLTOKEN readToken()
    {
        auto token = VLToken.parse(inputBuffer);
        if (token.separation == VS_REPEAT)
            token.separation = dynamic.separation;
        else
            dynamic.separation = token.separation;

        if (token.visibility == VI_REPEAT)
            token.visibility = dynamic.visibility;
        else
            dynamic.visibility = token.visibility;

        return token;
    }

    VLTOKEN peekToken()
    {
        return VLToken.peek(inputBuffer);
    }

    VLTOKEN readIf(TOKENTYPE type)
    {
        auto result = VLTOKEN();
        
        if (auto token = peekToken(); token && token.contour.getType() == type)
        {
            result = readToken();
        }
        return result;
    }

    VLTOKEN readIfCloser(const VLTOKEN& first)
    {
        auto result = VLTOKEN();
        if (auto token = peekToken(); token && token.isCloser(first))
        {
            result = readToken();
        }
        return result;
    }

    auto readFragmentTokens()
    {
        DATASTREAM<VLTOKEN, SCHEDULER_STACK> tokenStream;
        tokenStream.reserve(32);

        if (auto firstToken = readToken())
        {
            tokenStream.append(firstToken);

            while (auto childToken = readIfCloser(firstToken))
            {
                tokenStream.append(childToken);
            }
        }
        return tokenStream.toBuffer();
    }

    auto readFragment()
    {
        auto fragmentStart = inputBuffer.savePosition();;
        if (auto firstToken = readToken())
        {
            while (auto childToken = readIfCloser(firstToken))
            {
                // do nothing.
            }
        }
        return VLBUFFER{ inputBuffer.diffPosition(fragmentStart) };
    }

    explicit operator bool() { return inputBuffer.length() > 0; }
};

#include "Dict.h"
#include "Parser.h"
#include "TLS.h"
#include "Crypto.h"
#include "TPM.h"
#include "X509.h"
#include "File.h"
#include "System.h"

constexpr UINT64 UnixToSystemTime(UINT64 unixTime)
{
    return unixTime + UnixTimeOrigin;
}

constexpr UINT64 SystemToUnixTime(UINT64 systemTime)
{
    return systemTime - UnixTimeOrigin;
}
