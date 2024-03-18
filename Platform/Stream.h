
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct CC_HEXMAP
{
	constexpr static UINT8 MAPCHARS1[] = "0123456789abcdef";
	constexpr static UINT8 MAPCHARS2[] = "0123456789ABCDEF";

	UINT8 data[64];
	constexpr CC_HEXMAP()
	{
		for (UINT32 i = 0; i < ARRAYSIZE(data); i++)
		{
			data[i] = 0xFF;
		}
		for (UINT32 i = 0; i < ARRAYSIZE(MAPCHARS1) - 1; i++)
		{
			data[MAPCHARS1[i] - '0'] = i;
		}
		for (UINT32 i = 0; i < ARRAYSIZE(MAPCHARS2) - 1; i++)
		{
			data[MAPCHARS2[i] - '0'] = i;
		}
	}

	constexpr UINT8 toNumber(UINT8 ch) const
	{
		UINT8 result = 0xFF;
		if (ch >= '0' && ch <= 'f')
		{
			result = data[ch - '0'];
		}
		return result;
	}

	constexpr bool isHexChar(UINT8 ch) const
	{
		return toNumber(ch) != 0xFF;
	}
};

constexpr CC_HEXMAP HEXMAP;

constexpr bool isHexChar(UINT8 c) {
	return HEXMAP.isHexChar(c);
}

constexpr bool isGuidChar(UINT8 c) {
	return isHexChar(c) || c == '-';
}

constexpr bool isMacAddressChar(UINT8 c) {
	return isHexChar(c) || c == ':';
}

constexpr UINT8 ToUpper(UINT8 ch) { return (ch >= 'a' && ch <= 'z') ? ch - 0x20 : ch; }
constexpr UINT8 ToLower(UINT8 ch) { return (ch >= 'A' && ch <= 'Z') ? ch + 0x20 : ch; }

template<typename T>
const T StreamRead(const UINT8* address, UINT32 &offset)
{
	UINT64 tmp = 0; // declared UNIT64 to ensure alignment
	ASSERT(sizeof(T) <= sizeof(tmp));

	RtlCopyMemory(&tmp, address, sizeof(T));

	offset += sizeof(T);
	return *(T *)&tmp;
}

template <typename T>
struct STREAM_READER;

template <typename T>
struct STREAM_ITER
{
	STREAM_READER<T> arr;
	int index;

	STREAM_ITER(STREAM_READER<T> arr, int index) : arr(arr), index(index) {};

	T& operator *() const
	{
		return arr.at(index);
	}

	auto operator ++()
	{
		index++;
		return *this;
	}

	bool operator != (STREAM_ITER &other) const
	{
		return index != other.index;
	}
};

constexpr UINT32 stringLen(const char* input)
{
	for (UINT32 i = 0; i < 512; i++)
	{
		if (input[i] == 0)
			return i;
	}
	DBGBREAK(); // validate
	return 0;
}

constexpr UINT8 ToHexNumber(UINT8 c)
{
	auto value = HEXMAP.toNumber(c);
	ASSERT(value != 0xFF);
	return value;
}

template <UINT32 SZ>
struct HEXSTRING
{
	UINT8 data[SZ/2];
	constexpr HEXSTRING(const char(&inData)[SZ])
	{
		for (UINT32 i = 0; i < SZ - 1; i += 2)
		{
			ASSERT(isHexChar(inData[i]) && isHexChar(inData[i + 1]));
			data[i >> 1] = ToHexNumber(inData[i]) << 4 | ToHexNumber(inData[i + 1]);
		}
	}
};

template <typename T>
struct STREAM_READER
{
	UINT32 _start;
	UINT32 _end;
	const void * _data;

	STREAM_READER(const T *array, UINT32 length) : _data(array), _end(length), _start(0) {}

	constexpr STREAM_READER(const char* array) : _data(array), _end(stringLen(array)), _start(0) { static_assert(sizeof(T) == 1); }
	STREAM_READER(const char* array, UINT32 length) : _data(array), _end(length), _start(0) { static_assert(sizeof(T) == 1); }

	template <UINT32 SZ>
	constexpr STREAM_READER(const T(&inData)[SZ]) : _data(&inData), _start(0), _end(SZ) {}

	template <UINT32 SZ>
	constexpr STREAM_READER(const HEXSTRING<SZ> &inData) : _data(inData.data), _start(0), _end(sizeof(inData.data)) {}

	STREAM_READER(const T* array, UINT32 offset, UINT32 end) : _data(array), _end(end), _start(offset)
	{
		ASSERT(end >= offset);
	}

	constexpr STREAM_READER() : _data(nullptr), _start(0), _end(0) {}

	STREAM_READER(const U128& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U256& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U512& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U1024& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const GUID& guid) : _data((PUINT8)&guid), _start(0), _end(sizeof(GUID)) {}

	STREAM_READER(const U128&& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U256&& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U512&& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const U1024&& value) : _data(value.u8), _start(0), _end(sizeof(value)) {}
	STREAM_READER(const GUID&& guid) : _data((PUINT8)&guid, _start(0), _end(sizeof(GUID))) {}

	STREAM_READER<T>& rewind()
	{
		_start = 0;
		return *this;
	}

	STREAM_READER<T> savePosition()
	{
		return { (T *)_data, _start, _start };
	}

	STREAM_READER<T> diffPosition(const STREAM_READER<T>& saved)
	{
		ASSERT(saved._data == _data);
		ASSERT(saved._start <= _start);
		return { (T*)_data, saved._start, _start };
	}

	UINT32 diffLength(const STREAM_READER<T>& saved)
	{
		ASSERT(saved._data == _data);
		ASSERT(saved._start <= _start);
		return _start - saved._start;
	}

	STREAM_READER<const UINT8> toBuffer() 
	{ 
		ASSERT(sizeof(T) == sizeof(UINT8));
		return STREAM_READER<const UINT8>((const PUINT8)data(), length()); 
	}

	STREAM_READER<const UINT8> toBuffer(UINT32 count) const
	{
		ASSERT(sizeof(T) == sizeof(UINT8));
		return STREAM_READER<const UINT8>((const PUINT8)data(), count);
	}

	STREAM_READER<UINT8> toRWBuffer() 
	{ 
		ASSERT(sizeof(T) == sizeof(UINT8));
		return STREAM_READER<UINT8>((PUINT8)data(), length());
	}

	void setLength(UINT32 length)
	{
		_end = _start + length;
	}

	constexpr UINT32 length() const { return _data != nullptr ? _end - _start : 0; }
	constexpr UINT32 bitLength() const { return length() * 8; }

	STREAM_ITER<T> begin() const
	{
		return STREAM_ITER<T>(*this, 0);
	}

	STREAM_ITER<T> end() const
	{
		return STREAM_ITER<T>(*this, length());
	}

	constexpr T *data(INT32 offset = 0) const
	{
		auto atOffset = (UINT32)(_start + offset);
		auto addr = (T*)_data;
		addr += atOffset;
		return ((addr >= _data) && (addr < (T*)_data + _end)) ? addr : nullptr;
	}

	const char* toString(UINT32 offset = 0) const
	{
		auto address = (const T*)_data;
		ASSERT(_start <= _end);
		auto bufEnd = address + _end;
		ASSERT(*bufEnd == 0);
		return (const char*)(address + _start + offset);
	}

	const wchar_t *toWideString()
	{
		auto bytes = length() * 2 + 2;
		auto wideString = (wchar_t *)StackAlloc<SCHEDULER_STACK>(bytes);

		for (UINT32 i = 0; i < length(); i++)
		{
			wideString[i] = at(i);
		}
		wideString[length()] = 0;

		return wideString;
	}

	PUNICODE_STRING toUnicodeString() const
	{
		auto allocBytes = length() * 2 + 2 + sizeof(UNICODE_STRING);
		auto unicodeString = (PUNICODE_STRING)TempAlloc(UINT32(allocBytes));
		auto wideString = (wchar_t*)&unicodeString[1];
		for (UINT32 i = 0; i < length(); i++)
		{
			wideString[i] = at(i);
		}
		wideString[length()] = 0;
		unicodeString->Length = UINT16(length() * 2);
		unicodeString->MaximumLength = UINT16(2 + length() * 2);
		unicodeString->Buffer = wideString;
		return unicodeString;
	}

	void shift(INT32 count = 1)
	{
		auto newStart = (INT32)_start + count;
		ASSERT(newStart >= 0 && newStart <= (INT32)_end);
		_start += count;
	}

	T& read()
	{
		auto newStart = (INT32)_start + 1;
		ASSERT(newStart >= 0 && newStart <= (INT32)_end);
		T& value = *data();
		_start += 1;
		return value;
	}

	bool tryShift(INT32 count = 1)
	{
		result = false;
		auto newStart = (INT32)_start + count;
		if (newStart >= 0 && newStart <= (INT32)_end)
		{
			_start += count;
			result = true;
		}
		return result;
	}

	STREAM_READER<T> shiftToEnd(UINT32 count = 0)
	{
		return readBytes(length() - count);
	}

	void shiftAbs(UINT32 count)
	{
		_start = count;
	}

	UINT32 mark()
	{
		return _start;
	}

	void restore(UINT32 mark)
	{
		ASSERT(mark <= _end);
		_start = mark;
	}

	INT32 getIndex(T& entry)
	{
		auto startAddr = (PUINT8)data();
		auto endAddr = (PUINT8)last();
		auto thisAddr = &entry;

		if (thisAddr >= startAddr && thisAddr <= endAddr)
		{
			return (thisAddr - startAddr) / sizeof(T);
		}
		return -1;
	}

	constexpr T& at(INT32 index) const
	{
		auto addr = data(index);
		ASSERT(addr != nullptr);
		return (T&)*addr;
	}

	T& peek() const
	{
		return at(0);
	}

	constexpr T& operator [] (INT32 index) const
	{
		return at(index);
	}

	STREAM_READER<T> read(UINT32 count)
	{
		ASSERT(_start <= _end);
		STREAM_READER<T> buffer{ (T*)_data, _start, _start + count };
		shift(count);
		return buffer;
	}

	STREAM_READER<T> readMax(UINT32 count)
	{
		count = min(count, length());
		return read(count);
	}

	STREAM_READER<T> readBytes(UINT32 count) { return read(count); }

	STREAM_READER<T> readBytesMax(UINT32 count) { return readMax(count); }

	STREAM_READER<T> revReadMax(UINT32 maxCount)
	{
		auto count = min(length(), maxCount);
		return { (T *)_data, _end - count, _end};
	}

	inline void readBytesTo(PUINT8 address, UINT32 count)
	{
		RtlCopyMemory(address, data(), count);
		shift(count);
	}

	STREAM_READER<T> peekBytes(UINT32 count)
	{
		auto prevStart = _start;
		count = min(length(), count);
		auto buffer = read(count);
		_start = prevStart;
		return buffer;
	}

	GUID readGuid()
	{
		ASSERT(length() >= sizeof(GUID));
		return readU128().toGuid();
	}

	UINT32 readIntBE(UINT32 byteCount)
	{
		UINT32 value = 0;
		for (UINT32 i = byteCount; i > 0; i--)
		{
			auto byte = readByte();
			value |= (byte << ((i - 1) * 8));
		}
		return value;
	}

	UINT8 readHexChar()
	{
		UINT8 number = 0;
		if (length() >= 2)
		{
			auto first = at(0);
			auto second = at(1);

			if (isHexChar(first) && isHexChar(second))
			{
				shift(2);

				number = ToHexNumber(first) << 4;
				number |= ToHexNumber(second);
			}
			else DBGBREAK();
		}
		else DBGBREAK();
		return number;
	}

	STREAM_READER<T> shrink(UINT32 count = 1)
	{
		ASSERT((_end - count) >= _start);

		auto address = data(length() - count);
		_end -= count;

		return { address, count };
	}

	void expand(UINT32 count)
	{
		_end += count;
	}

	T& last(INT32 count = 0) const
	{
		return at(length() - 1 - count);
	}

	template <typename F, typename ... Args>
	void forEach(F func, Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			auto value = data(i);
			auto toContinue = func(*value, args ...);
			if (toContinue == false)
				break;
		}
	}

	template <typename F, typename ... Args>
	void indexedForEach(F func, Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			auto value = data(i);
			auto toContinue = func(*value, i, args ...);
			if (toContinue == false)
				break;
		}
	}

	template<typename V>
	constexpr INT32 findIndex(V&& arg, UINT32 count = 0) const
	{
		if (count == 0) count = length();
		for (UINT32 i = 0; i < count; i++)
		{
			if (at(i) == arg)
			{
				return (INT32)i;
			}
		}
		return -1;
	}

	template<typename V>
	INT32 findIndexReverse(V&& arg) const
	{
		for (UINT32 i = length(); i > 0; i--)
		{
			if (at(i - 1) == arg)
			{
				return (INT32)(i - 1);
			}
		}
		return -1;
	}

	template <typename ... Args>
	T& find(Args && ... args) const
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			if (at(i).match(args ...))
			{
				return at(i);
			}
		}
		return NullRef<T>();
	}

	template<typename V>
	constexpr bool contains(V&& arg) const
	{
		return findIndex(arg) != -1;
	}

	template <typename V>
	const V read()
	{
		ASSERT((_start + sizeof(V)) <= _end);
		return StreamRead<V>(data(), _start);
	}
 
	const UINT8 readByte() { return read(); }

	UINT16 beReadU16()
	{
		auto val = read<UINT16>();
		return _byteswap_ushort(val);
	}

	UINT32 beReadU32()
	{
		auto val = read<UINT32>();
		return _byteswap_ulong(val);
	}

	UINT64 beReadU64()
	{
		auto val = read<UINT64>();
		return _byteswap_uint64(val);
	}

	UINT16 readU16()
	{
		return read<UINT16>();
	}

	INT16 readI16()
	{
		return read<INT16>();
	}

	inline UINT32 readU32()
	{
		return read<UINT32>();
	}

	UINT64 readU64()
	{
		return read<UINT64>();
	}

	U128& readU128()
	{
		return *(U128 *)readBytes(U128_BYTES).data();
	}

	const U256& readU256()
	{
		return *(U256*)readBytes(U256_BYTES).data();
	}

	UINT32 readBE24()
	{
		UINT32 i1 = readByte();
		UINT32 i2 = readByte();
		UINT32 i3 = readByte();

		return (i1 << 16) | (i2 << 8) | i3;
	}

	UINT64 readUIntBE(UINT32 length)
	{
		UINT64 value = 0;
		ASSERT(length() >= length);
		for (UINT32 i = 0; i < length; i++)
		{
			value = (value << 8) | readByte();
		}
		return value;
	}

	UINT64 readQInt()
	{
		UINT8 bytes[8] = { 0 };
		auto byteCount = 1 << (peek() >> 6);
		auto start = 8 - byteCount;

		copyTo(&bytes[start], byteCount);
		bytes[start] &= 0x3F;

		return _byteswap_uint64(*(UINT64*)bytes);
	}

	UINT64 readVInt()
	{
		UINT64 value = 0;
		auto byteCount = _lzcnt_u32(peek()) - 24 + 1;

		PUINT8 address = ((PUINT8)&value) + (8 - byteCount);
		copyTo(address, byteCount);

		address[0] &= (0xFF >> byteCount);
		return _byteswap_uint64(value);
	}

	STREAM_READER<T> readVData()
	{
		auto length = (UINT32)readVInt();
		return readBytes(length);
	}

	template <typename V>
	V readEnumBE()
	{
		ASSERT(_start <= _end);
		if constexpr (sizeof(V) == 1)
		{
			return (V)readByte();
		}
		else if constexpr (sizeof(V) == 2)
		{
			return (V)beReadU16();
		}
		else if constexpr (sizeof(V) == 4)
		{
			return (V)beReadU32();
		}
		else DBGBREAK();
		return V();
	}

	UINT32 copyTo(T * outBuffer, ULONG bufSize)
	{
		ASSERT(_start <= _end);
		auto transferLength = min(length(), bufSize);
		RtlCopyMemory((void *)outBuffer, data(), transferLength * sizeof(T));
		_start += transferLength;
		return transferLength;
	}

	STREAM_READER<T> toBuffer(UINT32 offset, UINT32 length)
	{
		return STREAM_READER<T>((T*)_data, _start + offset, _start + offset + length);
	}

	STREAM_READER<T> clone() const
	{
		return STREAM_READER<T>((T*)_data, _start, _end);
	}
	bool atEnd() const
	{
		return _start == _end;
	}

	constexpr explicit operator bool() const
	{
		return _data == nullptr || _start == _end ? false : true;
	}

	bool isEmpty() const
	{
		return length() == 0;
	}

	STREAM_READER<T> rebase()
	{
		NEW(*this, data(), length());
		return *this;
	}

	bool operator == (STREAM_READER<T> other) const
	{
		if (length() == other.length())
		{
			if (RtlCompareMemory(data(), other.data(), length()) == length())
			{
				return true;
			}
		}
		return false;
	}

	bool operator != (STREAM_READER<T> other) const
	{
		return !(*this == other);
	}

	char* p()
	{
		return (char*)data();
	}

	char *print()
	{
		for (UINT32 i = 0; i < length(); i++)
		{
			printf("%c", at(i));
		}
		return (char*)data();
	}
};

using USTRING = STREAM_READER<const UINT8>;
using BUFFER = STREAM_READER<const UINT8>;
using RWBUFFER = STREAM_READER<UINT8>;
using TOKENBUFFER = STREAM_READER<const TOKEN>;
using STRINGBUFFER = STREAM_READER<const USTRING>;

constexpr USTRING HexChars = "0123456789ABCDEF";
constexpr USTRING CRLF = "\r\n";
constexpr USTRING ESC_CRLF = "\\r\\n";
constexpr USTRING CRLF_CRLF = "\r\n\r\n";
constexpr USTRING WHITESPACE = " \t\r\n";

constexpr UINT8 _ZeroBytesData[4096] = { 0 };
constexpr BUFFER ZeroBytes = _ZeroBytesData;
extern BUFFER OneBits;

constexpr USTRING Spaces = "                                                                                                       ";;

int NameToString(TOKEN handle, UINT8 *stringBuffer);

constexpr BUFFER Base64Chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
inline UINT8 Base64Index[128];

template <UINT32 SZ = 0>
struct TBYTESTREAM
{
	PUINT8 data;
	UINT32 _tail = 0;
	UINT8 _storage[SZ+4];

	auto& _size() const { return *(UINT32*)_storage; }

	void setAddress(PUINT8 address, UINT32 inSize)
	{
		data = address;
		_size() = inSize;
	}

	void reset(PUINT8 address, UINT32 inSize)
	{
		data = address;
		_size() = inSize;
		_tail = 0;
	}

	TBYTESTREAM()
	{
		reset(SZ ? &_storage[4] : nullptr, SZ);
		memset(data, 0, _size());
	}

	TBYTESTREAM& clear()
	{
		memset(data, 0, _size());
		_tail = 0;
		return *this;
	}

	TBYTESTREAM(TBYTESTREAM& other) = delete;

	template <UINT32 SIZE>
	TBYTESTREAM(UINT8(&inData)[SIZE])
	{
		reset(inData, SIZE);
	}

	TBYTESTREAM(PUINT8 address, UINT32 inSize)
	{
		reset(address, inSize);
	}

	TBYTESTREAM(TBYTESTREAM&& other) { reset(other.address(), other.size()); }
	TBYTESTREAM(U96& value) : TBYTESTREAM(value.u8) {} // { setAddress(value.u8, sizeof(value.u8)); }
	TBYTESTREAM(U128& value) : TBYTESTREAM(value.u8) {} //  { setAddress(value.u8, sizeof(value.u8)); }
	TBYTESTREAM(U256& value) : TBYTESTREAM(value.u8) {} //  { setAddress(value.u8, sizeof(value.u8)); }
	TBYTESTREAM(U256&& value) : TBYTESTREAM(value.u8) {} //  { setAddress(value.u8, sizeof(value.u8)); }
	TBYTESTREAM(U512& value) : TBYTESTREAM(value.u8) {} //  { setAddress(value.u8, sizeof(value.u8)); }
	TBYTESTREAM(U1024& value) : TBYTESTREAM(value.u8) {} //  { setAddress(value.u8, sizeof(value.u8)); }

	void fromBuffer(BUFFER otherData)
	{
		reset((PUINT8)otherData.data(), otherData.length());
		_tail = otherData.length();
	}

	TBYTESTREAM<0>& byteStream()
	{
		return *(TBYTESTREAM<0> *)this;
	}

	void setCount(UINT32 count) { _tail = count; }

	void shrink(UINT32 count)
	{
		ASSERT(_tail >= count);
		_tail -= count;
	}

	UINT32& setCount() { return _tail; }

	inline UINT32 size() { return _size(); }

	inline PUINT8 end() const
	{
		return &data[_tail];
	}

	UINT8& last(UINT32 offset = 0)
	{
		ASSERT(_tail > offset);
		return at(_tail - 1 - offset);
	}

	inline UINT32 mark()
	{
		return _tail;
	}

	void restore(UINT32 mark)
	{
		ASSERT(mark <= _tail);
		_tail = mark;
	}

	void resize(UINT32 newSize)
	{
		ASSERT(newSize <= _size());
		ASSERT(_tail == 0);
		_size() = newSize;
	}

	UINT8& at(UINT32 offset)
	{
		return *address(offset);
	}

	PUINT8 address(UINT32 offset = 0)
	{
		return &data[offset];
	}

	void reserve(UINT32 count)
	{
		ASSERT(count <= spaceLeft());
	}

	template <typename STACK>
	void allocReserve(UINT32 reserveSize, UINT32 expandScale = 2)
	{
		if (spaceLeft() < reserveSize)
		{
			auto newSize = max(size() * expandScale, reserveSize + count());
			auto newAddress = (PUINT8)StackAlloc<STACK>(newSize);
			RtlCopyMemory(newAddress, address(), count());
			data = newAddress;
			_size() = newSize;
		}
	}

	void tempAlloc(UINT32 size)
	{
		allocReserve<SCHEDULER_STACK>(size);
	}

	inline PUINT8 commit(UINT32 len)
	{
		auto addr = end();
		_tail += len;
		ASSERT(_tail <= _size());
		return addr;
	}

	inline PUINT8 commitAll() { return commit(spaceLeft()); }

	TBYTESTREAM<0> commitTo(UINT32 len)
	{
		auto address = commit(len);
		return TBYTESTREAM<0>{ address, len };
	}

	TBYTESTREAM<0> insert(UINT32 at, UINT32 count = 1)
	{
		reserve(count);
		auto from = address(at);
		auto to = address(at + count);
		auto bytes = _tail - at;

		memmove(to, from, bytes);
		_tail += count;

		return TBYTESTREAM<0>{ from, count };
	}

	void remove(UINT32 from, UINT32 removeCount = 1)
	{
		if (from == 0 && removeCount == count())
		{
			clear();
		}
		else
		{
			auto moveFrom = from + removeCount;
			if (moveFrom < count())
			{
				auto moveCount = count() - moveFrom;
				RtlMoveMemory(address(from), address(moveFrom), moveCount);
			}
		}
	}

	UINT32 spaceLeft() const
	{
		return _size() - _tail;
	}

	UINT32 count() const
	{
		return _tail;
	}

	TBYTESTREAM<0> subStream(UINT32 offset)
	{
		return { address(offset), size() - offset };
	}

	void writeByte(UINT8 ch)
	{
		*commit(1) = ch;
	}

	void writeHexString(BUFFER hexString)
	{
		while (hexString)
		{
			if (hexString.length() >= 2)
			{
				auto first = hexString.at(0);
				auto second = hexString.at(1);
				if (isHexChar(first) && isHexChar(second))
				{
					auto hexByte = (ToHexNumber(first) << 4) | ToHexNumber(second);
					writeByte(hexByte);
					hexString.shift(2);
				}
				else break;

			}
			else break;
		}
	}

	void writeBytes(const UINT8 * address, const UINT32 len)
	{
		memcpy(commit(len), address, len);
	}

	void writeBytes(BUFFER buffer)
	{
		if (buffer.length() > 0)
			writeBytes(buffer.data(), buffer.length());
	}

	BUFFER writeBytesTo(BUFFER buffer)
	{
		auto offset = mark();
		if (buffer.length() > 0)
			writeBytes(buffer.data(), buffer.length());
		return toBuffer(offset);
	}

	void writeBytes(BUFFER buffer, UINT32 len)
	{
		if (len > 0)
			writeBytes(buffer.data(), len);
	}

	template <typename STACK>
	void expandWriteBytes(BUFFER buffer, UINT32 expandScale = 4)
	{
		allocReserve<STACK>(buffer.length(), expandScale);
		writeBytes(buffer);
	}

	void writeSessionBytes(BUFFER bytes, UINT32 expandScale = 2)
	{
		expandWriteBytes<SESSION_STACK>(bytes, expandScale);
	}

	template <UINT32 SZ2>
	void writeStream(TBYTESTREAM<SZ2>& other)
	{
		writeBytes((const PUINT8)other.address(), other.count());
	}

	STREAM_READER<const UINT8> clone(BUFFER input)
	{
		auto&& offset = getPosition();
		writeBytes(input);
		return offset.toBuffer();
	}

	void encodeBase64(BUFFER inputBuffer)
	{
		auto inputBufferLength = inputBuffer.length();

		auto reminder = inputBufferLength % 3;
		auto fullCount = inputBufferLength - reminder;
		auto byteCount = (fullCount / 3) * 4 + (reminder ? 4 : 0);

		auto&& subStream = commitTo(byteCount);

		for (UINT32 i = 0; i < fullCount; i += 3)
		{
			UINT32 data = inputBuffer[i] << 16 | inputBuffer[i + 1] << 8 | inputBuffer[i + 2];
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte(Base64Chars[((data & 0x000FC0) >> 6)]);
			subStream.writeByte(Base64Chars[(data & 0x00003F)]);
		}

		if (reminder == 2)
		{
			UINT32 data = inputBuffer[fullCount] << 16 | inputBuffer[fullCount + 1] << 8;
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte(Base64Chars[((data & 0x000FC0) >> 6)]);
			subStream.writeByte('=');
		}
		else if (reminder == 1)
		{
			UINT32 data = inputBuffer[fullCount] << 16;
			subStream.writeByte(Base64Chars[((data & 0xFC0000) >> 18)]);
			subStream.writeByte(Base64Chars[((data & 0x03F000) >> 12)]);
			subStream.writeByte('=');
			subStream.writeByte('=');
		}
	}

	void writeUtf8(UINT32 c)
	{
		if (c <= 0x7F)
		{
			writeByte((UINT8)(c & 0x7F));
		}
		else if (c >= 0x80 && c <= 0x7FF)
		{
			writeByte((UINT8)(0xC0 | (c & 0x7C0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
		else if (c > 0x7FF && c < 0xFFFF)
		{
			writeByte((UINT8)(0xE0 | (c & 0xF000) >> 12));
			writeByte((UINT8)(0x80 | (c & 0x0FC0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
		else if (c >= 0xFFFF)
		{
			DBGBREAK();
			writeByte((UINT8)(0xF0 | (c & 0x1C0000) >> 18));
			writeByte((UINT8)(0x80 | (c & 0x3F000) >> 12));
			writeByte((UINT8)(0x80 | (c & 0x0FC0) >> 6));
			writeByte((UINT8)(0x80 | (c & 0x3F)));
		}
	}

	UINT8 base64Index(UINT8 base64Char)
	{
		return base64Char == '=' ? 0 : Base64Index[base64Char];
	}

	void decodeBase64(BUFFER base64String)
	{
		reserve(base64String.length());
		for (UINT32 i = 0; i < base64String.length(); i += 4)
		{
			UINT32 data = (base64Index(base64String[i]) << 18) | (base64Index(base64String[i + 1]) << 12) | (base64Index(base64String[i + 2]) << 6) | base64Index(base64String[i + 3]);

			writeByte((UINT8)((data & 0xFF0000) >> 16));
			writeByte((UINT8)((data & 0xFF00) >> 8));
			writeByte((UINT8)(data & 0xFF));

			if (base64String[i + 2] == '=' && base64String[i + 3] == '=')
			{
				trim(2);
			}
			else if (base64String[i + 3] == '=')
			{
				trim(1);
			}
		}
	}



	void beWriteU64(const UINT64 value)
	{
		*(UINT64*)commit(sizeof(value)) = _byteswap_uint64(value);
	}

	void beWriteU32(const UINT32 value)
	{
		*(UINT32*)commit(sizeof(value)) = _byteswap_ulong(value);
	}

	void beWriteU16(const UINT16 value)
	{
		*(UINT16*)commit(sizeof(value)) = _byteswap_ushort(value);
	}

	void beWriteAtU64(const UINT32 offset, const UINT64 value)
	{
		*(UINT64*)&data[offset] = _byteswap_uint64(value);
	}

	void beWriteAtU32(const UINT32 offset, const UINT32 value)
	{
		*(UINT32*)&data[offset] = _byteswap_ulong(value);
	}

	void beWriteAtU16(const UINT32 offset, const UINT16 value)
	{
		*(UINT16*)&data[offset] = _byteswap_ushort(value);
	}

	void writeByteAt(const UINT32 offset, const UINT8 value)
	{
		data[offset] = value;
	}

	template <typename V>
	void writeInt(V value)
	{
		*(V*)commit(sizeof(value)) = value;
	}

	template <typename V>
	void writeEnumBE(V value)
	{
		UINT32 size = sizeof(V);
		if (size == 1)
		{
			writeByte((UINT8)value);
		}
		else if (size == 2)
		{
			beWriteU16(UINT16(value));
		}
		else if (size == 4)
		{
			beWriteU32(UINT32(value));
		}
		else
		{
			DBGBREAK();
			return;
		}
	}

	template <typename V>
	void writeAt(UINT32 at, V value)
	{
		*(V*)&data[at] = value;
	}

	void writeBytesAt(UINT32 at, BUFFER value)
	{
		RtlCopyMemory(&data[at], value.data(), value.length());
	}

	void writeU128(const U128& val)
	{
		memcpy(commit(sizeof(val)), val.u8, sizeof(val));
	}

	void writeU256(const U256& val)
	{
		memcpy(commit(sizeof(val)), val.u8, sizeof(val));
	}

	void trim(UINT32 count = 1)
	{
		_tail -= count;
	}

	void expand(UINT32 count)
	{
		_tail += count;
	}

	void writeName(TOKEN name)
	{
		ASSERT(name.isString());
		auto nameString = GetName(name);
		RtlCopyMemory(commit(nameString.length()), nameString.data(), nameString.length());
		*end() = 0;
	}

	void writeHexString(const UINT8* inputData, UINT32 inputLength)
	{
		auto&& subStream = commitTo(inputLength * 2);
		for (UINT32 i = 0; i < inputLength; i++)
		{
			auto c = inputData[i];
			subStream.writeByte(HexChars[(c & 0xF0) >> 4]);
			subStream.writeByte(HexChars[c & 0x0F]);
		}
	}

	void writeString(BUFFER string)
	{
		writeBytes(string);
	}

	BUFFER writeString(TBYTESTREAM<0>& other)
	{
		auto offset = mark();
		writeBytes(other.toBuffer());
		return toBuffer(offset);
	}

	void writeString(TOKEN handle)
	{
		if (handle.isString())
		{
			writeName(handle);
		}
		else if (handle.isId())
		{
			DBGBREAK();
			auto value = TokenGetID(handle);
			writeHexString(value.u8, sizeof(value));
		}
		else if (handle.isNumber())
		{
			DBGBREAK();
			writeString(Tokens.getNumber(handle));
		}
		else if (handle.isBlob())
		{
			DBGBREAK();
		}
		else if (handle == Undefined)
		{
			writeBytes("undefined");
		}
		else if (handle == True)
		{
			writeBytes("true");
		}
		else if (handle == False)
		{
			writeBytes("false");
		}
		else if (handle == Undefined)
		{
			writeBytes("null");
		}
		else if (handle == Nan)
		{
			writeBytes("nan");
		}
		else DBGBREAK();
	}
	
	void writeHex(UINT8 letter)
	{
		reserve(3);
		writeByte(HexChars[(letter & 0xF0) >> 4]);
		writeByte(HexChars[letter & 0x0F]);
	}

	void writeHex(UINT32 value)
	{
		reserve(9);
		writeHex(UINT8(_pext_u32(value, 0xFF000000)));
		writeHex(UINT8(_pext_u32(value, 0xFF0000)));
		writeHex(UINT8(_pext_u32(value, 0xFF00)));
		writeHex(UINT8(_pext_u32(value, 0xFF)));
	}

	static BUFFER writeNumber(RWBUFFER buffer, UINT64 number, UINT32 base)
	{
		for (UINT32 i = buffer.length(); i > 0; i--)
		{
			buffer.at(i - 1) = HexChars[number % base];
			number /= base;
		}
		return buffer.toBuffer();
	}

	BUFFER _writeNumber(UINT64 number, UINT32 base = 10, UINT32 width = 0)
	{
		if (width == 0)
		{
			width = number ? (base == 16) ? NIBBLECOUNT(number) : 1 + UINT32(log10(double(number))) : 1;
		}
		RWBUFFER buffer{ commit(width), width };
		return writeNumber(buffer, number, base);
	}

	BUFFER writeString(UINT32 number)
	{
		return _writeNumber((UINT64)number, 10, 0);
	}

	BUFFER writeGuid(U128 id)
	{
		auto position = count();
		_writeNumber(_byteswap_ulong(id.u32[0]), 16, 8);
		writeByte('-');
		_writeNumber(_byteswap_ulong(id.u32[1]), 16, 8);
		writeByte('-');
		_writeNumber(_byteswap_ulong(id.u32[2]), 16, 8);
		writeByte('-');
		_writeNumber(_byteswap_ulong(id.u32[3]), 16, 8);
		return toBuffer(position);
	}

	BUFFER writeString(UINT64 number)
	{
		return _writeNumber(number, 10, 0);
	}

	BUFFER writeHexString(UINT64 number, UINT32 width = 0)
	{
		return _writeNumber(number, 16, width);
	}

	BUFFER writeString(UINT64 number, UINT32 width)
	{
		return _writeNumber(number, 10, width);
	}

	BUFFER writeString(INT64 number)
	{
		auto position = count();
		if (number == 0)
		{
			writeByte('0');
		}
		else
		{
			reserve(20);
			if (number < 0)
			{
				writeByte('-');
				number *= -1;
			}
			_writeNumber((UINT64)number, 10, 0);
		}
		*end() = 0;
		return toBuffer(position);
	}

	BUFFER writeString(INT32 number)
	{
		return _writeNumber((INT64)number, 10, 0);
	}

	BUFFER writeMany(auto&& ... args)
	{
		auto start = count();
		int dummy[] = { (writeString(args), 0) ... }; dummy;
		return toBuffer(start);
	}

	void writeQInt(UINT64 value)
	{
		if (value < (1ull << 6))
		{
			writeByte(UINT8(value));
		}
		else if (value < (1ull << 14))
		{
			beWriteU16(UINT16(value) | (UINT16(1) << 14));
		}
		else if (value < (1ull << 30))
		{
			beWriteU32(UINT32(value) | (UINT32(2) << 30));
		}
		else if (value < (1ull << 62))
		{
			beWriteU64(value | 3ull << 62);
		}
		else DBGBREAK();
	}

	void writeVInt(UINT64 value)
	{
		auto bitCount = 64 - _lzcnt_u64(value);
		auto byteCount = (UINT8)(ROUND8(1 + bitCount + (bitCount / 8)) / 8);
		ASSERT(byteCount <= 8);

		value = _byteswap_uint64(value);
		auto address = ((PUINT8)&value) + (8 - byteCount);

		address[0] |= (0x80 >> (byteCount - 1));
		writeBytes(address, byteCount);
	}

	void writeVData(BUFFER data)
	{
		writeVInt(data.length());
		writeBytes(data);
	}

	struct OFFSET
	{
		TBYTESTREAM& stream;
		UINT32 offset;
		UINT8 lengthType;
		bool lengthWritten = false;

		OFFSET() :stream(NullRef<TBYTESTREAM>()), lengthWritten(true) {}
		OFFSET(UINT8 type, TBYTESTREAM& bufferArg) : stream(bufferArg), lengthType(type)
		{
			offset = stream.count();
			for (UINT32 i = 0; i < lengthType; i++)
			{
				stream.writeByte(0);
			}
		}

		explicit operator bool() const { return lengthWritten == false; }

		void writeLength(INT32 adjustLength = 0)
		{
			auto length = (UINT32)(stream.count() - offset - lengthType);
			if (lengthType > 0)
			{
				lengthWritten = true;
				length += adjustLength;
				if (lengthType == 2)
				{
					stream.beWriteAtU16(offset, (UINT16)length);
				}
				else if (lengthType == 3)
				{ // for TLS
					length = SWAP32(length);
					stream.writeBytes(PUINT8(&length) + 1, 3);
				}
				else if (lengthType == 1)
				{
					stream.writeAt(offset, (UINT8)(length & 0xFF));
				}
				else if (lengthType == 4)
				{
					stream.beWriteAtU32(offset, (UINT32)length);
				}
				else DBGBREAK();
			}
			else DBGBREAK();
		}

		UINT32 getLength()
		{
			if (lengthWritten)
				return 0;

			return (UINT32)(stream.count() - offset - lengthType);
		}

		UINT32 writeQLength()
		{
			return writeQLength(getLength());
		}

		UINT32 writeQLength(UINT32 length)
		{
			ASSERT(lengthType == 1 || lengthType == 2 || lengthType == 4);
			ASSERT(lengthWritten == false);

			lengthWritten = true;
			if (lengthType == 2)
			{
				ASSERT(length < (1ull << 14));
				stream.beWriteAtU16(offset, UINT16(length) | (UINT16(1) << 14));
			}
			else if (lengthType == 4)
			{
				ASSERT(length < (1ull << 30));
				stream.beWriteAtU32(offset, UINT32(length) | (UINT32(2) << 30));
			}
			else if (lengthType == 1)
			{
				ASSERT(length < (1ull << 6));
				stream.writeAt(offset, UINT8(length));
			}
			else DBGBREAK();
			return length;
		}

		UINT32 writeASNlength()
		{
			ASSERT(!lengthWritten);
			auto length = getLength();
			if (length < 0x80)
			{
				stream.writeByteAt(offset, UINT8(length));
			}
			else
			{
				auto byteCount = BYTECOUNT(length);
				stream.writeByteAt(offset, 0x80 | byteCount);

				auto newOffset = offset + 1;
				stream.insert(newOffset, byteCount);
				for (UINT32 i = byteCount; i > 0; i--)
				{
					stream.writeByteAt(newOffset++, UINT8(length >> ((i - 1) * 8)));
				}
			}
			lengthWritten = true;
			return length;
		}

		BUFFER toBuffer()
		{
			return { stream.address(offset), stream.count() - offset - lengthType };
		}
	};

	OFFSET saveOffset(UINT32 intSize)
	{
		return OFFSET(intSize, *this);
	}

	void saveOffset(UINT32 intSize, OFFSET& savedPosition)
	{
		NEW(savedPosition, intSize, *this);
	}

	OFFSET getPosition()
	{
		auto offset = OFFSET(0, *this);
		offset.lengthWritten = true;
		return offset;
	}

	BUFFER toBuffer(UINT32 start = 0) const
	{
		ASSERT(start <= _tail);
		return BUFFER{ data, start, _tail };
	}

	RWBUFFER toRWBuffer(UINT32 start = 0)
	{
		ASSERT(start <= _tail);
		return RWBUFFER{ data, start, _tail};
	}

	BUFFER toBuffer(UINT32 start, UINT32 count)
	{
		ASSERT(start + count <= _tail);
		return BUFFER{ data, start, start + count };
	}

	RWBUFFER toRWBuffer(UINT32 start, UINT32 count)
	{
		ASSERT(start + count <= _tail);
		return RWBUFFER{ data, start, start + count };
	}

	BUFFER toMaxBuffer()
	{
		return BUFFER{ data, 0, _size() };
	}

	constexpr explicit operator bool() const
	{
		return _tail > 0;
	}

	//TBYTESTREAM& operator = (const TBYTESTREAM&& other) 
	//{ 
	//	ASSERT(other.count() == 0); 
	//	setAddress(other.end(), other.spaceLeft()); 
	//	return *this; 
	//}
};

using BYTESTREAM = TBYTESTREAM<>;

VARGS(BUFFER)
inline BUFFER WriteMany(ARGS&& ... args)
{
	BUFFER inputBuffers[] = { args ... };
	UINT32 sizeTotal = 1;
	for (UINT32 i = 0; i < ARRAYSIZE(inputBuffers); i++)
	{
		sizeTotal += inputBuffers[i].length();
	}
	auto&& outStream = ByteStream(sizeTotal);
	return outStream.writeMany(args ...);
}

template <typename T, typename STACK, UINT32 INIT=8, UINT32 INCR=8>
struct DATASTREAM
{
	T* _data = nullptr;
	UINT32 _tail = 0;
	UINT32 _size = 0;

	template <UINT32 SZ>
	DATASTREAM(T(&data)[SZ])
	{
		_data = data;
		_size = SZ;
	}

	DATASTREAM() : _tail(0) { ASSERT((bool(_data) ^ bool(_size)) == false); }  // construct or reset
	DATASTREAM(T* addr, UINT32 size) : _data(addr), _size(size) {}
	DATASTREAM(DATASTREAM& other) = delete;

	UINT32 count() { return _tail; }
	T* data(UINT32 index = 0) const { return &_data[index]; }
	T& at(UINT32 index) const { ASSERT(index < _tail); return _data[index]; }

	void reserve(UINT32 add = 1)
	{
		add = max(_tail + add, INIT);
		if (add > _size)
		{
			_size = (UINT32)ROUNDTO(add, INCR);
			auto newData = (T *)StackAlloc<STACK>(UINT32(sizeof(T) * _size));
			RtlCopyMemory(newData, _data, sizeof(T) * _tail);
			_data = newData;
		}
	}

	auto spaceLeft() { return _size - _tail; }

	T& last(UINT32 offset = 0) 
	{
		ASSERT(_tail > offset);
		return at(_tail - 1 - offset); 
	}

	T* end() { return &_data[_tail]; }

	T& append(auto&& ... args)
	{
		if (_tail >= _size)
			reserve();

		auto addr = &_data[_tail++];
		new (addr) T(args ...);

		return *addr;
	}

	DATASTREAM& clear()
	{
		_tail = 0;
		return *this;
	}

	DATASTREAM<T, THREAD_STACK> commit(UINT32 count, auto&& ... args)
	{
		auto addr = end();
		for (UINT32 i = 0; i < count; i++)
		{
			append(args ...);
		}
		return { addr, count };
	}

	T& insert(UINT32 position, UINT32 count = 1)
	{
		if (position == _tail)
		{
			return *commit(count);
		}
		else
		{
			ASSERT(position < _tail);
			commit(count);
			auto from = data(position);
			auto to = from + count;
			auto bytes = sizeof(T) * (_tail - position - count);

			RtlMoveMemory(to, from, bytes);
			return at(position);
		}
	}

	template<typename ... ARGS>
	void writeAt(UINT32 offset, ARGS&& ... args)
	{
		if (offset == _tail)
		{
			append(args ...);
		}
		else
		{
			auto newEntry = insert(offset);
			new (&newEntry) T(args ...);
		}
	}

	void remove(UINT32 position, UINT32 count = 1)
	{
		if (position + count == _tail)
		{
			shrink(count);
		}
		else
		{
			ASSERT(position < _tail);
			auto to = data(position);
			auto from = to + count;
			auto bytes = sizeof(T) * (_tail - (position + count));
			RtlMoveMemory(to, from, bytes);

			_tail -= count;
		}
	}

	void shrink(UINT32 count = 1)
	{
		if (_tail >= count)
			_tail -= count;
	}

	STREAM_READER<const T> toBuffer(UINT32 offset = 0) const
	{
		return STREAM_READER<const T>((const T*)_data, offset, _tail);
	}

	STREAM_READER<T> toRWBuffer(UINT32 offset = 0) const
	{
		return STREAM_READER<T>(_data, offset, _tail);
	}

	STREAM_READER<const T> toBuffer(UINT32 start, UINT32 count)
	{
		ASSERT(start + count <= _tail);
		return STREAM_READER<const T>(_data, start, start + count);
	}

	STREAM_READER<T> toRWBuffer(UINT32 start, UINT32 count)
	{
		ASSERT(start + count <= _tail);
		return STREAM_READER<T>(_data, start, start + count);
	}

	void writeBuffer(STREAM_READER<const T> buffer)
	{
		for (UINT32 i = 0; i < buffer.length(); i++)
		{
			append(buffer.at(i));
		}
	}
	UINT32 getIndex(const T& current) const
	{
		return UINT32(&current - _data);
	}

	void trim(UINT32 trimCount = 1)
	{
		ASSERT(_tail >= trimCount);
		_tail -= trimCount;
	}

	UINT32 size() { return _size; }

	STREAM_READER<T> clone()
	{
		auto address = (T*)TempAlloc(sizeof(T) * count());
		RtlCopyMemory(address, data(), sizeof(T) * count());
		return STREAM_READER<T>(address, count());
	}
};

constexpr USTRING NULL_STRING = USTRING();
constexpr BUFFER NULL_BUFFER = BUFFER();
constexpr RWBUFFER NULL_RWBUFFER = RWBUFFER();

constexpr UINT8 Utf8PrefixData[] = { 0xEF, 0xBB, 0xBF };
constexpr USTRING Utf8Prefix = Utf8PrefixData;

template <typename T, typename STACK, UINT32 BLKSZ>
struct STREAMPOOL
{
	using SBLOCK = DATASTREAM<T, STACK, BLKSZ, 0>;
	DATASTREAM<SBLOCK, STACK, 16> blockStream;

	void addBlock()
	{
		auto memory = (T *)StackAlloc<STACK>(sizeof(T) * BLKSZ);
		blockStream.append(memory, BLKSZ);
	}

	T& append(auto&& ... args)
	{
		if (blockStream.count() == 0 || blockStream.last().spaceLeft() == 0)
		{
			addBlock();
		}
		auto&& block = blockStream.last();
		return block.append(args ...);
	}

	STREAM_READER<T *> toBuffer()
	{
		DATASTREAM<T*, SCHEDULER_STACK> itemStream;
		itemStream.reserve(blockStream.count() * BLKSZ);
		for (UINT32 i = 0; i < blockStream.count(); i++)
		{
			auto&& block = blockStream.at(i);
			for (UINT32 j = 0; j < block.count(); j++)
			{
				itemStream.append(&block.at(i));
			}
		}
		return itemStream.toBuffer();
	}
};
