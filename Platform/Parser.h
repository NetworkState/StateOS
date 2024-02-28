
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once


constexpr USTRING RFC_DATE_SEPARATOR = ", \t:;";
constexpr USTRING DATE_SEPARATOR = "/ \t:.";

constexpr GUID NULL_GUID = { 0, 0, 0, {0} };

constexpr UINT8 GetCharInverse(UINT8 first)
{
    return first == '"' ? '"' :
        first == '\'' ? '\'' :
        first == '(' ? ')' :
        first == '[' ? ']' :
        first == '<' ? '>' :
        first == '/' ? '/' :
        first == '{' ? '}' : 0;
}

constexpr bool IsWhitespace(UINT8 input)
{
    return WHITESPACE.contains(input);
}

struct URL_INFO
{
    TOKEN hostname = Undefined;
    TOKEN protocol = Undefined;
    TOKEN path = Undefined;
    UINT32 port = TLS_PORT;

    TOKEN username;
    TOKEN password;

    void clear()
    {
        hostname = protocol = path = Null;
        port = TLS_PORT;
    }

    bool operator == (URL_INFO& other)
    {
        UNREFERENCED_PARAMETER(other);
        auto result = other.hostname == hostname && other.protocol == this->protocol
            && other.path == path && other.port == port;
        return result;
    }

    URL_INFO(const URL_INFO & other)
    {
        this->hostname = other.hostname;
        this->protocol = other.protocol;
        this->path = other.path;
        this->port = other.port;
    }

    URL_INFO() {}
};

constexpr UINT32 GUID_STRING_LENGTH = 36;
constexpr UINT32 MACADDRESS_STRING_LENGTH = 17;

struct STRINGOPS
{
    bool isGuidString(USTRING text)
    {
        auto result = false;
        if (text.length() == GUID_STRING_LENGTH)
        {
            result = true;
            for (UINT32 i = 0; i < text.length(); i++)
            {
                if (isGuidChar(text.at(i)) == false)
                {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    template <typename STR>
    USTRING splitString(STR&& input, USTRING pattern)
    {
        auto match = input;
        auto start = input.data();

        while (input)
        {
            if (input.length() >= pattern.length() && memcmp(input.data(), pattern.data(), pattern.length()) == 0)
            {
                match._end = match._start + (UINT32)(input.data() - start);
                input.shift(pattern.length());
                break;
            }
            input.shift();
        }
        return match;
    }

    USTRING splitStringIf(USTRING& input, USTRING pattern)
    {
        auto originalString = input;
        auto subString = splitString(input, pattern);

        if (subString == originalString)
        {
            input = originalString;
            subString = NULL_STRING;
        }
        return subString;
    }

    bool contains(USTRING input, USTRING pattern)
    {
        return splitStringIf(input, pattern).length() > 0;
    }

    template <typename STREAM>
    STREAM_READER<USTRING> splitStringToArray(USTRING& input, USTRING pattern, STREAM&& stream)
    {
        while (auto part = splitString(input, pattern))
        {
            stream.append(part);
        }
        return stream.toReader();
    }

    USTRING splitChar(USTRING& inputText, UINT8 separator)
    {
        if (inputText.length() == 0)
        {
            return USTRING();
        }

        auto result = USTRING();

        auto position = inputText.findIndex(separator); // FindChar(inputText, separator);
        ASSERT(position != 0); // separator is the first char, what to do?
        if (position > 0)
        {
            result = USTRING(inputText.data(), position);
            trim(result);
            inputText.shift(position + 1);
        }
        else
        {
            result = inputText;
            inputText.shift(inputText.length());
        }

        return result;
    }

    USTRING splitCharIf(USTRING& inputText, UINT8 separator, UINT32 maxLength = 0)
    {
        if (inputText.length() == 0)
        {
            return USTRING();
        }

        auto result = USTRING();

        auto position = inputText.findIndex(separator, maxLength); // FindChar(inputText, separator);
        ASSERT(position != 0); // separator is the first char, what to do?
        if (position > 0)
        {
            result = USTRING(inputText.data(), position);
            trim(result);
            inputText.shift(position + 1);
        }

        return result;
    }

    USTRING splitCharReverse(USTRING inputText, UINT8 seperator)
    {
        USTRING result;

        auto position = inputText.findIndexReverse(seperator);
        if (position >= 0)
        {
            position++;
            result = USTRING(inputText.data(position), inputText.length() - position);
        }
        return result;
    }

    USTRING splitCharAny(USTRING& input, USTRING separator)
    {
        UINT8 separatorMatch;
        return splitCharAny(input, separator, separatorMatch);
    }

    USTRING splitCharAny(USTRING& input, USTRING separator, UINT8& separatorMatch)
    {
        auto matchText = input;

        const UINT8* match = nullptr;
        separatorMatch = 0;

        for (UINT32 i = 0; i < separator.length(); i++)
        {
            auto sep = separator[i];
            auto nextMatch = (const UINT8*)memchr(input.data(), sep, input.length());
            if (nextMatch != nullptr)
            {
                if (match == nullptr || nextMatch < match)
                {
                    match = nextMatch;
                    separatorMatch = sep;
                }
            }
        }

        if (match != nullptr)
        {
            auto matchLength = (UINT32)(match - input.data());
            matchText = input.toBuffer(0, matchLength); // ._end = matchText._start + matchLength;
            input.shift(matchLength + 1);
        }
        else
        {
            input.shift(input.length());
        }

        trim(matchText);
        return matchText;
    }

    USTRING skipSeparators(USTRING& input, const USTRING separator)
    {
        UINT32 matchCount = 0;
        auto separatorsFound = input;

        while (input)
        {
            auto match = (const UINT8*)memchr(separator.data(), input[0], separator.length());
            if (match == nullptr)
            {
                break;
            }
            input.shift();
            matchCount++;
        }

        separatorsFound.setLength(matchCount);
        return separatorsFound;
    }

    template <typename STREAM>
    USTRING splitChar(USTRING& input, USTRING separator, STREAM&& matchSeparator)
    {
        UINT8 separatorFound;
        auto matchText = splitCharAny(input, separator, separatorFound);
        if (separatorFound)
        {
            matchSeparator.writeByte(separatorFound);
            auto separators = skipSeparators(input, separator/*, matchSeparator*/);
            matchSeparator.writeBytes(separators);
        }
        return matchText;
    }

    template <typename STR>
    USTRING splitChar(STR&& input, USTRING separator)
    {
        return splitChar(input, separator, ByteStream(64));
    }

    template <typename STREAM>
    STREAM_READER<USTRING> splitCharToArray(USTRING& input, USTRING separator, STREAM&& stream)
    {
        while (auto part = splitChar(input, separator))
        {
            stream.append(part);
        }
        return stream.toRWBuffer();
    }

    STREAM_READER<BUFFER> splitCharToArray(BUFFER& input, BUFFER separator)
    {
        DATASTREAM<BUFFER, SCHEDULER_STACK> bufferStream;
        bufferStream.reserve(16);

        while (auto part = splitChar(input, separator))
        {
            bufferStream.append(part);
        }
        return bufferStream.toRWBuffer();
    }

    UINT64 parseCompilerDate(USTRING dateString)
    {
        tm timeFields;
        RtlZeroMemory(&timeFields, sizeof(timeFields));

        auto dateParts = splitCharToArray(dateString, " ", TSTRING_STREAM());
        ASSERT(dateParts.length() == 4);

        auto monthName = FindName(dateParts.read());
        if (monthName)
        {
            auto index = ArrayFind(MonthNames2, monthName);
            if (index >= 0)
                timeFields.tm_mon = (UINT16)(index + 1);
        }
        else DBGBREAK();

        timeFields.tm_mday = (UINT16)toNumber(dateParts.read());
        timeFields.tm_year = (UINT16)toNumber(dateParts.read());

        auto timeParts = splitCharToArray(dateParts.read(), ":", TSTRING_STREAM());
        timeFields.tm_hour = (UINT16)toNumber(timeParts.read());
        timeFields.tm_min = (UINT16)toNumber(timeParts.read());
        timeFields.tm_sec = (UINT16)toNumber(timeParts.read());

        auto ticks = mktime(&timeFields);
        return ticks;
    }

    UINT64 parseDate(USTRING dateString)
    {
        SYSTEMTIME timeFields;
        RtlZeroMemory(&timeFields, sizeof(timeFields));

        auto dateParts = splitCharToArray(dateString, DATE_SEPARATOR, TSTRING_STREAM());
        ASSERT(dateParts.length() >= 3);

        timeFields.wMonth = (UINT16)toNumber(dateParts.read());
        timeFields.wDay = (UINT16)toNumber(dateParts.read());
        timeFields.wYear = (UINT16)toNumber(dateParts.read());

        timeFields.wHour = dateParts ? (UINT16)toNumber(dateParts.read()) : 0;
        timeFields.wMinute = dateParts ? (UINT16)toNumber(dateParts.read()) : 0;
        timeFields.wSecond = dateParts ? (UINT16)toNumber(dateParts.read()) : 0;

        timeFields.wMilliseconds = dateParts ? (UINT16)toNumber(dateParts.read()) : 0;

        FILETIME fileTime;
        SystemTimeToFileTime(&timeFields, &fileTime);

        return *(UINT64*)&fileTime;
    }

    UINT64 parseRfcDate(USTRING dateString)
    {
        tm timeFields;
        RtlZeroMemory(&timeFields, sizeof(timeFields));

        auto dateParts = splitCharToArray(dateString, RFC_DATE_SEPARATOR, TSTRING_STREAM());
        ASSERT(dateParts.length() == 8);

        dateParts.shift(); // ignore day of week.

        timeFields.tm_mday = (UINT16)toNumber(dateParts.read());
        ASSERT(timeFields.tm_mday > 0);

        auto monthName = FindName(dateParts.read());
        if (monthName)
        {
            auto index = ArrayFind(MonthNames2, monthName);
            if (index >= 0)
                timeFields.tm_mon = (UINT16)(index + 1);
        }

        timeFields.tm_year = (UINT16)toNumber(dateParts.read());

        timeFields.tm_hour = (UINT16)toNumber(dateParts.read());
        timeFields.tm_min = (UINT16)toNumber(dateParts.read());
        timeFields.tm_sec = (UINT16)toNumber(dateParts.read());

        auto timezone = dateParts.read();
        ASSERT(timezone == "GMT");

        auto ticks = mktime(&timeFields);
        return ticks;
    }

    UINT64 parseHttpDate(BUFFER dateString) // Windows time in MS.
    {
        // Wed, 21 Oct 2015 07:28:00 GMT
        SYSTEMTIME timeFields;
        RtlZeroMemory(&timeFields, sizeof(timeFields));

        auto dateParts = splitCharToArray(dateString, RFC_DATE_SEPARATOR);
        dateParts.shift(); // ignore day of week

        timeFields.wDay = (UINT16)toNumber(dateParts.read());
        if (auto monthName = FindName(dateParts.read()))
        {
            timeFields.wMonth = ArrayFind(MonthNames2, monthName) + 1;
            ASSERT(timeFields.wMonth);
        }
        else DBGBREAK();

        timeFields.wYear = (UINT16)toNumber(dateParts.read());

        timeFields.wHour = (UINT16)toNumber(dateParts.read());
        timeFields.wMinute = (UINT16)toNumber(dateParts.read());
        timeFields.wSecond = (UINT16)toNumber(dateParts.read());

        ASSERT(dateParts.read() == "GMT");

        FILETIME fileTime;
        auto result = SystemTimeToFileTime(&timeFields, &fileTime);
        ASSERT(result != 0);

        auto dateTime = *(UINT64*)&fileTime;
        return dateTime / TICKS_PER_MS;
    }

    template <typename STREAM>
    BUFFER formatHttpDate(STREAM && stream, UINT64 timeValue = 0) // in ticks
    {
        auto offset = stream.count();
        SYSTEMTIME timeFields;
        if (timeValue > 0)
        {
            FileTimeToSystemTime((const FILETIME*)&timeValue, &timeFields);
        }
        else
        {
            GetSystemTime(&timeFields);
        }
        
        stream.writeMany(DayNames2[timeFields.wDayOfWeek], ", ");
        stream.writeString(timeFields.wDay, 2);
        stream.writeMany(" ", MonthNames2[timeFields.wMonth - 1], " ");
        stream.writeString(timeFields.wYear, 4);

        stream.writeByte(' ');
        stream.writeString(timeFields.wHour, 2);
        stream.writeByte(':');
        stream.writeString(timeFields.wMinute, 2);
        stream.writeByte(':');
        stream.writeString(timeFields.wSecond, 2);
        stream.writeString(" GMT");

        return stream.toBuffer(offset);
    }

    BUFFER foraatASNtime(BYTESTREAM& outStream, UINT64 fileTime = 0) // seconds
    {
        auto streamOffset = outStream.getPosition();

        SYSTEMTIME timeFields;
        fileTime *= TICKS_PER_SECOND;
        fileTime ? (void)FileTimeToSystemTime((const FILETIME*)&fileTime, &timeFields) : GetSystemTime(&timeFields);

        outStream.writeString(timeFields.wYear % 100, 2);
        outStream.writeString(timeFields.wMonth % 100, 2);
        outStream.writeString(timeFields.wDay % 100, 2);
        outStream.writeString(timeFields.wHour % 100, 2);
        outStream.writeString(timeFields.wMinute % 100, 2);
        outStream.writeString(timeFields.wSecond % 100, 2);
        outStream.writeByte('Z');;

        return streamOffset.toBuffer();
    }

    UINT16 STRtoNUM2(BUFFER& numberText)
    {
        return (UINT16(numberText.readByte() - 0x30) * 10) + UINT16(numberText.readByte() - 0x30);
    }

    UINT64 parseASNtime(BUFFER timeString)  // seconds
    {
        ASSERT(timeString.last() == 'Z');
        timeString.shrink();

        SYSTEMTIME timeFields;
        RtlZeroMemory(&timeFields, sizeof(timeFields));

        timeFields.wYear = STRtoNUM2(timeString);
        timeFields.wYear += timeFields.wYear > 50 ? 1900 : 2000;
        timeFields.wMonth = STRtoNUM2(timeString);
        timeFields.wDay = STRtoNUM2(timeString);
        timeFields.wHour = STRtoNUM2(timeString);
        timeFields.wMinute = STRtoNUM2(timeString);
        timeFields.wSecond = STRtoNUM2(timeString);

        UINT64 fileTime;
        SystemTimeToFileTime(&timeFields, (LPFILETIME)&fileTime);
        return fileTime /= TICKS_PER_SECOND;
    }

    using IPADDR = UINT32;
    using IPPORT = UINT16;

    constexpr IPADDR parseIPAddress(USTRING ipString) // in big endian
    {
        IPADDR ipAddress = 0;
        ULONG i = 0;
        for (; i < 4; i++)
        {
            auto digitString = splitChar(ipString, '.');
            if (isNumber(digitString))
            {
                auto number = toNumber(digitString);
                if (number < 255)
                {
                    ipAddress |= (number << i * 8);
                }
                else break;
            }
            else break;
        }

        if (i != 4)
            return 0;

        return ipAddress;
    }

    template<typename OUTSTREAM> // address in big endian
    BUFFER formatIPAddress(ULONG ipAddress, OUTSTREAM&& stream)
    {
        auto start = stream.getPosition();
        for (UINT32 i = 0; i < 4; i++)
        {
            auto part = (UINT8)(ipAddress >> (i * 8));
            stream.writeString((UINT64)part);
            if (i != 3) stream.writeString(".");
        }
        return start.toBuffer();
    }

    template<typename STREAM>
    BUFFER formatIPAddress(SOCKADDR_IN socketAddress, STREAM&& stream)
    {
        auto ipAddress = socketAddress.sin_addr.s_addr;
        return formatIPAddress(ipAddress, stream);
    }

    template <typename STR>
    constexpr UINT32 toHexNumber(STR&& text)
    {
        ASSERT(text.length() <= 8);
        UINT32 number = 0;

        while (text)
        {
            auto digit = text.at(0);
            if (isHexChar(digit))
            {
                digit = ToHexNumber(text.read());
                number = (number << 4) | (digit & 0x0F);
            }
            else break;
        }
        return number;
    }

    template <typename STR>
    INT64 stringToNumber(STR&& text)
    {
        auto start = text._start;
        auto isNegative = false;
        if (text.peek() == '-')
        {
            isNegative = true;
            text.shift();
        }

        if (startsWith(text, "0x"))
        {
            text.shift(2);
            return toHexNumber(text);
        }

        auto base = 10;
        INT64 number = 0;

        while (text)
        {
            UINT8 c = text.at(0);
            if (!isdigit(c))
                break;

            number *= base;
            number += c - '0';
            text.shift();
        }

        if (isNegative)
        {
            if ((text._start - start) == 1)
            {
                DBGBREAK();
                isNegative = false;
                text._start = start;
            }
        }

        number *= isNegative ? -1 : 1;
        return number;
    }

    INT64 toNumber(const USTRING& text)
    {
        return stringToNumber(text.clone());
    }

    INT64 toNumber(USTRING& text)
    {
        return stringToNumber(text);
    }

    INT64 toNumber(TOKEN name)
    {
        return toNumber(NameToString(name));
    }

    UINT32 toNumber(USTRING& text, USTRING& numberString)
    {
        numberString = text.toBuffer(0, 0);
        auto number = stringToNumber(text);
        numberString._end = text._start;
        return (UINT32)number;
    }

    constexpr bool isNumber(USTRING text)
    {
        for (UINT32 i = 0; i < text.length(); i++)
        {
            if (!isdigit(text.at(i)))
                return false;
        }
        return true;
    }

    float toFloat(USTRING& text)
    {
        auto value = (float)toNumber(text);
        if (text.peek() == '.')
        {
            text.shift();
            USTRING numberString;
            auto fraction = (float)toNumber(text, numberString);
            if (fraction > 0)
            {
                value += (1.0f / (float)(pow(10.0f, (int)numberString.length()))) * fraction;
            }
        }
        return value;
    }

    float toFloat(USTRING& text, USTRING& numberString)
    {
        numberString = text.toBuffer(0, 0);
        auto number = toFloat(text);
        numberString._end = text._start;
        return number;
    }

    UINT8 toUpper(UINT8 c) const
    {
        return (c >= 'a' && c <= 'z') ? c - ('a' - 'A') : c;
    }

    UINT8 toLower(UINT8 c) const
    {
        return (c >= 'A' && c <= 'Z') ? c + ('a' - 'A') : c;
    }

    void toUpper(USTRING& text)
    {
        auto address = (PUINT8)text.data();
        for (UINT32 i = 0; i < text.length(); i++)
        {
            *(address + i) = (UINT8)toUpper(*(address + i));
        }
    }

    void toLower(USTRING & text)
    {
        auto address = (PUINT8)text.data();
        for (UINT32 i = 0; i < text.length(); i++)
        {
            *(address + i) = (UINT8)toLower(*address);
        }
    }

    bool equals(USTRING first, USTRING second, bool isCaseSensitive = false) const
    {
        if (isCaseSensitive)
            return first == second;

        auto result = false;
        if (first.length() == second.length())
        {
            result = true;
            for (UINT32 i = 0; i < first.length(); i++)
            {
                if (toUpper(first[i]) != toUpper(second[i]))
                {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    template <typename STREAM>
    auto readHexString(STREAM&& stream, BUFFER hexString)
    {
        ASSERT((hexString.length() % 2) == 0);
        while (hexString.length() > 1)
        {
            auto first = hexString.at(0);
            auto second = hexString.at(1);

            if (isHexChar(first) && isHexChar(second))
            {
                hexString.shift(2);

                UINT8 number = ToHexNumber(first) << 4;
                number |= ToHexNumber(second);

                stream.writeByte(number);
            }
            else break;
        }
        return stream.toBuffer();
    }

    bool contains(USTRING text, UINT8 letter)
    {
        letter = toUpper(letter);
        auto result = true;
        for (UINT32 i = 0; i < text.length(); i++)
        {
            if (toUpper(text.at(i)) != letter)
            {
                result = false;
                break;
            }
        }
        return result;
    }

    USTRING& trimStart(USTRING& text)
    {
        while ((text.length() > 0) && IsWhitespace(text[0]))
            text.shift();
        
        return text;
    }

    USTRING& trimEnd(USTRING& text)
    {
        while ((text.length() > 0) && IsWhitespace(text.last()))
            text.shrink();

        return text;
    }

    USTRING& trim(USTRING& text)
    {
        while (text)
        {
            if (IsWhitespace(text.at(0)))
                text.shift();
            else break;
        }
        while (text)
        {
            if (IsWhitespace(text.last()))
                text.shrink();
            else break;
        }
        return text;
    }

    template <typename STACK>
    TOKEN parseLiteral(USTRING text)
    {
        auto value = Undefined;
        do
        {
            if (text.length() == 0)
            {
                value = NULL_NAME;
                break;
            }

            value = Dict.CreateName<STACK>(text, true);
        } while (false);
        return value;
    }

    bool endsWith(USTRING subject, USTRING match) const
    {
        auto result = false;
        if (subject.length() >= match.length())
        {
            auto endPart = subject.shrink(match.length());
            result = equals(endPart, match);
        }
        return result;
    }

    constexpr bool startsWith(USTRING subject, USTRING match)
    {
        auto result = false;
        if (subject.length() >= match.length())
        {
            result = true;
            for (UINT32 i = 0; i < match.length(); i++)
            {
                if (toUpper(subject[i]) != toUpper(match[i]))
                {
                    result = false;
                    break;
                }
            }
        }
        return result;
    }

    bool isIDstring(USTRING idString)
    {
        constexpr static USTRING IDCHARS = "0123456789ABCDEFabcdef-";
        skipSeparators(idString, IDCHARS);
        return idString.length() == 0;
    }

    bool parseID(USTRING idString, U128& id)
    {
        auto&& byteStream = BYTESTREAM(id.u8, 16);
        if (isIDstring(idString))
        {
            while (auto part = splitChar(idString, '-'))
            {
                readHexString(byteStream, part);
            }
        }
        return (byteStream.count() == 16);
    }

    U128 parseID(TOKEN idName)
    {
        U128 id;
        auto idString = NameToString(idName);
        auto result = parseID(idString, id);
        return result ? id : U128();
    }

    GUID parseGuid(USTRING guidString)
    {
        TSTRING_STREAM partsStream;
        auto parts = splitCharToArray(guidString, "-", partsStream);

        if (parts.length() == 5)
        {
            LOCAL_STREAM<16> guidBytes;
            for (auto& part : parts)
            {
                readHexString(guidBytes, part);
            }
            return guidBytes.toBuffer().readGuid();
        }

        return NULL_GUID;
    }

    template <typename STACK>
    USTRING copy(USTRING other)
    {
        auto& charStream = StackAlloc<STREAM_BUILDER<UINT8, STACK, 32>, STACK>();
        charStream.writeStream(other);
        return charStream.toBuffer();
    }

    UINT8 convertEscapeSequence(USTRING& input)
    {
        auto firstChar = input.readByte();
        UINT8 newChar = 0;

        if (firstChar == 'r')
        {
            newChar = '\r';
        }
        else if (firstChar == 'n')
        {
            newChar = '\n';
        }
        else if (firstChar == 'x')
        {
            newChar = input.readHexChar();
        }
        else if (firstChar == 't')
        {
            newChar = '\t';
        }
        else
        {
            newChar = firstChar;
        }
        return newChar;
    }

    void splitBlock(USTRING& input, USTRING separators, UINT32 openBraces = 0)
    {
        trim(input);
        ASSERT(separators.length() == 2);
        while (input)
        {
            UINT8 separatorFound;
            auto matchText = splitCharAny(input, separators, separatorFound);
            if (separatorFound == 0)
            {
                DBGBREAK();
                break;
            }

            if (separatorFound == separators.at(0))
            {
                openBraces++;
            }
            else if (separatorFound == separators.at(1))
            {
                ASSERT(openBraces > 0);
                openBraces--;
                if (openBraces == 0)
                    break;
            }
        }
    }

    template <typename STREAM>
    USTRING parseQuote(USTRING& input, STREAM&& quoteStream, UINT8 quoteChar = '"')
    {
        UINT8 separator;
        BUFFER quoteSeparator = quoteChar == '"' ? "\\\"" : "\\'";
        while (auto part = splitCharAny(input, quoteSeparator, separator))
        {
            quoteStream.writeBytes(part);

            if (separator == '\\')
            {
                auto newChar = convertEscapeSequence(input);
                quoteStream.writeByte(newChar);
            }
            else if (separator == quoteChar)
            {
                break;
            }
        }
        return quoteStream.toBuffer();
    }
};

inline STRINGOPS String;
