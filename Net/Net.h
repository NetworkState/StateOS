
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

constexpr BUFFER STATUS_100 = "100 CONTINUE";
constexpr BUFFER STATUS_101 = "101 SWITCHING PROTOCOLS";
constexpr BUFFER STATUS_200 = "200 OK";
constexpr BUFFER STATUS_201 = "201 CREATED";
constexpr BUFFER STATUS_202 = "202 ACCEPTED";
constexpr BUFFER STATUS_203 = "203 NON AUTHORITAVIVE INFORMATION";
constexpr BUFFER STATUS_204 = "204 NO CONTENT";
constexpr BUFFER STATUS_205 = "205 RESET CONTENT";
constexpr BUFFER STATUS_300 = "300 MULTIPLE CHOICES";
constexpr BUFFER STATUS_301 = "301 MOVED PERMANENTLY";
constexpr BUFFER STATUS_302 = "302 FOUND";
constexpr BUFFER STATUS_303 = "303 SEE OTHER";
constexpr BUFFER STATUS_304 = "304 NOT MODIFIED";
constexpr BUFFER STATUS_305 = "305 USE PROXY";
constexpr BUFFER STATUS_307 = "307 TEMPORARY REDIRECT";
constexpr BUFFER STATUS_400 = "400 BAD REQUEST";
constexpr BUFFER STATUS_401 = "401 UNAUTHORIZED";
constexpr BUFFER STATUS_402 = "402 PAYMENT REQUIRED";
constexpr BUFFER STATUS_403 = "403 FORBIDDEN";
constexpr BUFFER STATUS_404 = "404 NOT FOUND";
constexpr BUFFER STATUS_405 = "405 METHOD NOT ALLOWED";
constexpr BUFFER STATUS_406 = "406 NOT ACCEPTABLE";
constexpr BUFFER STATUS_407 = "407 PROXY AUTHORIZATION REQUIRED";
constexpr BUFFER STATUS_408 = "408 REQUEST TIMEOU";
constexpr BUFFER STATUS_409 = "409 CONFLICT";
constexpr BUFFER STATUS_410 = "410 GONE";
constexpr BUFFER STATUS_411 = "411 LENGTH REQUIRED";
constexpr BUFFER STATUS_412 = "412 PRECONDITION FAILED";
constexpr BUFFER STATUS_413 = "413 PAYLOAD TOO LARGE";
constexpr BUFFER STATUS_414 = "414 URI TOO LONG";
constexpr BUFFER STATUS_415 = "415 UNSUPPORTED MEDIA";
constexpr BUFFER STATUS_426 = "426 UPGRADE REQUIRED";
constexpr BUFFER STATUS_500 = "500 INTERNAL SERVER ERROR";
constexpr BUFFER STATUS_501 = "501 NOT IMPLEMENTED";
constexpr BUFFER STATUS_502 = "502 BAD GATEWAY";
constexpr BUFFER STATUS_503 = "503 SERVICE UNAVAILABLE";
constexpr BUFFER STATUS_504 = "504 GATEWAY TIMEOUT";
constexpr BUFFER STATUS_505 = "505 HTTP VERSION NOT SUPPORTED";

struct HTTP_STATUS_MAP
{
    TOKEN code;
    TOKEN text;
};

constexpr HTTP_STATUS_MAP HttpStatusMap[] = {
    { HTTP_100, HTTP_CONTINUE},
    { HTTP_101, HTTP_SWITCHING_PROTOCOLS },
    { HTTP_200, HTTP_OK },
    { HTTP_201, HTTP_CREATED },
    { HTTP_202, HTTP_ACCEPTED},
    { HTTP_203, HTTP_NON_AUTHORITAVIVE_INFORMATION},
    { HTTP_204, HTTP_NO_CONTENT},
    { HTTP_205, HTTP_RESET_CONTENT},
    { HTTP_300, HTTP_MULTIPLE_CHOICES},
    { HTTP_301, HTTP_MOVED_PERMANENTLY},
    { HTTP_302, HTTP_FOUND},
    { HTTP_303, HTTP_SEE_OTHER},
    { HTTP_304, HTTP_NOT_MODIFIED},
    { HTTP_305, HTTP_USE_PROXY},
    { HTTP_307, HTTP_TEMPORARY_REDIRECT},
    { HTTP_400, HTTP_BAD_REQUEST},
    { HTTP_401, HTTP_UNAUTHORIZED},
    { HTTP_402, HTTP_PAYMENT_REQUIRED},
    { HTTP_403, HTTP_FORBIDDEN},
    { HTTP_404, HTTP_NOT_FOUND},
    { HTTP_405, HTTP_METHOD_NOT_ALLOWED},
    { HTTP_406, HTTP_NOT_ACCEPTABLE},
    { HTTP_408, HTTP_REQUEST_TIMEOUT},
    { HTTP_409, HTTP_CONFLICT},
    { HTTP_410, HTTP_GONE},
    { HTTP_411, HTTP_LENGTH_REQUIRED},
    { HTTP_413, HTTP_PAYLOAD_TOO_LARGE},
    { HTTP_414, HTTP_URI_TOO_LONG},
    { HTTP_415, HTTP_UNSUPPORTED_MEDIA},
    { HTTP_426, HTTP_UPGRADE_REQUIRED},
    { HTTP_500, HTTP_INTERNAL_SERVER_ERROR},
    { HTTP_501, HTTP_NOT_IMPLEMENTED},
    { HTTP_502, HTTP_BAD_GATEWAY},
    { HTTP_503, HTTP_SERVICE_UNAVAILABLE},
    { HTTP_504, HTTP_GATEWAY_TIMEOUT},
    { HTTP_505, HTTP_HTTP_VERSION_NOT_SUPPORTED},
};

constexpr TOKEN HTTP_STATUS(TOKEN code)
{
    TOKEN result;
    for (UINT32 i = 0; i < ARRAYSIZE(HttpStatusMap); i++)
    {
        if (HttpStatusMap[i].code == code)
        {
            result = HttpStatusMap[i].text;
            break;
        }
    }
    return result;
}

extern ADDRINFOEX DnsResolverHints;
struct IPENDPOINT
{
    SOCKADDR_IN _address;
    auto address() const { return (LPSOCKADDR_IN)&_address; }
    auto addressC() const { return (sockaddr *)&_address; }
    void zero() { RtlZeroMemory(&_address, sizeof(_address)); }
    IPENDPOINT() { zero(); }
    IPENDPOINT(UINT32 ipAddress, UINT16 ipPort = 0)
    {
        _address.sin_family = AF_INET;
        _address.sin_addr.s_addr = SWAP32(ipAddress);
        _address.sin_port = SWAP16(ipPort);
    }
    IPENDPOINT(const SOCKADDR_IN& init)
    {
        assign(&init);
    }

    void setAddress(UINT32 addr) { _address.sin_addr.s_addr = SWAP32(addr); }
    void setPort(UINT16 port) { _address.sin_port = SWAP16(port); }

    void assign(const SOCKADDR_IN* inAddress)
    {
        RtlCopyMemory(&_address, inAddress, sizeof(SOCKADDR_IN));
    }

    bool compare(const SOCKADDR_IN* other) const
    {
        return _address.sin_addr.s_addr == other->sin_addr.s_addr && _address.sin_port == other->sin_port;
    }

    explicit operator bool() const { return _address.sin_addr.s_addr != 0; }
    IPENDPOINT& operator = (const SOCKADDR_IN& inAddr) { assign(&inAddr); return *this; }
    IPENDPOINT& operator = (const LPSOCKADDR_IN inAddr) { assign(inAddr); return *this; }
    IPENDPOINT& operator = (const IPENDPOINT& inAddr) { assign(inAddr.address()); return *this; }

    bool operator == (const IPENDPOINT& other) const { return compare(other.address()); }
    bool operator == (const SOCKADDR_IN& other) const { return compare(&other); }
    bool operator == (const LPSOCKADDR_IN other) const { return compare(other); }
};

extern IPENDPOINT IPLOOPBACK;
constexpr UINT32 SOCKADDR_LEN = sizeof(sockaddr);

struct DNS_QUERY
{
    SCHEDULER_INFO<>& scheduler;
    OVERLAPPED overlap;
    STASK task;
    IPENDPOINT ipAddress;
    PADDRINFOEX addrInfo;

    DNS_QUERY(SCHEDULER_INFO<>& scheduler) : scheduler(scheduler) {}

    void resolveDns(BUFFER hostname, UINT16 port)
    {
        ipAddress = IPENDPOINT(INADDR_ANY, port);
        auto result = GetAddrInfoEx(hostname.toWideString(), nullptr, NS_DNS, nullptr, &DnsResolverHints, &addrInfo, nullptr, &overlap,
            [](DWORD errorCode, DWORD, LPWSAOVERLAPPED overlapPtr)
            {
                auto&& dnsQuery = *(CONTAINING_RECORD(overlapPtr, DNS_QUERY, overlap));
                if (errorCode == 0)
                {
                    auto addrInfo = dnsQuery.addrInfo;
                    ASSERT(addrInfo != nullptr);
                    ASSERT(addrInfo->ai_protocol == IPPROTO_IPV4);
                    ASSERT(addrInfo->ai_addrlen == sizeof(SOCKADDR_IN));
                    dnsQuery.ipAddress._address.sin_addr = ((LPSOCKADDR_IN)addrInfo->ai_addr)->sin_addr;
                    FreeAddrInfoEx(dnsQuery.addrInfo);
                }
                dnsQuery.scheduler.runTask(dnsQuery.task, errorCode);
            }, nullptr);
    }

    void clear()
    {
        ZeroMemory(&overlap, sizeof(OVERLAPPED));
        task.clear();
    }
};

constexpr USTRING HTTP_HEADER_NAME_PATTERN = ": \t";
constexpr USTRING WHITESPACE_PATTERN = " \t";
constexpr USTRING HTTP_HEADERS_DELIMITER = "\r\n\r\n";

constexpr USTRING COOKIE_PARAM_SEPARATOR = " \t;";
constexpr USTRING COOKIE_NAME_SEPARATOR = " \t-";

struct HTTP_COOKIE
{
    TOKEN nameValue;

    UINT64 expires = 0;
    TOKEN path = HTTP_SLASH;
    TOKEN domain;

    explicit operator bool() const { return IsValidRef(*this); }
    HTTP_COOKIE(TOKEN nameValue) : nameValue(nameValue) {};
    HTTP_COOKIE() {}
};

struct HTTP_AUTH
{
    TOKEN type;
    BUFFER realm;
    TOKEN algorithm;
    BUFFER nonce;
    BUFFER opaque;
    UINT32 useCount = 1;

    void clear()
    {
        algorithm = NULL_NAME;
    }
    operator bool() const { return algorithm; }
};

constexpr USTRING HttpHeaderPairDelimiters = "=;\"";
constexpr USTRING HttpHeaderListDelimiters = ",\"";

struct HTTP_OPS
{
    struct HEADER_PAIR
    {
        USTRING Name;
        USTRING value;
    };

    template <typename STREAM>
    USTRING UnescapeHttpString(USTRING inString, STREAM&& stream)
    {
        while (inString)
        {
            auto inChar = inString.read();
            if (inChar == '%')
            {
                auto hexChar = inString.readHexChar();
                stream.writeByte(hexChar);
            }
            else
            {
                stream.writeByte(inChar);
            }
        }
        return stream.toBuffer();
    }

    USTRING UnescapeHttpString(USTRING inString)
    {
        return UnescapeHttpString(inString, ByteStream(64));
    }

    template <typename STACK, typename URLINFO>
    URL_INFO& parseUrl(USTRING urlText, URLINFO&& urlInfo)
    {
        urlInfo.clear();

        auto matchString = String.splitString(urlText, "://");
        if (urlText.length() == 0)
        {
            // no protocol - relative url
            urlInfo.path = CreateCustomName<STACK>(matchString);
        }
        else
        {
            urlInfo.protocol = FindName(matchString);
            ASSERT(urlInfo.protocol);

            urlInfo.port = urlInfo.protocol == HTTP_https ? TLS_PORT : 80;

            UINT8 separator;
            auto match = String.splitCharAny(urlText, "@/", separator);
            USTRING hostnamePort;
            if (separator == '@')
            {
                // username password
                match = UnescapeHttpString(match);
                urlInfo.username = CreateCustomName<STACK>(String.splitChar(match, ':'));
                urlInfo.password = CreateCustomName<STACK>(match);

                hostnamePort = String.splitCharAny(urlText, "/");
            }
            else if (separator == '/' || urlText.isEmpty())
            {
                hostnamePort = match;
            }

            ASSERT(hostnamePort);

            auto hostname = String.splitCharAny(hostnamePort, ":");
            if (hostnamePort)
            {
                urlInfo.port = (UINT32)String.toNumber(hostnamePort);
            }
            urlInfo.hostname = CreateCustomName<STACK>(hostname);

            urlInfo.path = urlText ? CreateCustomName<STACK>(urlText) : HTTP_SLASH;
        }

        return urlInfo;
    }

    USTRING getResponseHeaders(BUFFER& socketData)
    {
        auto headers = String.splitStringIf(socketData, HTTP_HEADERS_DELIMITER);
        return headers;
    }

    template <typename FUNC, typename ... ARGS>
    void parseHeaders(USTRING headers, FUNC callback, ARGS&& ... args)
    {
        String.splitString(headers, CRLF); // get past the status line!

        while (auto line = String.splitString(headers, CRLF))
        {
            auto nameString = String.splitChar(line, HTTP_HEADER_NAME_PATTERN);
            auto name = FindName(nameString);

            callback(name, line, args ...);
        }
    }

    template <typename STREAM, typename FUNC, typename ... ARGS>
    void parseHeaderValue(USTRING headerText, STREAM&& valueStream, FUNC callback, ARGS&& ... args)
    {
        UINT8 separator;
        while (auto name = String.splitCharAny(headerText, "=;,", separator))
        {
            auto valueStart = valueStream.getPosition();
            if (separator == '=')
            {
                while (auto part = String.splitCharAny(headerText, ";\"", separator))
                {
                    valueStream.writeBytes(part);
                    if (separator == '"')
                    {
                        part = String.parseQuote(headerText, valueStream);
                        //valueStream.writeBytes(part);
                    }
                    else if (separator == ';' || separator == 0)
                    {
                        break;
                    }
                    else
                    {
                        DBGBREAK();
                        break;
                    }
                }
            }

            auto shouldContinue = callback(name, valueStart.toBuffer(), args ...);
            if (shouldContinue == false)
                break;
        }
    }

    HTTP_COOKIE& parseSetCookie(BUFFER fieldValue, HTTP_COOKIE& cookie)
    {
        auto cookieValue = String.splitChar(fieldValue, ";");
        cookie.nameValue = CreateServiceName(cookieValue);

        parseHeaderValue(fieldValue, ByteStream(512), [](BUFFER nameString, BUFFER valueString, HTTP_COOKIE& cookie)
            {
                if (auto name = FindName(nameString))
                {
                    if (name == HTTP_Expires)
                    {
                        auto unixTime = String.parseRfcDate(valueString);
                        cookie.expires = SecondsClock.elapsedTime() + (unixTime - UnixTimeOriginSeconds);
                    }
                    else if (name == HTTP_Path)
                    {
                        cookie.path = CreateServiceName(valueString);
                    }
                    else if (name == HTTP_Domain)
                    {
                        cookie.domain = CreateServiceName(valueString);
                    }
                    else if (name == HTTP_Max_Age)
                    {
                        cookie.expires = SecondsClock.elapsedTime() + String.toNumber(valueString);
                    }
                }
                return true;
            }, cookie);
        return cookie;
    }

    void parseAuth(BUFFER headerValue, HTTP_AUTH& auth)
    {
        parseHeaderValue(headerValue, ByteStream(512), [](BUFFER nameString, BUFFER valueString, HTTP_AUTH& auth)
            {
                if (auto name = FindName(nameString))
                {
                    if (name == HTTP_Basic || HTTP_Digest)
                    {
                        auth.type = name;
                    }
                    else if (name == HTTP_realm)
                    {
                        auth.realm = valueString;
                    }
                    else if (name == HTTP_algorithm)
                    {
                        auth.algorithm = FindName(valueString);
                    }
                    else if (name == HTTP_nonce)
                    {
                        auth.nonce = valueString;
                    }
                    else if (name == HTTP_opaque)
                    {
                        auth.opaque = valueString;
                    }
                }
                return true;
            }, auth);
    }

    void formatAuth(URL_INFO& url, HTTP_AUTH& auth, TOKEN method, BYTESTREAM& messageStream)
    {
        auto&& byteStream = ByteStream(1024);
        if (auth.type == HTTP_Basic)
        {
            byteStream.writeMany(url.username, ":", url.password);
            messageStream.writeString("Authorization: Basic ");
            messageStream.encodeBase64(byteStream.toBuffer());
            messageStream.writeString(CRLF);
        }
        else if (auth.type == HTTP_Digest)
        {
            SHA256_DATA authA1;
            byteStream.writeMany(url.username, ":", auth.realm, ":", url.password);
            Sha256ComputeHash(authA1, byteStream.toBuffer());

            SHA256_DATA authA2;
            byteStream.clear().writeMany(method, ":/", url.path);
            Sha256ComputeHash(authA2, byteStream.toBuffer());

            byteStream.clear().encodeBase64(authA1);
            byteStream.writeMany(":", auth.nonce, ":");
            byteStream.writeHexString(auth.useCount, 8);
            byteStream.writeString(":");
            UINT8 cnonce[32];
            Random.getBytes(cnonce);
            byteStream.encodeBase64(cnonce);
            byteStream.writeMany(":auth:");
            byteStream.encodeBase64(authA2);

            SHA256_DATA responseHash;
            Sha256ComputeHash(responseHash, byteStream.toBuffer());

            messageStream.writeMany("Authorization: Digest username=\"", url.username, "\", ");
            messageStream.writeMany("realm=\"", auth.realm, "\", ");
            messageStream.writeMany("uri=\"", url.path, "\", ");
            messageStream.writeMany("algorithm=\"", auth.algorithm, "\", ");
            messageStream.writeMany("nonce=\"", auth.nonce, "\", ");
            messageStream.writeString("nc=\"");
            byteStream.writeHexString(auth.useCount, 8);
            messageStream.writeMany("\", cnonce=\"");
            messageStream.encodeBase64(cnonce);
            messageStream.writeMany("\", ");
            messageStream.writeMany("qop=\"", "auth\", ");
            messageStream.writeMany("response=\"");
            messageStream.encodeBase64(responseHash);
            messageStream.writeString("\", ");
            messageStream.writeMany("opaque=\"", auth.opaque, "\"", CRLF);

            auth.useCount++;
        }
    }

    template <typename STREAM, typename FUNC, typename ... ARGS>
    void parseHeaderValueList(USTRING headerText, STREAM&& valueStream, FUNC callback, ARGS&& ... args)
    {
        UINT8 separator;
        USTRING valueStart = valueStream.getPosition();
        while (auto name = String.splitCharAny(headerText, ",\";=", separator))
        {
            valueStream.writeStream(part);
            if (separator == '"')
            {
                String.parseQuote(headerText, valueStream);
            }
            else if (separator == ',' || separator == 0)
            {
                auto shouldContinue = callback(name, valueStream.toBuffer(valueStart), args ...);
                valueStart = valueStream.getPosition();
                if (shouldContinue == false)
                    break;
            }
            else
            {
                DBGBREAK();
            }
        }
    }

    template <typename STREAM>
    USTRING parseHeaderValue(USTRING headerText, STREAM&& valueStream)
    {
        UINT8 separator;
        USTRING valueStart = valueStream.getPosition();
        while (auto name = String.splitCharAny(headerText, ",\";=", separator))
        {
            valueStream.writeStream(part);
            if (separator == '"')
            {
                String.parseQuote(headerText, valueStream);
            }
            else break;
        }
        return valueStream.toBuffer(valueStart);
    }

    USTRING findHeader(USTRING headers, TOKEN name)
    {
        USTRING returnValue;

        parseHeaders(headers, [](TOKEN headerName, USTRING headerValue, TOKEN matchName, USTRING& returnValue)
            {
                if (headerName == matchName)
                {
                    returnValue = headerValue;
                }
            }, name, returnValue);

        return returnValue;
    }

    bool isRequest(USTRING headers)
    {
        auto result = false;
        auto firstLine = String.splitString(headers, CRLF);
        auto version = String.splitChar(firstLine, WHITESPACE_PATTERN);

        if (String.startsWith(version, "HTTP") || String.startsWith(version, "RTSP"))
        {
            result = true;
        }
        return result;
    }

    bool isResponse(USTRING headers)
    {
        return !isRequest(headers);
    }

    TOKEN getMethod(USTRING headers)
    {
        ASSERT(isRequest(headers));

        auto firstLine = String.splitString(headers, CRLF);
        auto methodString = String.splitChar(firstLine, WHITESPACE_PATTERN);

        return FindName(methodString);
    }

    TOKEN getStatus(USTRING headers)
    {
        ASSERT(isResponse(headers));

        auto firstLine = String.splitString(headers, CRLF);

        String.splitChar(firstLine, WHITESPACE_PATTERN); // version
        auto status = String.splitChar(firstLine, WHITESPACE_PATTERN);

        ASSERT(status);
        return FindName(status);
    }

    template <typename VALUE>
    inline void formatHeader(BYTESTREAM& headerStream, TOKEN name, VALUE value)
    {
        headerStream.writeMany(name, ": ", value, CRLF);
    }

    inline void formatDate(BYTESTREAM& dataStream, TOKEN header, UINT64 time = 0)
    {
        dataStream.writeMany(header, ": ");
        String.formatHttpDate(dataStream, time);
        dataStream.writeString(CRLF);
    }

};

extern HTTP_OPS Http;

template <typename ... ARGS>
inline NTSTATUS SocketSend(SOCKET socketHandle, IOCALLBACK& ioState, ARGS&& ... buffers)
{
    WSABUF sendBufs[] = { {buffers.length(), (char*)buffers.data()} ...};
    DWORD flags = 0, bytesSent;
    auto result = WSASend(socketHandle, sendBufs, ARRAYSIZE(sendBufs), &bytesSent, 0, ioState.start(), nullptr);

    return (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

inline NTSTATUS SocketSend(SOCKET socketHandle, BUFFER sendData, IOCALLBACK& ioCallback)
{
    WSABUF wsaBuf{ sendData.length(), (char*)sendData.data() };
    DWORD flags = 0, bytesSent;
    auto result = WSASend(socketHandle, &wsaBuf, 1, &bytesSent, 0, ioCallback.start(), nullptr);

    return (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

inline NTSTATUS SocketSend(SOCKET socketHandle, BUFFER sendData)
{
    WSABUF wsaBuf{ sendData.length(), (char*)sendData.data() };
    DWORD flags = 0, bytesSent;
    auto result = WSASend(socketHandle, &wsaBuf, 1, &bytesSent, 0, nullptr, nullptr);

    return (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

inline NTSTATUS SocketSendTo(SOCKET socketHandle, IPENDPOINT& destination, BUFFER sendData)
{
    WSABUF wsaBuf{ sendData.length(), (char*)sendData.data() };
    DWORD flags = 0, bytesSent;
    auto result = ::WSASendTo(socketHandle, &wsaBuf, 1, &bytesSent, flags, destination.addressC(), SOCKADDR_LEN, nullptr, nullptr);
    return result == SOCKET_ERROR ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

inline NTSTATUS SocketRecvFrom(SOCKET socketHandle, IPENDPOINT& recvFromAddress, IOCALLBACK& ioState, BYTESTREAM& recvStream)
{
    WSABUF buf{ recvStream.spaceLeft(), (char *)recvStream.end() };
    DWORD flags = 0, bytesReceived;
    int addrLen = SOCKADDR_LEN;
    auto result = WSARecvFrom(socketHandle, &buf, 1, &bytesReceived, &flags, recvFromAddress.addressC(), &addrLen, ioState.start(), nullptr);
    return (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

inline NTSTATUS SocketRecv(SOCKET socketHandle, BYTESTREAM& recvStream, IOCALLBACK& ioCallback)
{
    WSABUF wsaBuf{ recvStream.spaceLeft(), (char*)recvStream.end()};
    DWORD flags = 0, bytesReceived;
    auto result = WSARecv(socketHandle, &wsaBuf, 1, &bytesReceived, &flags, ioCallback.start(), nullptr);
    return (result == SOCKET_ERROR && WSAGetLastError() != WSA_IO_PENDING) ? STATUS_NETWORK_UNREACHABLE : STATUS_SUCCESS;
}

extern LPFN_CONNECTEX ConnectExFunc;
extern LPFN_ACCEPTEX AcceptExFunc;
extern LPFN_DISCONNECTEX DisconnectExFunc;

struct EXT_MIME_MAP
{
    TOKEN extension;
    TOKEN mimeType;
};

constexpr EXT_MIME_MAP ExtensionMimeMap[] = {
    { EXT_html, MIME_text_html},
    { EXT_txt, MIME_text_plain},
    { EXT_css, MIME_text_css},
    { EXT_xml,  MIME_application_xml},
    { EXT_json, MIME_application_json},
    { EXT_sdp, MIME_application_sdp},
    { EXT_mp4, MIME_video_mp4},
    { EXT_mp4a, MIME_audio_mp4},
    { EXT_mp3, MIME_audio_mpeg},
    { EXT_jpeg, MIME_image_jpeg},
    { EXT_jpg, MIME_image_jpeg},
    { EXT_png, MIME_image_png},
    { EXT_webm, MIME_video_webm},
    { EXT_docx, MIME_application_vnd_openxmlformats_officedocument_wordprocessingml_document},
    { EXT_xlsx, MIME_application_vnd_openxmlformats_officedocument_spreadsheetml_sheet},
    { EXT_pptx, MIME_application_vnd_openxmlformats_officedocument_presentationml_presentation},
    { EXT_svg,  MIME_image_svg_xml},
    { EXT_bin, MIME_application_octet_stream},
    { EXT_pdf, MIME_application_postscript}, // fix
    { EXT_7z, MIME_application_x_7z_compressed},

};

constexpr TOKEN GET_MIME_TYPE(TOKEN ext)
{
    TOKEN result;
    for (UINT32 i = 0; i < ARRAYSIZE(ExtensionMimeMap); i++)
    {
        if (ExtensionMimeMap[i].extension == ext)
        {
            result = ExtensionMimeMap[i].mimeType;
        }
    }
    return result;
}

/*
https://github.com/miguelmota/mime-ext/blob/master/src/data/mime_types.txt

3g2 video/3gpp2
3gp video/3gpp
7z  application/x-7z-compressed
aac audio/x-aac
asc application/pgp-signature
asf video/x-ms-asf
asm text/x-asm
avi video/x-msvideo
azw application/vnd.amazon.ebook
bat application/x-msdownload
bin application/octet-stream
bmp image/bmp
boz application/x-bzip2
bpk application/octet-stream
bz  application/x-bzip
bz2 application/x-bzip2
c   text/x-c
cab application/vnd.ms-cab-compressed
cc  text/x-c
cgm  image/cgm
class application/java-vm
com  application/x-msdownload
conf text/plain
cpio application/x-cpio
cpp  text/x-c
css  text/css
csv  text/csv
def  text/plain
dll  application/x-msdownload
dmg  application/x-apple-diskimage
dmp  application/vnd.tcpdump.pcap
docx application/vnd.openxmlformats-officedocument.wordprocessingml.document
dot  application/msword
dotm application/vnd.ms-word.template.macroenabled.12
dotx application/vnd.openxmlformats-officedocument.wordprocessingml.template
ecma application/ecmascript
eps  application/postscript
epub application/epub+zip
etx  text/x-setext
flac audio/x-flac
fli  video/x-fli
flo  application/vnd.micrografx.flo
flv  video/x-flv
flw  application/vnd.kde.kivio
flx  text/vnd.fmi.flexstor
fly  text/vnd.fly
fm   application/vnd.framemaker
gif  image/gif
gtar application/x-gtar
h    text/x-c
h261 video/h261
h263 video/h263
h264 video/h264
hal  application/vnd.hal+xml
htm  text/html
html text/html
ifb  text/calendar
in   text/plain
jar  application/java-archive
java text/x-java-source
jpe  image/jpeg
jpeg image/jpeg
jpg  image/jpeg
jpgm video/jpm
jpgv video/jpeg
jpm  video/jpm
js   application/javascript
json application/json
jsonml application/jsonml+json
list text/plain
log  text/plain
m1v  video/mpeg
m21  application/mp21
m2a  audio/mpeg
m2v  video/mpeg
m3a  audio/mpeg
m4a  audio/mp4
m4v  video/x-m4v
man  text/troff
mid  audio/midi
midi audio/midi
mime message/rfc822
mk3d video/x-matroska
mka  audio/x-matroska
mks  video/x-matroska
mkv  video/x-matroska
mng  video/x-mng
mov  video/quicktime
movie video/x-sgi-movie
mp2  audio/mpeg
mp21 application/mp21
mp2a audio/mpeg
mp3  audio/mpeg
mp4  video/mp4
mp4a audio/mp4
mp4s application/mp4
mp4v video/mp4
mpc  application/vnd.mophun.certificate
mpe  video/mpeg
mpeg video/mpeg
mpg  video/mpeg
mpg4 video/mp4
mpga audio/mpeg
ms   text/troff
oga  audio/ogg
ogg  audio/ogg
ogv  video/ogg
ogx  application/ogg
omdoc application/omdoc+xml
onepkg application/onenote
onetmp application/onenote
onetoc application/onenote
onetoc2 application/onenote
opf  application/oebps-package+xml
opml text/x-opml
oprc application/vnd.palm
org  application/vnd.lotus-organizer
osf  application/vnd.yamaha.openscoreformat
png  image/png
ppt  application/vnd.ms-powerpoint
pptm application/vnd.ms-powerpoint.presentation.macroenabled.12
pptx application/vnd.openxmlformats-officedocument.presentationml.presentation
ps   application/postscript
psd  image/vnd.adobe.photoshop
qt   video/quicktime
rar  application/x-rar-compressed
rmi  audio/midi
rtf  application/rtf
rtx  text/richtext
s    text/x-asm
sdp  application/sdp
sgi  image/sgi
sgl  application/vnd.stardivision.writer-global
sgm  text/sgml
sgml text/sgml
sh   application/x-sh
tex  application/x-tex
texi application/x-texinfo
texinfo application/x-texinfo
text text/plain
tiff image/tiff
txt  text/plain
vcard text/vcard
vcd application/x-cdlink
vcf text/x-vcard
vcg application/vnd.groove-vcard
vcs text/x-vcalendar
vcx application/vnd.vcx
vis application/vnd.visionary
viv video/vnd.vivo
vob video/x-ms-vob
vor application/vnd.stardivision.writer
vox application/x-authorware-bin
vrml model/vrml
vsd application/vnd.visio
vsf application/vnd.vsf
vss application/vnd.visio
vst application/vnd.visio
vsw application/vnd.visio
vtu  model/vnd.vtu
vxml application/voicexml+xml
w3d  application/x-director
wad  application/x-doom
wav  audio/x-wav
wax  audio/x-ms-wax
wbmp image/vnd.wap.wbmp
wcm  application/vnd.ms-works
wdb  application/vnd.ms-works
wdp  image/vnd.ms-photo
weba audio/webm
webm video/webm
webp image/webp
wg   application/vnd.pmi.widget
wgt  application/widget
wks  application/vnd.ms-works
wm   video/x-ms-wm
wma  audio/x-ms-wma
wmd  application/x-ms-wmd
wmf  application/x-msmetafile
wml  text/vnd.wap.wml
wmlc application/vnd.wap.wmlc
wmls text/vnd.wap.wmlscript
wmlsc application/vnd.wap.wmlscriptc
wmv  video/x-ms-wmv
wmx  video/x-ms-wmx
wmz  application/x-ms-wmz
wmz  application/x-msmetafile
woff application/font-woff
wpd  application/vnd.wordperfect
wsdl application/wsdl+xml
xaml application/xaml+xml
xbap application/x-ms-xbap
xhtml application/xhtml+xml
xif  image/vnd.xiff
xla  application/vnd.ms-excel
xlc  application/vnd.ms-excel
xlf  application/x-xliff+xml
xlm  application/vnd.ms-excel
xls  application/vnd.ms-excel
xlsb application/vnd.ms-excel.sheet.binary.macroenabled.12
xlsm application/vnd.ms-excel.sheet.macroenabled.12
xlsx application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
xlt  application/vnd.ms-excel
xltm application/vnd.ms-excel.template.macroenabled.12
xltx application/vnd.openxmlformats-officedocument.spreadsheetml.template
xlw  application/vnd.ms-excel
xm   audio/xm
xml  application/xml
xo   application/vnd.olpc-sugar
xop  application/xop+xml
xpi  application/x-xpinstall
xpl  application/xproc+xml
xpm  image/x-xpixmap
xpr  application/vnd.is-xpr
xps  application/vnd.ms-xpsdocument
xpw  application/vnd.intercon.formnet
xpx  application/vnd.intercon.formnet
xsl  application/xml
xslt application/xslt+xml
yang application/yang
*/