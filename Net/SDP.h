
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

enum class ICE_TYPE : UINT8
{
    UNKNOWN = 0,
    HOST = 126,
    PEER_REFLX = 110,
    SERVER_REFLX = 100,
    RELAYED = 0,
};

constexpr UINT32 LOCAL_PREFERENCE = 65535;
constexpr UINT32 COMPONENT_ID = 1;

struct ICE_CANDIDATE
{
    ICE_TYPE type = ICE_TYPE::UNKNOWN;
    IPENDPOINT candidate = { AF_INET, 0 };
    IPENDPOINT base = { AF_INET, 0 };
    UINT64 foundation = 0;
    UINT32 priority = 0;
    LOCAL_STREAM<8> ufrag;

    ICE_CANDIDATE() {}

    ICE_CANDIDATE(IPENDPOINT candidate) : candidate(candidate), type(ICE_TYPE::HOST)
    {
        foundation = (UINT64(type) << 32) | candidate._address.sin_addr.s_addr;;
        priority = (UINT32(type) << 24) | LOCAL_PREFERENCE << 8 | (256 - COMPONENT_ID); // RFC8445 5.1.2.1
    }

    ICE_CANDIDATE(ICE_CANDIDATE& other)
    {
        type = other.type;
        candidate = other.candidate;
        base = other.base;
        foundation = other.foundation;
        priority = other.priority;
        ufrag.writeBytes(other.ufrag.toBuffer());
    }

    constexpr explicit operator bool() const { return IsValidRef(*this); }
};

constexpr UINT32 KEYWORD_MASK = BITFIELD32(8, 0);
constexpr UINT32 SCOPE_MASK = BITFIELD32(16, 8);

struct SDP_LINE
{
    TOKEN name = NULL_NAME;
    TSTRING_STREAM params;

    SDP_LINE() {};
    SDP_LINE(SDP_LINE& other) : name(other.name)
    {
        auto buffer = other.params.toBuffer();
        for (UINT32 i = 0; i < buffer.length(); i++)
        {
            params.append(buffer.at(i));
        }
    }
    constexpr explicit operator bool() const { return IsValidRef(*this); }
};
constexpr TOKEN SDP_KEYWORDS[] = {
    SDP_video, SDP_audio, SDP_application, SDP_group, SDP_rtcp, SDP_ice_ufrag, SDP_ice_pwd, SDP_ice_options,
    SDP_extmap, SDP_rtcp_mux, SDP_rtpmap, SDP_rtcp_fb, SDP_fmtp, SDP_ssrc, SDP_setup, SDP_mid,
    SDP_msid, SDP_ssrc_group, SDP_msid_semantic, SDP_BUNDLE, SDP_fingerprint, SDP_sendrecv, SDP_rtcp_rsize, SDP_codec,
    SDP_sctpmap, SDP_rtx, SDP_candidate, SDP_end_of_candidates, SDP_controlled };

constexpr INT32 SdpKeywordIndex(TOKEN keyword)
{
    auto result = ArrayFind(SDP_KEYWORDS, keyword);
    ASSERT(result != -1);
    return result;
}

constexpr TOKEN SdpKeyword(UINT8 index)
{
    ASSERT(index < ARRAYSIZE(SDP_KEYWORDS));
    return SDP_KEYWORDS[index];
}

constexpr bool IsSdpKeyword(TOKEN name)
{
    return SdpKeywordIndex(name) != -1;
}

TOKEN GetSdpName(TOKEN token)
{
    auto name = NULL_NAME;
    if (token.isSdp())
    {
        auto keyword = token.getKeyword();
        if (keyword < ARRAYSIZE(SDP_KEYWORDS))
            name = SDP_KEYWORDS[keyword];
    }
    return name;
}

using SDP_BUFFER = STREAM_READER<const TOKEN>;
using SDP_RWBUFFER = STREAM_READER<TOKEN>;

template <typename STACK>
using SDP_STREAM = DATASTREAM<TOKEN, STACK>;

using TSDP_STREAM = DATASTREAM<TOKEN, SCHEDULER_STACK>;

template <typename STACK = SERVICE_STACK>
struct SDP_OPS
{
    TOKEN createToken(UINT8 keyword, UINT16 scope = 0)
    {
        return TOKEN::createScript(TF_SDP, keyword, scope);
    }

    template <typename STREAM>
    UINT32 writeKeyword(STREAM&& outStream, TOKEN name)
    {
        auto offset = outStream.count();
        outStream.append(createToken((UINT8)SdpKeywordIndex(name), 0));
        return offset;
    }

    template <typename STREAM>
    void writeLength(STREAM&& outStream, UINT32 offset)
    {
        auto&& token = outStream.at(offset);
        auto length = outStream.count() - offset;
        if (length > 1)
        {
            token.setScope(length);
        }
        else
        {
            DBGBREAK();
            outStream.trim();
        }
    }

    template <typename STREAM, typename ... Args>
    void writeSdpStream(STREAM&& outStream, TOKEN keyName, Args&& ... args)
    {
        auto lengthOffset = writeKeyword(outStream, keyName);
        int dummy[] = { (outStream.append(args), 0) ... }; dummy;
        writeLength(outStream, lengthOffset);
    }

    template <typename STREAM, typename T>
    void writeSdpStream(STREAM&& outStream, TOKEN name, STREAM_READER<T> args)
    {
        auto lengthOffset = writeKeyword(outStream, name);
        for (auto& string : args)
        {
            outStream.append(CreateServiceName(string));
        }
        writeLength(outStream, lengthOffset);
    }

    TOKEN parseSdpLine(USTRING line, SDP_LINE& sdpLine, UINT8 type = 0)
    {
        sdpLine.name = NULL_NAME;
        sdpLine.params.clear();

        if (type == 0)
        {
            type = line.readByte();
            ASSERT(line.readByte() == '=');
        }
        auto params = String.splitCharToArray(line, " ", sdpLine.params);

        if (type == 'm')
        {
            auto mtype = params.read();
            if (mtype == "audio")
                sdpLine.name = SDP_audio;
            else if (mtype == "video")
                sdpLine.name = SDP_video;
            else if (mtype == "application")
                sdpLine.name = SDP_application;
            else DBGBREAK();
        }
        else if (type == 'a')
        {
            auto nameString = String.splitChar(params.at(0), ':');
            auto name = FindName(nameString);

            if (IsSdpKeyword(name))
                sdpLine.name = name;
        }
        return sdpLine.name;
    }

    bool isMediaLine(const SDP_LINE& line) const
    {
        return line.name == SDP_video || line.name == SDP_audio || line.name == SDP_application;
    }

    const SDP_LINE& findSdpLine(STREAM_READER<const SDP_LINE> sdpLines, TOKEN name)
    {
        for (auto& line : sdpLines)
        {
            if (line.name == name)
                return line;
        }
        return NullRef<SDP_LINE>();
    }

    template <typename F, typename ... Args>
    void findSdpLine(STREAM_READER<const SDP_LINE> sdpLines, TOKEN name, F func, Args&& ... args)
    {
        for (auto& line : sdpLines)
        {
            if (line.name == name)
                func(line, args ...);
        }
    }

    template <typename SDP>
    TOKEN_BUFFER findInternal(SDP&& tokenBuffer, TOKEN name)
    {
        TOKEN_BUFFER result;
        auto keyword = SdpKeywordIndex(name);
        ASSERT(keyword != -1);
        while (tokenBuffer)
        {
            auto token = tokenBuffer.at(0);
            if (GetSdpName(token) == name)
            {
                tokenBuffer.shift();
                ASSERT(token.getScope() > 1);
                auto length = token.getScope() - 1;
                result = TOKEN_BUFFER(tokenBuffer.data(), length);
                tokenBuffer.read(length);
                break;
            }
            else tokenBuffer.read(token.getScope());
        }
        return result;
    }

    SDP_BUFFER find(SDP_BUFFER sdpBuffer, TOKEN name)
    {
        return findInternal(sdpBuffer, name);
    }

    template <typename FUNC, typename ... ARGS>
    void findMany(SDP_BUFFER sdpBuffer, TOKEN name, FUNC callback, ARGS&& ... args)
    {
        while (auto result = findInternal(sdpBuffer, name))
        {
            callback(result, args ...);
        }
    }

    template <typename STREAM>
    void addExtmap(STREAM&& extmapStream, TOKEN id, TOKEN url)
    {
        auto buffer = extmapStream.toBuffer();
        auto exists = false;
        for (UINT32 i = 0; i < buffer.length(); i += 2)
        {
            if (buffer.at(i) == id)
            {
                exists = true;
                break;
            }
        }

        if (exists == false)
        {
            extmapStream.append(id);
            extmapStream.append(url);
        }
    }

    template <typename STREAM, typename EXTMAP>
    void parseSdp(STREAM_READER<const SDP_LINE> sdpLines, EXTMAP&& extmapStream, STREAM&& sdpStream)
    {
        auto sdpLinesCopy = sdpLines;
        auto&& firstLine = sdpLines.at(0);
        TDATASTREAM<TOKEN> ssrcStream;

        if (isMediaLine(firstLine))
        {
            sdpLines.shift();
            auto ssrcLength = writeKeyword(ssrcStream, SDP_ssrc);
            findSdpLine(sdpLines, SDP_ssrc, [](const SDP_LINE& sdpLine, TDATASTREAM<TOKEN>& ssrcStream)
                {
                    auto value = String.toNumber(sdpLine.params.at(0));
                    auto handle = Tokens.createNumber(value);// CreateNumberToken<STACK>(value);
                    if (ssrcStream.toBuffer().contains(handle) == false)
                    {
                        ssrcStream.append(handle);
                    }
                }, ssrcStream);
            writeLength(ssrcStream, ssrcLength);
        }

        while (sdpLines)
        {
            auto&& sdp = sdpLines.read();
            auto params = sdp.params.toBuffer();
            auto name = sdp.name;

            if (name == SDP_extmap)
            {
                auto id = Tokens.createNumber(String.toNumber(params.read()));
                auto url = FindName(params.read());
                ASSERT(url);
                addExtmap(extmapStream, id, url);
            }
            else if (name == SDP_group)
            {
                if (params.read() == "BUNDLE")
                {
                    writeSdpStream(sdpStream, SDP_BUNDLE, params);
                }
                else DBGBREAK();
            }
            else if (name == SDP_rtpmap)
            {
                TOKEN currentMid = NULL_NAME;
                auto packetType = (UINT32)String.toNumber(params.read());
                auto codecString = params.read();

                auto codecParams = String.splitCharToArray(codecString, "/", TSTRING_STREAM());
                auto codecType = codecParams.at(0);

                if (codecType == "opus" || codecType == "H264")
                {
                    if (auto&& midLine = findSdpLine(sdpLinesCopy, SDP_mid))
                    {
                        auto bundleConfig = find(sdpStream.toBuffer(), SDP_BUNDLE);
                        ASSERT(bundleConfig);
                        currentMid = CreateCustomName<STACK>(midLine.params.at(0));
                        if (currentMid == bundleConfig.at(0))
                        {
                            if (auto&& iceLine = findSdpLine(sdpLinesCopy, SDP_ice_ufrag))
                            {
                                //if (context.remoteIceUfrag.count() == 0) // XXX move this logic to WebRTC code
                                //	context.remoteIceUfrag.writeStream(iceLine.params.at(0));

                                writeSdpStream(sdpStream, SDP_ice_ufrag, CreateCustomName<STACK>(iceLine.params.at(0)));
                            }
                            if (auto&& iceLine = findSdpLine(sdpLinesCopy, SDP_ice_pwd))
                            {
                                //if (context.remoteIcePassword.count() == 0) // XXX move this logic to WebRTC code
                                //	context.remoteIcePassword.writeStream(iceLine.params.at(0));

                                writeSdpStream(sdpStream, SDP_ice_pwd, CreateCustomName<STACK>(iceLine.params.at(0)));
                            }
                            if (auto&& fingerprint = findSdpLine(sdpLinesCopy, SDP_fingerprint))
                            {
                                LOCAL_STREAM<64> hexString;
                                auto&& inputString = fingerprint.params.at(1);
                                while (inputString)
                                {
                                    hexString.writeHexString(String.splitChar(inputString, ':'));
                                }
                                writeSdpStream(sdpStream, SDP_fingerprint, String.parseLiteral<STACK>(fingerprint.params.at(0)),
                                    String.parseLiteral<STACK>(hexString.toBuffer()));
                            }
                        }
                    }

                    auto mediaLength = writeKeyword(sdpStream, firstLine.name); // SDP_VIDEO or SDP_AUDIO

                    writeSdpStream(sdpStream, SDP_mid, currentMid);
                    writeSdpStream(sdpStream, SDP_rtpmap, Tokens.createNumber(packetType));
                    writeSdpStream(sdpStream, SDP_codec, codecParams);

                    sdpStream.writeBuffer(ssrcStream.toBuffer());

                    auto rtcpLength = writeKeyword(sdpStream, SDP_rtcp_fb);
                    findSdpLine(sdpLines, SDP_rtcp_fb, [](const SDP_LINE& sdpLine, STREAM&& config, UINT32 packetType)
                        {
                            auto params = sdpLine.params.toBuffer();
                            auto typeString = params.read();
                            if (String.toNumber(typeString) == (INT32)packetType)
                            {
                                auto&& type1 = params.read();
                                auto&& type2 = params ? params.read() : "";

                                auto typeName = NULL_NAME;
                                if (type1 == "nack")
                                {
                                    typeName = SDP_nack;
                                    if (type2 == "pli") typeName = SDP_nack_pli;
                                    else if (type2 == "sli") typeName = SDP_nack_sli;
                                    else if (type2 == "rpsi") typeName = SDP_nack_rpsi;
                                    else if (type2) DBGBREAK();
                                }
                                else if (type1 == "ccm")
                                {
                                    if (type2 == "fir") typeName = SDP_ccm_fir;
                                    else if (type2 == "tmmbr") typeName = SDP_ccm_tmmbr;
                                    else if (type2 == "tstr") typeName = SDP_ccm_tstr;
                                    else DBGBREAK();
                                }
                                else
                                {
                                    typeName = CreateCustomName<STACK>(type1);
                                }
                                config.append(typeName);
                            }
                        }, sdpStream, packetType);
                    writeLength(sdpStream, rtcpLength);
                    findSdpLine(sdpLines, SDP_fmtp, [](const SDP_LINE& sdpLine, STREAM&& config, UINT32 packetType)
                        {
                            auto params = sdpLine.params.toBuffer();
                            auto fmtpType = String.toNumber(params.read());
                            auto pairsString = params.read();
                            if (fmtpType == (INT32)packetType)
                            {
                                auto fmtpLength = Sdp.writeKeyword(config, SDP_fmtp);
                                while (pairsString)
                                {
                                    auto&& pair = String.splitChar(pairsString, ';');
                                    auto&& pairName = String.splitChar(pair, '=');

                                    config.append(CreateCustomName<STACK>(pairName));
                                    auto value = String.toHexNumber(pair);
                                    config.append(Tokens.createNumber(value));
                                }
                                Sdp.writeLength(config, fmtpLength);
                            }
                            else
                            {
                                while (pairsString)
                                {
                                    auto&& pair = String.splitChar(pairsString, ';');
                                    auto&& pairName = String.splitChar(pair, '=');

                                    if (pairName == "apt")
                                    {
                                        if (String.toNumber(pair) == (INT32)packetType)
                                        {
                                            Sdp.writeSdpStream(config, SDP_rtx, Tokens.createNumber(fmtpType));
                                        }
                                    }
                                }
                            }
                        }, sdpStream, packetType);

                    writeLength(sdpStream, mediaLength);
                }
            }
            else if (name == SDP_candidate)
            {
            ICE_CANDIDATE iceCandidate;
                parseIceCandidate(sdp, iceCandidate);
            }
            else if (name == SDP_control) 
            {
                auto lengthOffset = writeKeyword(sdpStream, SDP_control);
                auto pairsString = params.read();
                while (pairsString)
                {
                    auto&& pair = String.splitChar(pairsString, ';');
                    auto&& pairName = String.splitChar(pair, '=');

                    sdpStream.append(CreateCustomName<STACK>(pairName));

                    if (pair)
                    {
                        auto value = String.toHexNumber(pair);
                        sdpStream.append(Tokens.createNumber(value));
                    }
                    else
                    {
                        sdpStream.append(Null);
                    }
                }
                writeLength(sdpStream, lengthOffset);
            }
        }
    }

    template <typename STREAM>
    TOKEN_BUFFER parseSdp(USTRING sdpString, STREAM&& sdpStream)
    {
        TDATASTREAM<TOKEN> extmapStream;
        extmapStream.reserve(16);

        TDATASTREAM<SDP_LINE> sdpLines;
        sdpLines.reserve(64);

        sdpStream.clear();
        while (sdpString)
        {
            SDP_LINE sdpLine;
            auto line = String.splitString(sdpString, CRLF);
            if (line)
            {
                parseSdpLine(line, sdpLine);
                if (sdpLine.name)
                {
                    if (isMediaLine(sdpLine))
                    {
                        parseSdp(sdpLines.toBuffer(), extmapStream, sdpStream);
                        sdpLines.clear().append(sdpLine);
                    }
                    else
                    {
                        sdpLines.append(sdpLine);
                    }
                }
            }
        }
        parseSdp(sdpLines.toBuffer(), extmapStream, sdpStream);
        auto lengthOffset = writeKeyword(sdpStream, SDP_extmap);
        sdpStream.writeBuffer(extmapStream.toBuffer());
        writeLength(sdpStream, lengthOffset);

        return sdpStream.toBuffer();
    }

    template <typename BUFFER>
    TOKEN_BUFFER getSdp(BUFFER&& configStream, TOKEN name)
    {
        TOKEN_BUFFER result;
        for (UINT32 i = 0; i < configStream.length(); i++)
        {
            auto token = configStream.at(i);
            if (GetSdpName(token) == name)
            {
                result = TOKEN_BUFFER(configStream.data(), i, token.getScope() - 1);
            }
        }
        return result;
    }

    template <typename STREAM>
    USTRING formatIceCandidate(STREAM& outString, const ICE_CANDIDATE& candidate)
    {
        auto streamOffset = outString.getPosition();
        outString.writeMany("a=candidate:", candidate.foundation, " ", COMPONENT_ID, " udp ", candidate.priority, " ");
        auto addrString = String.formatIPAddress(*candidate.candidate.address(), outString);
        outString.writeMany(" ", SWAP16(candidate.candidate._address.sin_port), " typ ",
            candidate.type == ICE_TYPE::HOST ? "host" :
            candidate.type == ICE_TYPE::SERVER_REFLX ? "srflx" : "prflx");

        if (candidate.type == ICE_TYPE::SERVER_REFLX || candidate.type == ICE_TYPE::PEER_REFLX)
        {
            outString.writeString(" raddr ");
            String.formatIPAddress(*candidate.base.address(), outString);
            outString.writeMany(" rport ", SWAP16(candidate.base._address.sin_port));
        }
        outString.writeString(ESC_CRLF);
        return streamOffset.toBuffer();
    }

    bool parseIceCandidate(const SDP_LINE& sdpLine, ICE_CANDIDATE& iceCandidate)
    {
        auto result = false;
        do
        {
            auto&& parts = sdpLine.params.toBuffer();

            iceCandidate.foundation = String.toNumber(parts.read());

            auto componentId = String.toNumber(parts.read());
            ASSERT(componentId == 1);

            auto protocol = parts.read();
            if (protocol != "udp")
                break;

            iceCandidate.priority = (UINT32)String.toNumber(parts.read());

            auto ipAddress = String.parseIPAddress(parts.read());
            auto port = (UINT16)String.toNumber(parts.read());

            iceCandidate.candidate = IPENDPOINT(ipAddress, port);
            //iceCandidate.candidate._address.sin_addr.s_addr = swap32(ipAddress);

            //iceCandidate.candidate.sin_port = swap16(port);

            while (parts)
            {
                auto paramName = parts.read();
                if (paramName == "typ")
                {
                    auto typeValue = parts.read();
                    iceCandidate.type = typeValue == "host" ? ICE_TYPE::HOST
                        : typeValue == "srflx" ? ICE_TYPE::SERVER_REFLX
                        : typeValue == "prflx" ? ICE_TYPE::PEER_REFLX
                        : ICE_TYPE::UNKNOWN;

                    ASSERT(iceCandidate.type != ICE_TYPE::UNKNOWN);
                }
                else if (paramName == "ufrag")
                {
                    ASSERT(parts);
                    iceCandidate.ufrag.writeBytes(parts.read());
                }
                else if (paramName == "raddr")
                {
                    ASSERT(parts);
                    ASSERT(iceCandidate.type != ICE_TYPE::HOST);
                    auto ipAddress = String.parseIPAddress(parts.read());
                    iceCandidate.base.setAddress(ipAddress);
                }
                else if (paramName == "rport")
                {
                    ASSERT(parts);
                    auto port = (UINT16)String.toNumber(parts.read());
                    iceCandidate.base.setPort(port);
                }
                else if (paramName == "generation" || paramName == "network-id" || paramName == "network-cost")
                {
                    parts.shift();
                }
                else DBGBREAK();
            }
            result = true;
        } while (false);
        return result;
    }
};


/*


v=0                   
o=- 20519 0 IN IP4 0.0.0.0                 
s=-                 
t=0 0                                      
a=group:BUNDLE m0 m1 m2                    
a=group:LS m0 m1                           
a=ice-options:trickle                      
                                           
****** Audio m=line *********              
                                           
m=audio 54609 UDP/TLS/RTP/SAVPF 109        
c=IN IP4 203.0.113.141                     
a=mid:m0                                   
a=msid:ma ta                               
a=sendonly                                 
a=rtpmap:109 opus/48000/2                  
a=maxptime:120                             
a=ice-ufrag:074c6550                       
a=ice-pwd:a28a397a4c3f31747d1ee3474af08a068
a=fingerprint:sha-256 19:E2:1C:3B:4B:9F:81:E6:B8:5C:F4:A5:A8:D8:73:04:BB:05:2F:70:9F:04:A9:0E:05:E9:26:33:E8:70:88:A2
a=setup:actpass                            
a=tls-id:89J2LRATQ3ULA24G9AHWVR31VJWSLB68  
a=rtcp-mux                                 
a=rtcp-rsize                               
a=extmap:1 urn:ietf:params:rtp-hdrext:ssrc-audio-level                                
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid                            
a=candidate:0 1 UDP 2113667327 192.0.2.4 61665 typ host                             
a=candidate:1 1 UDP 694302207 203.0.113.141 54609 typ srflx raddr 192.0.2.4 rport 61665
a=end-of-candidates                        
                                           
****** Video-1 m=line *********            
                                           
m=video 0 UDP/TLS/RTP/SAVPF 98 100         
c=IN IP4 203.0.113.141                     
a=bundle-only                              
a=mid:m1                                   
a=msid:ma tb                               
a=sendonly                                 
a=rtpmap:98 VP8/90000                      
a=fmtp:98 max-fr=30                        
a=rtpmap:100 VP8/90000                     
a=fmtp:100 max-fr=15                       
a=rtcp-fb:* nack                           
a=rtcp-fb:* nack pli                       
a=rtcp-fb:* ccm fir                        
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid                            
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id                  
a=rid:1 send pt=98;max-width=1280;max-height=720                                 
a=rid:2 send pt=100;max-width=640;max-height=480                                 
a=simulcast:send 1;~2                      
                                           
****** Video-2 m=line *********            
                                           
m=video 0 UDP/TLS/RTP/SAVPF 101 102        
c=IN IP4 203.0.113.141                     
a=bundle-only                              
a=mid:m2                                   
a=msid:ma tc                               
a=sendonly                                 
a=rtpmap:101 H264/90000                    
a=rtpmap:102 H264/90000                    
a=fmtp:101 profile-level-id=42401f;packetization-mode=0;max-fr=30   
a=fmtp:102 profile-level-id=42401f;packetization-mode=1;max-fr=15   
a=rtcp-fb:* nack                           
a=rtcp-fb:* nack pli                       
a=rtcp-fb:* ccm fir                        
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid                            
a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id                  
a=rid:3 send pt=101;max-width=1280;max-height=720                                 
a=rid:4 send pt=102;max-width=640;max-height=360                                 
a=simulcast:send 3;4                       
                                           
                                           
                                           
                                           
                                           




*/