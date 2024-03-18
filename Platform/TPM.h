
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

//
// Routines to work with TPM 2.0
//

#include "Types.h"
#include <tbs.h>
#include <wbcl.h>
#include "TpmTypes.h"

constexpr UINT32 EC256_PUBLICKEY_LENGTH = 64;
using EC256_PUBLICKEY = UINT8[EC256_PUBLICKEY_LENGTH];

struct TPMOPS;
extern TPMOPS TPM;

using TPM_HANDLE = UINT32;

constexpr static UINT32 TPM_COUNTER_TICKET =   0x01801001;
constexpr static UINT32 TPM_COUNTER_NODE_ID =  0x01801002;
constexpr static UINT32 TPM_COUNTER_ROLE_ID =  0x01801003;
constexpr static UINT32 TPM_COUNTER_BLOCK_ID = 0x01801004;

struct TPMOPS
{
    TBS_HCONTEXT tbsContext;

    TPM_HANDLE ECDHhandle;
    EC256_PUBLICKEY ECDHpublicKey{ 0 };

    AES_GCM KeyCipher;

    TPMOPS() {}

    void defineCounter(UINT32 index, STREAM_READER<const UINT32> indexesFound)
    {
        if (indexesFound.findIndex(index) == -1)
        {
            defineCounter(index);
        }
    }

    bool init()
    {
        auto result = false;
        do
        {
            TBS_CONTEXT_PARAMS2 param;
            param.includeTpm12 = TRUE;
            param.version = TBS_CONTEXT_VERSION_TWO;
            auto rc = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&param, &tbsContext);
            if (rc != TBS_SUCCESS) break;

            TPM_DEVICE_INFO deviceInfo;
            deviceInfo.structVersion = TPM_VERSION_20;
            rc = Tbsi_GetDeviceInfo(sizeof(deviceInfo), &deviceInfo);
            if (rc != TBS_SUCCESS) break;

            ECDHhandle = TPM.createECDHhandle(NULL_BUFFER, WriteMany(STATEOS_BRAND, " - ECDH"), ECDHpublicKey);
            deriveKey(ECDHhandle, "keygen", KeyCipher);

            auto existingIndexes = getHandles(TPM2_HR_NV_INDEX);
            defineCounter(TPM_COUNTER_TICKET, existingIndexes);
            defineCounter(TPM_COUNTER_BLOCK_ID, existingIndexes);
            defineCounter(TPM_COUNTER_NODE_ID, existingIndexes);
            defineCounter(TPM_COUNTER_ROLE_ID, existingIndexes);

            getCertificate();

            EKauthSession = getEndorsementAuth();
            if (EKauthSession == TPM2_RH_NULL) break;

            result = true;;
        } while (false);
        //ASSERT(result);
        return result;
    }

    bool deriveKey(TPM_HANDLE keyHandle, BUFFER context, AES_GCM& cipher)
    {
        return deriveKey(keyHandle, ECDHpublicKey, context, cipher);
    }

    BUFFER deriveKey(TPM_HANDLE keyHandle, BUFFER context, U512& keyDerived)
    {
        return deriveKey(keyHandle, ECDHpublicKey, context, keyDerived);
    }

    BUFFER deriveKey(TPM_HANDLE privateKey, BUFFER publicKey, BUFFER context, U512& keyDerived)
    {
        BUFFER result;
        LOCAL_STREAM<64> sharedSecret;
        auto response = submitCommand(TPM2_CC_ECDH_ZGen, TPM2_ST_SESSIONS, [](BYTESTREAM& request, TPM_HANDLE privateKey, BUFFER publicKey)
            {
                request.beWriteU32(privateKey);
                TPM.setPassword(request, NULL_BUFFER);

                auto lengthOffset = request.saveOffset(2);
                TPM.writeTPM2B(request, publicKey.readBytes(32));
                TPM.writeTPM2B(request, publicKey.readBytes(32));
                lengthOffset.writeLength();

            }, privateKey, publicKey);
        if (response)
        {
            response = getSessionResponse(response);
            auto zData = readTPM2B(response);
            sharedSecret.writeBytes(readTPM2B(zData));
            sharedSecret.writeBytes(readTPM2B(zData));

            result = HmacSha512(keyDerived, sharedSecret.toBuffer(), context, "send/recv iv");
        }

        return result;
    }

    bool deriveKey(TPM_HANDLE privateKey, BUFFER publicKey, BUFFER context, AES_GCM& cipher)
    {
        auto result = false;
        U512 derivedKey;
        if (auto keyData = deriveKey(privateKey, publicKey, context, derivedKey))
        {
            cipher.init(keyData.readBytes(32), keyData.readBytes(12));
            result = true;
        }
        return result;
    }

    BUFFER sign(UINT32 keyHandle, BUFFER signHash, BYTESTREAM&& outStream)
    {
        ASSERT(signHash.length() == SHA256_HASH_LENGTH);
        auto response = submitCommand(TPM2_CC_Sign, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 keyHandle, BUFFER signHash)
            {
                request.beWriteU32(keyHandle);
                TPM.setPassword(request, NULL_BUFFER);

                TPM.writeTPM2B(request, signHash);
                request.beWriteU16(TPM2_ALG_NULL);
                request.beWriteU16(TPM2_ST_HASHCHECK);
                request.beWriteU32(TPM2_RH_OWNER);
                TPM.writeTPM2B(request, NULL_BUFFER);
            }, keyHandle, signHash);
        ASSERT(response);
        if (response)
        {
            response = getSessionResponse(response);
            auto alg = response.beReadU16();
            alg = response.beReadU16();
            auto pointR = readTPM2B(response);
            outStream.writeBytes(pointR);
            auto pointS = readTPM2B(response);
            outStream.writeBytes(pointS);
        }
        return outStream.toBuffer();
    }

    bool verifySignature(UINT32 keyHandle, BUFFER signHash, BUFFER signature)
    {
        bool result = false;
        auto response = submitCommand(TPM2_CC_VerifySignature, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 keyHandle, BUFFER signHash, BUFFER signature)
            {
                request.beWriteU32(keyHandle);
                TPM.setPassword(request, NULL_BUFFER);

                TPM.writeTPM2B(request, signHash);
                request.beWriteU16(TPM2_ALG_ECDSA);
                request.beWriteU16(TPM2_ALG_SHA256);
                TPM.writeTPM2B(request, signature.readBytes(32));
                TPM.writeTPM2B(request, signature.readBytes(32));
            }, keyHandle, signHash, signature);

        if (response)
        {
            auto tag = response.beReadU16();
            ASSERT(tag == TPM2_ST_HASHCHECK);
            result = true;
        }
        return result;
    }

    BUFFER getSessionResponse(BUFFER response)
    {
        auto length = response.beReadU32();
        return response.readBytes(length);
    }

    BUFFER getSessionResponse(UINT32& handle, BUFFER response)
    {
        handle = response.beReadU32();
        return getSessionResponse(response);
    }

    template <typename FUNC, typename ... ARGS>
    BUFFER submitCommand(UINT32 cmd, UINT16 tag, FUNC handler, ARGS&& ... args)
    {
        BUFFER response;

        auto&& commandStream = ByteStream(4096);

        commandStream.beWriteU16(tag);
        auto lengthOffset = commandStream.saveOffset(4);
        commandStream.beWriteU32(cmd);

        handler(commandStream, args ...);

        lengthOffset.writeLength(6);

        UINT32 responseBytes = commandStream.size();
        auto result = Tbsip_Submit_Command(tbsContext, TBS_COMMAND_LOCALITY_ZERO, TBS_COMMAND_PRIORITY_NORMAL,
            commandStream.address(), commandStream.count(), commandStream.address(), &responseBytes);

        if (result == TBS_SUCCESS)
        {
            response = { commandStream.address(), responseBytes };
            auto tag = response.beReadU16();
            auto length = response.beReadU32();
            ASSERT(length == responseBytes);
            auto status = response.beReadU32();
            if (status != TPM2_RC_SUCCESS)
            {
                printf("status: 0x%x\n", status);
                response = NULL_BUFFER;
            }
        }
        return response;
    }

    void setAuth(BYTESTREAM& request, TPM_HANDLE handle1, TPM_HANDLE handle2)
    {
        auto offset = request.saveOffset(4);
        //TPMS_AUTH_COMMAND
        request.beWriteU32(handle1);
        request.beWriteU16(0); // nonce
        request.writeByte(1); // attr
        request.beWriteU16(0);

        //TPMS_AUTH_COMMAND
        request.beWriteU32(handle2);
        request.beWriteU16(0); // nonce
        request.writeByte(1); // attr
        request.beWriteU16(0);

        offset.writeLength(0);
    }

    void setPassword(BYTESTREAM& request, BUFFER password, UINT32 handleCount = 1)
    {
        auto offset = request.saveOffset(4);

        for (UINT32 i = 0; i < handleCount; i++)
        {
            //TPMS_AUTH_COMMAND
            request.beWriteU32(TPM2_RH_PW);
            request.beWriteU16(0); // nonce
            request.writeByte(1); // attr
            request.beWriteU16(password.length());
            request.writeBytes(password);
        }
        offset.writeLength(0);
    }

    void defineNVSpace(UINT32 index, BUFFER password, UINT16 size, UINT32 type = TPM2_NT_ORDINARY)
    {
        type = _pdep_u32(type, TPMA_NV_TPM2_NT_MASK);
        auto response = submitCommand(TPM2_CC_NV_DefineSpace, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 index, UINT16 size, UINT32 type, BUFFER password)
            {
                request.beWriteU32(TPM2_RH_OWNER);
                TPM.setPassword(request, NULL_BUFFER);

                request.beWriteU16(password.length());
                request.writeBytes(password);

                //TPMS_NV_PUBLIC
                auto offset = request.saveOffset(2);
                request.beWriteU32(index);
                request.beWriteU16(TPM2_ALG_SHA256);
                request.beWriteU32(TPMA_NV_AUTHREAD | TPMA_NV_AUTHWRITE | type);
                request.beWriteU16(0);
                request.beWriteU16(size);
                offset.writeLength();

            }, index, size, type, password);
    }

    UINT64 defineCounter(UINT32 index)
    {
        defineNVSpace(index, NULL_BUFFER, 8, TPM2_NT_COUNTER);
        return incrementIndex(index);
    }

    void writeNVIndex(UINT32 index, BUFFER password, BUFFER data)
    {
        auto response = submitCommand(TPM2_CC_NV_Write, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 index, BUFFER password, BUFFER data)
            {
                request.beWriteU32(index);
                request.beWriteU32(index);

                TPM.setPassword(request, password);

                request.beWriteU16(data.length());
                request.writeBytes(data);

                request.beWriteU16(0); // offset

            }, index, password, data);
    }

    UINT64 incrementIndex(UINT32 index)
    {
        auto response = submitCommand(TPM2_CC_NV_Increment, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 index)
            {
                request.beWriteU32(index);
                request.beWriteU32(index);

                TPM.setPassword(request, NULL_BUFFER);

            }, index);

        auto value = readNVIndex(index, 8);
        return value.beReadU64();
    }

    BUFFER readNVIndex(UINT32 index, UINT32 dataSize = 0)
    {
        dataSize = dataSize ? dataSize : readNVpublic(index);
        auto response = submitCommand(TPM2_CC_NV_Read, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 index, UINT16 size)
            {
                request.beWriteU32(index);
                request.beWriteU32(index);

                TPM.setPassword(request, NULL_BUFFER);

                request.beWriteU16(size);
                request.beWriteU16(0);

            }, index, dataSize);
        if (response)
        {
            response = getSessionResponse(response);
            response = readTPM2B(response);
            ASSERT(response.length() == dataSize);
        }
        return response;
    }

    BUFFER readNVIndex2(UINT32 index)
    {
        auto response = submitCommand(TPM2_CC_NV_Read, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 index)
            {
                request.beWriteU32(index);

            }, index);

        return response;
    }

    void buildECDSAtemplate(BYTESTREAM& request, BUFFER context)
    {
        //TPM2B_PUBLIC
        auto templateOffset = request.saveOffset(2);

        request.beWriteU16(TPM2_ALG_ECC);
        request.beWriteU16(TPM2_ALG_SHA256);
        request.beWriteU32(TPMA_OBJECT_SIGN_ENCRYPT| TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDPARENT | 
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_SENSITIVEDATAORIGIN);

        ASSERT(context.length() == SHA256_HASH_LENGTH);
        request.beWriteU16(SHA256_HASH_LENGTH);
        request.writeBytes(context);

        // TPMS_ECC_PARMS
        request.beWriteU16(TPM2_ALG_NULL); 
        request.beWriteU16(TPM2_ALG_ECDSA);
        request.beWriteU16(TPM2_ALG_SHA256);
        request.beWriteU16(TPM2_ECC_NIST_P256);
        request.beWriteU16(TPM2_ALG_NULL);

        // TPMS_ECC_POINT
        request.beWriteU16(0);
        request.beWriteU16(0);

        templateOffset.writeLength();
    }

    void buildECDHtemplate(BYTESTREAM& request, BUFFER context)
    {
        //TPM2B_PUBLIC
        auto templateOffset = request.saveOffset(2);

        request.beWriteU16(TPM2_ALG_ECC);
        request.beWriteU16(TPM2_ALG_SHA256);
        request.beWriteU32(TPMA_OBJECT_DECRYPT | TPMA_OBJECT_USERWITHAUTH | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_SENSITIVEDATAORIGIN);

        ASSERT(context.length() == SHA256_HASH_LENGTH);
        request.beWriteU16(SHA256_HASH_LENGTH);
        request.writeBytes(context);

        // TPMS_ECC_PARMS
        request.beWriteU16(TPM2_ALG_NULL);
        request.beWriteU16(TPM2_ALG_NULL);
        request.beWriteU16(TPM2_ECC_NIST_P256);
        request.beWriteU16(TPM2_ALG_NULL);

        // TPMS_ECC_POINT
        request.beWriteU16(0);
        request.beWriteU16(0);

        templateOffset.writeLength();
    }

    void buildDefaultECCtemplate(BYTESTREAM& request)
    {
        //TPM2B_PUBLIC
        auto templateOffset = request.saveOffset(2);

        request.beWriteU16(TPM2_ALG_ECC);
        request.beWriteU16(TPM2_ALG_SHA256);
        request.beWriteU32(TPMA_OBJECT_DECRYPT | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_ADMINWITHPOLICY |
            TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_RESTRICTED);
        request.beWriteU16(32);
        request.writeBytes(ECC_DEFAULT_DIGEST);

        // TPMS_ECC_PARMS
        request.beWriteU16(TPM2_ALG_AES);
        request.beWriteU16(128);
        request.beWriteU16(TPM2_ALG_CFB);
        request.beWriteU16(TPM2_ALG_NULL);
        request.beWriteU16(TPM2_ECC_NIST_P256);
        request.beWriteU16(TPM2_ALG_NULL);

        // TPMS_ECC_POINT
        request.beWriteU16(32);
        request.writeBytes(ZeroBytes, 32);
        request.beWriteU16(32);
        request.writeBytes(ZeroBytes, 32);

        templateOffset.writeLength();
    }

    constexpr static UINT8 ECC_DEFAULT_DIGEST[] = { 0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xB3, 0xF8, 0x1A, 0x90, 0xCC, 0x8D,
                                        0x46, 0xA5, 0xD7, 0x24, 0xFD, 0x52, 0xD7, 0x6E, 0x06, 0x52, 0x0B, 0x64, 0xF2, 
                                        0xA1, 0xDA, 0x1B, 0x33, 0x14, 0x69, 0xAA };

    BUFFER readTPM2B(BUFFER& data)
    {
        auto length = data.beReadU16();
        return data.readBytes(length);
    }

    void writeTPM2B(BYTESTREAM& outStream, BUFFER data)
    {
        outStream.beWriteU16(data.length());
        outStream.writeBytes(data);
    }

    inline void writeHandle(BYTESTREAM& outStream, UINT32 handle) { outStream.beWriteU32(handle); }
    inline void writeAlg(BYTESTREAM& outStream, UINT16 alg = TPM2_ALG_NULL) { outStream.beWriteU16(alg); }

    BUFFER parsePublicData(BUFFER data, BYTESTREAM&& keyStream)
    {
        auto type = data.beReadU16();

        auto nameAlg = data.beReadU16();

        auto objectAttributes = data.beReadU32();
        auto policy = readTPM2B(data);

        auto symmetricAlg = data.beReadU16();
        if (symmetricAlg != TPM2_ALG_NULL)
        {
            auto keySize = data.beReadU16();
            auto mode = data.beReadU16();
        }

        UINT16 signAlg = TPM2_ALG_NULL;
        UINT16 signHash = TPM2_ALG_NULL;

        if (type == TPM2_ALG_ECC)
        {
            // ecc params

            signAlg = data.beReadU16();
            if (signAlg != TPM2_ALG_NULL)
            {
                signHash = data.beReadU16();
            }

            auto eccCurve = data.beReadU16();
            auto kdfAlg = data.beReadU16();
            if (kdfAlg != TPM2_ALG_NULL)
            {
                auto kdfHash = data.beReadU16();
            }

            auto pointX = readTPM2B(data);
            auto pointY = readTPM2B(data);

            keyStream.writeBytes(pointX);
            keyStream.writeBytes(pointY);

            ASSERT(data.length() == 0);
            return keyStream.toBuffer();
        }
        else if (type == TPM2_ALG_RSA)
        {
            signAlg = data.beReadU16();
            if (signAlg != TPM2_ALG_NULL)
            {
                signHash = data.beReadU16();
            }

            auto keyBits = data.beReadU16();
            auto exponent = data.beReadU32();
            auto keyBytes = data.beReadU16();

            auto key = data.readBytes(keyBytes);
            keyStream.writeBytes(key);
            return keyStream.toBuffer();
        }
        else DBGBREAK();
        return NULL_BUFFER;
    }

    UINT32 createECDSAhandle(BUFFER authPassword, BUFFER contextData, BYTESTREAM&& publicKey)
    {
        SHA256_DATA hashBuffer;
        auto contextHash = Sha256ComputeHash(hashBuffer, contextData);

        auto response = submitCommand(TPM2_CC_CreatePrimary, TPM2_ST_SESSIONS, [](BYTESTREAM& request, BUFFER authPassword, BUFFER context)
            {
                request.beWriteU32(TPM2_RH_OWNER);
                TPM.setPassword(request, NULL_BUFFER);

                //TPM2B_SENSITIVE_CREATE
                auto authOffset = request.saveOffset(2);
                request.beWriteU16(authPassword.length());
                request.writeBytes(authPassword);
                request.beWriteU16(0); // no sensitive data
                authOffset.writeLength();

                //TMP2B_PUBLIC
                TPM.buildECDSAtemplate(request, context);

                request.beWriteU16(0); // no outside info
                request.beWriteU32(0); // no pcr
            }, authPassword, contextHash);

        UINT32 handle;
        response = getSessionResponse(handle, response);

        auto publicData = readTPM2B(response);
        parsePublicData(publicData, std::move(publicKey));

        auto creationData = readTPM2B(response);

        auto digestOut = readTPM2B(response);

        auto ticketTag = response.beReadU16();
        auto ticketHierarchy = response.beReadU32();
        auto ticketDigest = readTPM2B(response);

        auto name = readTPM2B(response);

        return handle;
    }

    UINT8 EKpublicKeyEC[64];
    UINT32 openEKhandleEC()
    {
        UINT32 handle = 0;
        auto response = submitCommand(TPM2_CC_CreatePrimary, TPM2_ST_SESSIONS, [](BYTESTREAM& request)
            {
                request.beWriteU32(TPM2_RH_OWNER);
                TPM.setPassword(request, NULL_BUFFER);

                auto authOffset = request.saveOffset(2);
                request.beWriteU16(0); // no password
                request.beWriteU16(0); // no sensitive data
                authOffset.writeLength();

                TPM.buildDefaultECCtemplate(request);

                request.beWriteU16(0); // no outside info
                request.beWriteU32(0); // no pcr
            });
        ASSERT(response);
        if (response)
        {
            handle = response.beReadU32();
            auto responseBytes = response.beReadU32();

            auto publicData = readTPM2B(response);
            parsePublicData(publicData, EKpublicKeyEC);
        }
        return handle;
    }

    UINT32 createECDHhandle(BUFFER authPassword, BUFFER contextData, BYTESTREAM&& publicKey)
    {
        SHA256_DATA hashBuffer;
        auto contextHash = Sha256ComputeHash(hashBuffer, contextData);

        auto response = submitCommand(TPM2_CC_CreatePrimary, TPM2_ST_SESSIONS, [](BYTESTREAM& request, BUFFER authPassword, BUFFER context)
            {
                request.beWriteU32(TPM2_RH_OWNER);
                TPM.setPassword(request, NULL_BUFFER);

                //TPM2B_SENSITIVE_CREATE
                auto authOffset = request.saveOffset(2);
                request.beWriteU16(authPassword.length());
                request.writeBytes(authPassword);
                request.beWriteU16(0); // no sensitive data
                authOffset.writeLength();

                //TMP2B_PUBLIC
                TPM.buildECDHtemplate(request, context);

                request.beWriteU16(0); // no outside info
                request.beWriteU32(0); // no pcr
            }, authPassword, contextHash);

        ASSERT(response);
        UINT32 handle;
        response = getSessionResponse(handle, response);

        auto publicData = readTPM2B(response);
        parsePublicData(publicData, std::move(publicKey));

        auto creationData = readTPM2B(response);

        auto digestOut = readTPM2B(response);

        auto ticketTag = response.beReadU16();
        auto ticketHierarchy = response.beReadU32();
        auto ticketDigest = readTPM2B(response);

        auto name = readTPM2B(response);

        return handle;
    }

    BUFFER getCapabaility(UINT32 category)
    {
        auto response = submitCommand(TPM2_CC_GetCapability, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 category)
            {
                request.beWriteU32(category);
                request.beWriteU32(0);
                request.beWriteU32(0xFFFFFF);
            }, category);

        return response;
    }

    void getCurves()
    {
        auto response = getCapabaility(TPM2_CAP_ECC_CURVES);
        auto more = response.readByte();
        ASSERT(more == 0);

        auto count = response.beReadU16();
        while (response)
        {
            auto curve = response.beReadU16();
            LogInfo("curve: ", curve);
        }
    }

    BUFFER getPCRdigest(SHA256_DATA& digestHash)
    {
        BUFFER result;
        auto response = submitCommand(TPM2_CC_PCR_Read, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request)
            {
                request.beWriteU32(1);
                request.beWriteU16(TPM2_ALG_SHA256);
                request.writeByte(3);
                request.writeByte(0x80); // get PCRS 7 and 11 (0x80, 0x08)
                request.writeByte(0x08);
                request.writeByte(0);
            });

        if (response)
        {
            auto updateCounter = response.beReadU32();
            auto pcrCount = response.beReadU32();

            auto alg = response.beReadU16();
            ASSERT(alg == TPM2_ALG_SHA256);

            auto filterLength = response.readByte();
            auto filter = response.readBytes(3);

            auto&& digestStream = ByteStream(1024);

            auto digestCount = response.beReadU32();
            for (UINT32 i = 0; i < digestCount; i++)
            {
                auto digestSize = response.beReadU16();
                auto digest = response.readBytes(digestSize);
                digestStream.writeBytes(digest);
            }
            result = Sha256ComputeHash(digestHash, digestStream.toBuffer());
        }
        return result;
    }

    BUFFER getPrimaryKey(BUFFER context, BYTESTREAM&& idStream)
    {
        createECDHhandle(NULL_BUFFER, context, std::move(idStream));
        return idStream.toBuffer();
    }

    BUFFER parseAttest(BUFFER attestData)
    {
        //TPMS_ATTEST
        auto magic = attestData.beReadU32();
        ASSERT(magic == TPM2_GENERATED_VALUE);

        auto attestType = attestData.beReadU16();
        ASSERT(attestType == TPM2_ST_ATTEST_QUOTE);

        auto signer = readTPM2B(attestData);

        auto extraData = readTPM2B(attestData);

        auto upTime = attestData.beReadU64();
        auto resetCount = attestData.beReadU32();
        auto restartCount = attestData.beReadU32();
        auto safe = attestData.readByte();

        auto firmwareVersion = attestData.beReadU64();

        auto pcrSets = attestData.beReadU32();
        ASSERT(pcrSets == 1);

        auto hashAlg = attestData.beReadU16();
        ASSERT(hashAlg == TPM2_ALG_SHA256);

        auto registerCount = attestData.readByte();
        ASSERT(registerCount    == 3);

        auto registe1 = attestData.readByte();
        auto registe2 = attestData.readByte();
        auto registe3 = attestData.readByte();

        auto pcrDigest = readTPM2B(attestData);
        return pcrDigest;
    }

    constexpr static UINT32 SIGN_RSA_HANDLE = 0x81000002;
    constexpr static UINT32 ENCRYPT_RSA_HANDLE = 0x81010001;
    constexpr static UINT32 ENCRYPT_ECC_HANDLE = 0x81000009;

    BUFFER getQuote(TPM_HANDLE signHandle)
    {
        BUFFER pcrDigest;
        auto response = submitCommand(TPM2_CC_Quote, TPM2_ST_SESSIONS, [](BYTESTREAM& request, TPM_HANDLE signHandle)
            {
                request.beWriteU32(signHandle);
                //request.beWriteU32(TPM.attestationHandle); XXX
                TPM.setPassword(request, NULL_BUFFER);

                request.beWriteU16(0);
                //request.writeBytes(context);

                //request.beWriteU16(TPM2_ALG_ECDSA); XXX
                request.beWriteU16(TPM2_ALG_RSASSA);
                request.beWriteU16(TPM2_ALG_SHA);

                request.beWriteU32(1);
                request.beWriteU16(TPM2_ALG_SHA256);
                request.writeByte(3);
                request.writeByte(0x80); // get PCRS 7 and 11 (0x80, 0x08)
                request.writeByte(0x08);
                request.writeByte(0);
            }, signHandle);
        if (response)
        {
            response = getSessionResponse(response);

            auto attestData = readTPM2B(response);
            pcrDigest = parseAttest(attestData);

            //TPMT_SIGNATURE
            auto&& signature = ByteStream(512);
            auto sigAlg = response.beReadU16();
            auto sigHash = response.beReadU16();
            if (sigAlg == TPM2_ALG_RSASSA)
            {
                signature.writeBytes(readTPM2B(response));
            }
            else if (sigAlg == TPM2_ALG_ECDSA)
            {
                signature.writeBytes(readTPM2B(response));
                signature.writeBytes(readTPM2B(response));

                SHA256_DATA digestHash;
                Sha256ComputeHash(digestHash, attestData);
                //auto result = ecdsa_verify(TPM.AKpublicKey, digestHash, signature.toBuffer());
                //ASSERT(result);
            }
            else DBGBREAK();
            ASSERT(response.length() == 0);
        }
        return pcrDigest;
    }
/* persistent handles
handle: 0x81000001 => RSA encrypt
handle: 0x81000002 => RSA signing keyd
handle: 0x81000009
handle: 0x81010001 => Endorsement, RSA encrypt
*/
    BUFFER readPublic(TPM_HANDLE handle, auto&& name)
    {
        BUFFER publicData;
        auto response = submitCommand(TPM2_CC_ReadPublic, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 handle)
            {
                request.beWriteU32(handle);
            }, handle);
        if (response)
        {
            publicData = readTPM2B(response);
            name = readTPM2B(response);
        }
        else DBGBREAK();
        return publicData;
    }
    
    bool activateCredential(TPM_HANDLE aikHandle, BUFFER digest, BUFFER cipherSecret, BUFFER& plainSecret)
    {
        auto result = false;
        auto response = submitCommand(TPM2_CC_ActivateCredential, TPM2_ST_SESSIONS, [](BYTESTREAM& request, TPM_HANDLE aikHandle, BUFFER digest, BUFFER secret)
            {
                request.beWriteU32(aikHandle);
                request.beWriteU32(ENCRYPT_RSA_HANDLE);
                TPM.setAuth(request, TPM2_RH_PW, TPM.EKauthSession);

                TPM.writeTPM2B(request, digest);
                TPM.writeTPM2B(request, secret);
            }, aikHandle, digest, cipherSecret);
        if (response)
        {
            response = getSessionResponse(response);
            plainSecret = readTPM2B(response);
            ASSERT(response.length() == 0);
            result = true;
        }
        return result;
    }

    bool makeCredential(BUFFER ekPUblicData, BUFFER aikName, BUFFER plainSecret, BUFFER& credential, BUFFER& cipherSecret)
    {
        auto result = false;
        do
        {
            TPM_HANDLE ekHandle;
            auto response = submitCommand(TPM2_CC_LoadExternal, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, BUFFER publicData)
                {
                    request.beWriteU16(0);
                    TPM.writeTPM2B(request, publicData);
                    request.beWriteU32(TPM2_RH_OWNER);
                }, ekPUblicData);
            if (response)
            {
                ekHandle = response.beReadU32();
            }
            else break;

            response = submitCommand(TPM2_CC_MakeCredential, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, TPM_HANDLE ekHandle, BUFFER aikName, BUFFER secret)
                {
                    request.beWriteU32(ekHandle);
                    TPM.writeTPM2B(request, secret);
                    TPM.writeTPM2B(request, aikName);
                }, ekHandle, aikName, plainSecret);
            if (response)
            {
                credential = readTPM2B(response);
                cipherSecret = readTPM2B(response);

                ASSERT(response.length() == 0);
            }
            else break;
        } while (false);
        return result;
    }

    void testAttetation(TPM_HANDLE aikHandle)
    {
        ASSERT(aikHandle);
        getHandleInfo(ENCRYPT_RSA_HANDLE, std::move(rsaSignPublicKey.byteStream()));
        auto publicData = readPublic(ENCRYPT_RSA_HANDLE, BUFFER());
        auto plainSecret = WriteMany("test secret data");

        BUFFER aikName;
        readPublic(aikHandle, aikName);

        BUFFER cipherSecret, credential;
        auto valid = makeCredential(publicData, aikName, plainSecret, credential, cipherSecret);
        ASSERT(valid);

        BUFFER testSecret;
        valid = activateCredential(aikHandle, credential, cipherSecret, testSecret);
        ASSERT(valid);
    }

    void getHandleInfo(UINT32 handle, BYTESTREAM&& publicKey)
    {
        auto publicData = readPublic(handle, BUFFER());
        parsePublicData(publicData, std::move(publicKey));
    }

    bool isNVIndex(TPM2_HANDLE handle)
    {
        return ((handle >> 24) == TPM2_HT_NV_INDEX);
    }

    STREAM_READER<const UINT32> getHandles(UINT32 handleRange)
    {
        auto response = submitCommand(TPM2_CC_GetCapability, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 range)
            {
                request.beWriteU32(TPM2_CAP_HANDLES);
                request.beWriteU32(range);
                request.beWriteU32(TPM2_MAX_CAP_HANDLES);
            }, handleRange);

        auto&& handleStream = DATASTREAM<UINT32, SCHEDULER_STACK>();
        if (response)
        {
            auto isMore = response.readByte();
            auto type = response.beReadU32();
            auto count = response.beReadU32();

            handleStream.reserve(count);
            for (UINT32 i = 0; i < count; i++)
            {
                handleStream.append(response.beReadU32());
            }
        }
        return handleStream.toBuffer();
    }

    bool getHandles(UINT32 handleRange, UINT32 matchHandle)
    {
        UINT8 publicKey[512];
        auto handleFound = false;
        auto response = submitCommand(TPM2_CC_GetCapability, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 range)
            {
                request.beWriteU32(TPM2_CAP_HANDLES);

                request.beWriteU32(range);
                //request.beWriteU32(TPM2_HR_PERSISTENT);
                //request.beWriteU32(TPM2_HR_NV_INDEX);

                request.beWriteU32(TPM2_MAX_CAP_HANDLES);
            }, handleRange);
        if (response)
        {
            auto isMore = response.readByte();
            auto type = response.beReadU32();
            auto count = response.beReadU32();

            for (UINT32 i = 0; i < count; i++)
            {
                auto handle = response.beReadU32();
                printf("handle: 0x%x\n", handle);
                if (isNVIndex(handle))
                {
                    auto nvData = readNVIndex(handle);
                    printf("length: %d\n", nvData.length());
                }
                else
                {
                    getHandleInfo(handle, publicKey);
                }
                if (handle == matchHandle)
                {
                    handleFound = true;
                    break;
                }
            }
        }
        return handleFound;
    }

    void getDeviceInfo()
    {
        auto response = submitCommand(TPM2_CC_GetCapability, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request)
            {
                request.beWriteU32(TPM2_CAP_TPM_PROPERTIES);
                request.beWriteU32(TPM2_PT_PERMANENT);
                //request.beWriteU32(TPM2_PT_MANUFACTURER);
                request.beWriteU32(TPM2_MAX_TPM_PROPERTIES);
            });
        if (response)
        {
            auto isMore = response.readByte();
            // TPMS_CAPABILITY_DATA
            auto type = response.beReadU32();
            auto count = response.beReadU32();
            for (UINT32 i = 0; i < count; i++)
            {
                auto property = response.beReadU32();
                auto value = response.beReadU32();
                printf("0x%X 0x%x\n", property, value);
            }
        }
    }

    BUFFER undefineNV(UINT32 handle)
    {
        BUFFER result;
        auto response = submitCommand(TPM2_CC_NV_UndefineSpace, TPM2_ST_SESSIONS, [](BYTESTREAM& request, UINT32 handle)
            {
                request.beWriteU32(TPM2_RH_OWNER);
                request.beWriteU32(handle);
                TPM.setPassword(request, NULL_BUFFER);
            }, handle);
        return result;
    }

    UINT16 readNVpublic(UINT32 handle)
    {
        UINT16 dataSize = 0;
        auto response = submitCommand(TPM2_CC_NV_ReadPublic, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request, UINT32 handle)
            {
                request.beWriteU32(handle);
            }, handle);
        if (response)
        {
            auto&& outStream = ByteStream(64);
            auto publicData = readTPM2B(response);
            auto index = publicData.beReadU32();
            ASSERT(index == handle);
            auto nameAlg = publicData.beReadU16();
            auto attributes = publicData.beReadU32();
            auto policy = readTPM2B(publicData);
            dataSize = publicData.beReadU16();
        }
        return dataSize;
    }
/*
    typedef struct {
        TCG_PCRINDEX PCRIndex;
        TCG_EVENTTYPE EventType;
        TPML_DIGEST_VALUES Digests;
        UINT32 EventSize;
        UINT8 Event[EventSize];
    } TCG_PCR_EVENT2;

    typedef struct {
        UINT32 Count;
        TPMT_HA Digests;
    } TPML_DIGEST_VALUES;

    typedef struct {
        UINT16 HashAlg;
        UINT8 Digest[size_varies_with_algorithm];
    } TPMT_HA;

    typedef struct {
        BYTE[16] Signature;
        UINT32 PlatformClass;
        UINT8 SpecVersionMinor;
        UINT8 SpecVersionMajor;
        UINT8 SpecErrata;
        UINT8 UintNSize;
        UINT32 NumberOfAlgorithms;
        TCG_EfiSpecIdEventAlgorithmSize DigestSizes[NumberOfAlgorithms];
        UINT8 VendorInfoSize;
        UINT8 VendorInfo[VendorInfoSize];
    } TCG_EfiSpecIdEventStruct;

    typedef struct {
        UINT16 HashAlg;
        UINT16 DigestSize;
    } TCG_EfiSpecIdEventAlgorithmSize;

    typedef struct {
        TCG_PCRINDEX PCRIndex;
        TCG_EVENTTYPE EventType;
        TCG_DIGEST Digest;
        UINT32 EventSize;
        UINT8 Event[EventSize];
    } TCG_PCR_EVENT;
*/
#define EV_PREBOOT_CERT            0x0
#define EV_POST_CODE               0x1
#define EV_UNUSED                  0x2
#define EV_NO_ACTION               0x3
#define EV_SEPARATOR               0x4
#define EV_ACTION                  0x5
#define EV_EVENT_TAG               0x6
#define EV_S_CRTM_CONTENTS         0x7
#define EV_S_CRTM_VERSION          0x8
#define EV_CPU_MICROCODE           0x9
#define EV_PLATFORM_CONFIG_FLAGS   0xa
#define EV_TABLE_OF_DEVICES        0xb
#define EV_COMPACT_HASH            0xc
#define EV_IPL                     0xd
#define EV_IPL_PARTITION_DATA      0xe
#define EV_NONHOST_CODE            0xf
#define EV_NONHOST_CONFIG          0x10
#define EV_NONHOST_INFO            0x11
#define EV_OMIT_BOOT_DEVICE_EVENTS 0x12

    void parseTCGLog(BUFFER log)
    {
        auto pcr = log.readU32();
        auto type = log.readU32();
        auto digest = log.readBytes(20);
        auto eventSize = log.readU32();
        auto header = log.readBytes(eventSize);

        auto signature = header.readBytes(16);

        BUFFER eventData;
        while (log)
        {
            auto pcr = log.readU32();
            auto eventType = log.readU32();

            auto digestCount = log.readU32();
            for (UINT32 i = 0; i < digestCount; i++)
            {
                auto alg = log.readU16();
                BUFFER hash;
                if (alg == TPM2_ALG_SHA256)
                {
                    hash = log.readBytes(SHA256_HASH_LENGTH);
                }
                else if (alg == TPM2_ALG_SHA1)
                {
                    hash = log.readBytes(SHA1_HASH_LENGTH);
                }
                else DBGBREAK();
            }
            eventSize = log.readU32();
            eventData = log.readBytes(eventSize);
        }
    }

    void readTCGLog()
    {
        auto&& tcgData = ByteStream(256 * 1024);
        auto result = Tbsi_Get_TCG_Log_Ex(TBS_TCGLOG_SRTM_CURRENT, tcgData.commit(tcgData.size()), &tcgData.setCount());
        if (result == TBS_SUCCESS)
        {
            parseTCGLog(tcgData.toBuffer());
        }

    }

    constexpr static UINT32 ECC_EKCERT_NVINDEX = 0x01C0000A;
    constexpr static UINT32 RSA_EKCERT_NVINDEX =      0x01C00002;
    constexpr static UINT32 EK_TEMPLATE_NVINDEX = 0x01c0000c;
    constexpr static UINT32 EK_NONCE_NVINDEX =    0x01c0000b;

    LOCAL_STREAM<512> certPublicKey;

    BUFFER EKCertECCbytes;
    BUFFER EKCertRSAbytes;

    BUFFER EKpublicKeyRSA;

    void getCertificate()
    {
        auto certData = readNVIndex(ECC_EKCERT_NVINDEX);
        EKCertECCbytes = GlobalStack().blobStream.writeBytesTo(certData);

        certData = readNVIndex(RSA_EKCERT_NVINDEX);
        EKCertRSAbytes = GlobalStack().blobStream.writeBytesTo(certData);

        auto publicData = readPublic(ENCRYPT_RSA_HANDLE, BUFFER());
        auto publicKey = parsePublicData(publicData, ByteStream(512));

        EKpublicKeyRSA = GlobalStack().blobStream.writeBytesTo(publicKey).rebase();
    }

    TPM_HANDLE EKauthSession;
    TPM_HANDLE getEndorsementAuth()
    {
        TPM_HANDLE sessionHandle = TPM2_RH_NULL;

        auto response = submitCommand(TPM2_CC_StartAuthSession, TPM2_ST_NO_SESSIONS, [](BYTESTREAM& request)
            {
                request.beWriteU32(TPM2_RH_NULL);
                request.beWriteU32(TPM2_RH_NULL);

                TPM.writeTPM2B(request, ZeroBytes.toBuffer(16));

                request.beWriteU16(0);
                request.writeByte(TPM2_SE_POLICY);
                request.beWriteU16(TPM2_ALG_NULL);
                request.beWriteU16(TPM2_ALG_SHA256);
            });
        if (response)
        {
            sessionHandle = response.beReadU32();
        }
        ASSERT(sessionHandle != TPM2_RH_NULL);

        response = submitCommand(TPM2_CC_PolicySecret, TPM2_ST_SESSIONS, [](BYTESTREAM& request, TPM_HANDLE sessionHandle)
            {
                request.beWriteU32(TPM2_RH_ENDORSEMENT);
                request.beWriteU32(sessionHandle);

                TPM.setPassword(request, NULL_BUFFER);

                request.beWriteU16(0);
                request.beWriteU16(0);
                request.beWriteU16(0);
                request.beWriteU32(0);

            }, sessionHandle);
        ASSERT(response);
        sessionHandle = response ? sessionHandle : TPM2_RH_NULL;
        return sessionHandle;
    }

    LOCAL_STREAM<512> rsaSignPublicKey;
    UINT32 EKhandleEC;

    void test()
    {
        //defineNVSpace(0x01c00004, NULL_BUFFER);
        //readNVpublic(0x01c0000A);
        //undefineNV(0x01c00004);
        //openEKhandleEC();
        //getEndorsementAuth();
        auto found1 = getHandles(TPM2_HR_PERSISTENT, -1); // RSA_EKCERT_NVINDEX);
        //auto found2 = getHandles(TPM2_HR_NV_INDEX, EKCERT_NVINDEX);
        //auto found2 = getHandles(EK_TEMPLATE_NVINDEX);
        //auto found3 = getHandles(EK_NONCE_NVINDEX);
        //getEK();
    
        //readTCGLog();

        AES_GCM cipher;
        getHandleInfo(ENCRYPT_RSA_HANDLE, std::move(rsaSignPublicKey.byteStream()));
        //getCertificate();
        //EKhandleEC = openEKhandleEC();
        getQuote(SIGN_RSA_HANDLE);
        //getQuote();
        //getDeviceInfo();
        UINT8 pcrDigest[SHA256_HASH_LENGTH];
        getPCRdigest(pcrDigest);
    }
};
inline TPMOPS TPM;

inline UINT64 TPMincrementIndex(UINT32 index) { return TPM.incrementIndex(index); }

struct ECDH_CIPHER
{
    TPM_HANDLE ecdhHandle;
    EC256_PUBLICKEY ecdhPublicKey;

    void init()
    {
        ecdhHandle = TPM.createECDHhandle(NULL_BUFFER, "ECDH AES KEYGEN", ecdhPublicKey);
        ASSERT(ecdhHandle);
    }

    bool createCipher(EC256_PUBLICKEY& peerKey, BUFFER context, AES_GCM& cipher)
    {
        return TPM.deriveKey(ecdhHandle, peerKey, context, cipher);
    }

    bool encrypt(EC256_PUBLICKEY& peerKey, BUFFER context, RWBUFFER text, U128& tag)
    {
        AES_GCM cipher;

        auto result = TPM.deriveKey(ecdhHandle, peerKey, context, cipher);
        ASSERT(result);

        cipher.encrypt(NULL_BUFFER, text, tag);

        return result;
    }

    BUFFER decrypt(EC256_PUBLICKEY& peerKey, BUFFER context, RWBUFFER text, U128 tag)
    {
        AES_GCM cipher;

        auto result = TPM.deriveKey(ecdhHandle, peerKey, context, cipher);
        ASSERT(result);

        return cipher.decrypt(NULL_BUFFER, text, tag);
    }
};
