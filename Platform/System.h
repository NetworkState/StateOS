
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct SYSTEM_SERVICE
{
    SCHEDULER_INFO<> scheduler;
    GLOBAL_STACK globalStack;
    SERVICE_STACK serviceStack;

    BUFFER hostnameText;
    TOKEN hostname;
    TOKEN userAgent;
    TOKEN serverBrand;

    X509_CA CAsignKey;
    X509_KEY AKsignKey;

    ECDH_CIPHER ecdhKey;

    SYSTEM_SERVICE() : scheduler(serviceStack) {}

    bool isCA() { return CAsignKey.isCA; }
    U128 getNodeId() { return AKsignKey.nodeId; }

    void init()
    {
        globalStack.init(8 * 1024 * 1024);
        serviceStack.init(2 * 1024 * 1024);
        scheduler.init();
    }

    BUFFER KeyToFilename(BUFFER publicKey, BUFFER suffix)
    {
        ASSERT(publicKey.length() == 64);
        auto hash = TPM.KeyCipher.hash(publicKey);
        
        auto&& nameStream = ByteStream(128);
        nameStream.writeGuid(hash);
        nameStream.writeString(suffix);

        return nameStream.toBuffer();
    }

    bool verifySignature(U128 keyId, BUFFER signHash, BUFFER signature)
    {
        return CAsignKey.verifySignature(keyId, signHash, signature);
    }

    constexpr static BUFFER AUTH_AK_CSR = "auth-ak.csr";
    constexpr static BUFFER AUTH_AK_CRT = "auth-ak.crt";

    BUFFER buildAKcsr()
    {
        TSTRING_STREAM nameStream;
        nameStream.append(hostnameText);
        auto certBytes = AKsignKey.buildCSR(false, CERT_KEYUSAGE, hostnameText, nameStream.toBuffer());
        return certBytes;
    }

    void initAKkey()
    {
        AKsignKey.create(WriteMany(STATEOS_BRAND, " - AK"));
        auto certBytes = File.ReadFile<GLOBAL_STACK>(AUTH_AK_CRT);
        if (!CAsignKey.importAK(certBytes, AKsignKey))
        {
            File.WriteFile(AUTH_AK_CSR, buildAKcsr());
            AKsignKey.close();
        }
    }

    constexpr static BUFFER SIGN_REQ_CSR = "sign-req.csr";
    constexpr static BUFFER SIGN_REQ_CRT = "sign-req.crt";

    void signAK()
    {
        if (CAsignKey.isCA)
        {
            if (auto requestBytes = File.ReadFile<SCHEDULER_STACK>(SIGN_REQ_CSR))
            {
                auto crtBytes = CAsignKey.signCSR(requestBytes, ByteStream(2048));
                File.WriteFile(SIGN_REQ_CRT, crtBytes);
                File.DeleteFile(SIGN_REQ_CSR);
            }
        }
    }

    BUFFER formatSignReq()
    {
        VLSTREAM<> outStream{ StructDynamic, 4096 };
        
        outStream.write(QMSG_sign_ak_req);

        //outStream.write(TPM.EKInfo.certBytes, QMSG_ek_cert);
        outStream.write(TPM.EKInfo.publicData, QMSG_ek_public);

        auto akPUblic = TPM.readPublic(AKsignKey.signHandle);
        outStream.write(akPUblic, QMSG_ak_public);

        auto certBytes = buildAKcsr();
        outStream.write(certBytes, QMSG_ak_csr);

        return outStream.toBuffer();
    }

    BUFFER formatSignResponse(BUFFER digest, BUFFER secret, BUFFER certBytes)
    {
        VLSTREAM<> outStream{ StructDynamic, 4096 };

        outStream.write(QMSG_sign_ak_resp);

        outStream.write(digest, QMSG_cred_digest);
        outStream.write(secret, QMSG_cred_secret);

        outStream.write(certBytes, QMSG_ak_cert);

        return outStream.toBuffer();
    }

    void onSignResponse(BUFFER responseBytes)
    {
        VLBUFFER response{ responseBytes };

        auto method = response.readToken();
        ASSERT(method.contour == QMSG_sign_ak_resp);

        BUFFER credDigest, credSecret, certBytes;
        while (response)
        {
            auto token = response.readToken();
            ASSERT(token.label);

            if (token.label == QMSG_cred_digest)
            {
                credDigest = token.contourBlob;
            }
            else if (token.label == QMSG_cred_secret)
            {
                credSecret = token.contourBlob;
            }
            else if (token.label == QMSG_ak_cert)
            {
                certBytes = token.contourBlob;
            }
            else DBGBREAK();
        }
        ASSERT(credDigest && credSecret && certBytes);

        auto result = TPM.activateCredential(AKsignKey.signHandle, credDigest, credSecret, credSecret);
        if (result)
        {
            AES_CTR cipher; cipher.init(credSecret);
            cipher.encrypt(certBytes.toRWBuffer());

            CAsignKey.importAK(certBytes, AKsignKey);
        }
        else DBGBREAK();
    }

    void onSignReq(BUFFER requestBytes)
    {
        VLBUFFER request{ requestBytes };

        auto method = request.readToken();
        ASSERT(method.contour == QMSG_sign_ak_req);

        BUFFER ekCert, ekPublic, akPublic, csr;
        while (request)
        {
            auto token = request.readToken();
            ASSERT(token.label);
            //if (token.label == QMSG_ek_cert)
            //{
            //    ekCert = token.contourBlob;
            //}
            if (token.label == QMSG_ek_public)
            {
                ekPublic = token.contourBlob;
            }
            else if (token.label == QMSG_ak_public)
            {
                akPublic = token.contourBlob;
            }
            else if (token.label == QMSG_ak_csr)
            {
                csr = token.contourBlob;
            }
            else DBGBREAK();
        }

        ASSERT(ekPublic && akPublic && csr);
        //ASSERT(ekCert && ekPublic && akPublic && csr);

        auto signedCert = CAsignKey.signCSR(csr, ByteStream(csr.length() * 2));

        auto&& nameStream = ByteStream(64);
        nameStream.beWriteU16(TPM2_ALG_SHA256);

        Sha256ComputeHash(nameStream.commitTo(SHA256_HASH_LENGTH), akPublic);

        auto plainSecret = Random.getBytes(32);
        AES_CTR cipher; cipher.init(plainSecret);

        cipher.encrypt(signedCert.toRWBuffer());

        BUFFER digest, cipherSecret;
        TPM.makeCredential(ekPublic, nameStream.toBuffer(), plainSecret, digest, cipherSecret);

        auto response = formatSignResponse(digest, cipherSecret, signedCert);
        onSignResponse(response);
    }

    void testAttestation()
    {
        auto request = formatSignReq();
        onSignReq(request);
    }

    constexpr static BUFFER AUTH_CA_CSR = "auth-ca.csr";
    constexpr static BUFFER AUTH_CA_CRT = "auth-ca.crt";

    void initCAkey()
    {
        CAsignKey.create(WriteMany(STATEOS_BRAND, " - CA"));
        auto caCertBytes = File.ReadFile<GLOBAL_STACK>(AUTH_CA_CRT);
        if (CAsignKey.import(caCertBytes))
        {
            initAKkey();
            signAK();
            ecdhKey.init();
        }
        else
        {
            auto csrData = CAsignKey.signKey.buildCSR(true, CA_KEYUSAGE, STATEOS_BRAND, STRINGBUFFER());
            File.WriteFile(AUTH_CA_CSR, csrData);
            CAsignKey.signKey.close();
        }
    }

    constexpr static char HTTP_STRING_USER_AGENT[] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36";

    void start()
    {
        auto&& byteStream = ByteStream(256);
        GetComputerNameExA(ComputerNameDnsFullyQualified, (LPSTR)byteStream.commitAll(), (LPDWORD)&byteStream.setCount());

        hostname = CreateName(byteStream.toBuffer(), false); // ignore case
        hostnameText = globalStack.blobStream.writeBytesTo(NameToString(hostname)); // lower case name

        userAgent = CreateName(HTTP_STRING_USER_AGENT);
        serverBrand = CreateName(STATEOS_BRAND);

        auto publicKey = X509_PARTS(TPM.EKInfo.certBytes).getPublicKey(ByteStream(512));
        //ASSERT(publicKey == TPM.EKInfo.publicKey);

        initCAkey();

        testAttestation();
    }
};

extern SYSTEM_SERVICE& SystemService();
