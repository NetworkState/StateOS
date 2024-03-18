
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

    void initAKkey()
    {
        AKsignKey.create(WriteMany(STATEOS_BRAND, " - AK"));
        auto certBytes = File.ReadFile<GLOBAL_STACK>(AUTH_AK_CRT);
        if (!CAsignKey.importAK(certBytes, AKsignKey))
        {
            TSTRING_STREAM nameStream;
            nameStream.append(hostnameText);
            certBytes = AKsignKey.buildCSR(false, CERT_KEYUSAGE, hostnameText, nameStream.toBuffer());
            File.WriteFile(AUTH_AK_CSR, certBytes);
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

        auto publicKey = X509_PARTS(TPM.EKCertRSAbytes).getPublicKey(ByteStream(512));
        ASSERT(publicKey == TPM.EKpublicKeyRSA);

        initCAkey();

        TPM.testAttetation(AKsignKey.signHandle);
    }
};

extern SYSTEM_SERVICE& SystemService();
