
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

constexpr UINT32 SHA1_HASH_LENGTH = 20;
constexpr UINT32 SHA256_HASH_LENGTH = 32;
constexpr UINT32 MD5_HASH_LENGTH = 16;
constexpr UINT32 SHA384_HASH_LENGTH = 48;
constexpr UINT32 SHA512_HASH_LENGTH = 64;
constexpr UINT32 AES_TAG_LENGTH = 16;
constexpr UINT32 AES_GCM_IV_LENGTH = 12;
constexpr UINT32 AES_CTR_IV_LENGTH = 14;
constexpr UINT32 AES128_KEY_LENGTH = 16;
constexpr UINT32 AES256_KEY_LENGTH = 32;
constexpr UINT32 AES_BLOCK_SIZE = 16;

constexpr UINT32 EC256_BYTES = 32;
constexpr UINT32 EC384_BYTES = 48;

using SHA_STREAM = LOCAL_STREAM<SHA512_HASH_LENGTH>;
using AES_GCM_IV = U96; // UINT8[AES_GCM_IV_LENGTH];
using SHA_DATA = UINT8[SHA512_HASH_LENGTH];

extern void sha256_process_x86(uint32_t state[8], BUFFER data);
extern void sha1_process_x86(uint32_t state[5], BUFFER input);

using SHA1_DATA   = UINT8[SHA1_HASH_LENGTH];
using SHA256_DATA = UINT8[SHA256_HASH_LENGTH];
using SHA384_DATA = UINT8[SHA384_HASH_LENGTH];
using SHA512_DATA = UINT8[SHA512_HASH_LENGTH];

extern void X25519_public_from_private(UINT8 out_public_value[32], const UINT8 private_key[32]);
extern int X25519(UINT8 out_shared_key[32], const UINT8 private_key[32], const UINT8 peer_public_value[32]);

constexpr UINT32 ECDH256_KEY_SIZE = 32;
using ECDH256_PRIVATE_KEY_DATA = UINT8[ECDH256_KEY_SIZE];
using ECDH256_PUBLIC_KEY_DATA = UINT8[ECDH256_KEY_SIZE * 2];

/* Curves IDs */
#define ECC_CURVE_NIST_P192     0x0001
#define ECC_CURVE_NIST_P256     0x0002
#define ECC_CURVE_NIST_P384     0x0003

inline void XorData(U128& first, U128& second)
{
    first.u64[0] ^= second.u64[0];
    first.u64[1] ^= second.u64[1];
}

struct RANDOM
{
    BUFFER getBytes(BYTESTREAM&& outStream)
    {
        auto saved = outStream.getPosition();

        while (outStream.spaceLeft())
        {
            UINT64 value = getNumber();
            outStream.writeBytes((PUINT8)&value, min(8, outStream.spaceLeft()));
        }
        return saved.toBuffer();
    }

    inline UINT64 getNumber()
    {
        UINT64 value1;
        while (_rdrand64_step(&value1) == 0)
        {
            DBGBREAK();
            Sleep(1);
        }
        UINT64 value2;
        _rdseed64_step(&value2);
        return value1 ^ value2;
    }

    BUFFER getBytes(UINT32 size)
    {
        return getBytes(ByteStream(size));
    }
};

inline RANDOM Random;

struct SHA1_HASH
{
    constexpr static INT32 BLOCK_SIZE = 64;
    constexpr static UINT32 LENGTH_FIELD = sizeof(UINT64); // in bytes

    UINT32 hashState[5] = { 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0 };

    UINT64 totalLength = 0;

    LOCAL_STREAM<BLOCK_SIZE> partialBlock;

    void addMessage(BUFFER message)
    {
        if (message.length() == 0)
            return;
        totalLength += message.length();

        if (partialBlock.count() > 0)
        {
            partialBlock.writeBytes(message.readBytes(min(partialBlock.spaceLeft(), message.length()))); // spaceLeft));

            if (partialBlock.count() == BLOCK_SIZE)
            {
                sha1_process_x86(hashState, partialBlock.toBuffer());
                partialBlock.clear();
            }
        }

        sha1_process_x86(hashState, message.readBytes(message.length() & -BLOCK_SIZE));

        partialBlock.writeBytes(message);
    }

    template <typename STREAM>
    BUFFER getHash(STREAM&& outStream)
    {
        partialBlock.writeByte(0x80);
        if (partialBlock.spaceLeft() < LENGTH_FIELD)
        {
            partialBlock.writeBytes(ZeroBytes, BLOCK_SIZE - partialBlock.count());
            sha1_process_x86(hashState, partialBlock.toBuffer());
            partialBlock.clear();
        }

        partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft() - LENGTH_FIELD); // BLOCK_SIZE - LENGTH_FIELD - partialBlock.count());
        partialBlock.beWriteU64(totalLength * 8);
        sha1_process_x86(hashState, partialBlock.toBuffer());

        auto address = (UINT32*)outStream.commit(SHA1_HASH_LENGTH);
        for (UINT32 i = 0; i < 5; i++)
        {
            address[i] = _byteswap_ulong(hashState[i]);
        }
        return outStream.toBuffer();
    }
};

VARGS(BUFFER)
BUFFER Sha1ComputeHash(BYTESTREAM outStream, ARGS && ... args)
{
    SHA1_HASH hash;
    ASSERT(outStream.size() == SHA1_HASH_LENGTH);

    int dummy[] = { (hash.addMessage(args), 0) ... }; dummy;

    return hash.getHash(outStream);
}

struct SHA256_HASH
{
    constexpr static INT32 BLOCK_SIZE = 64;
    constexpr static UINT32 LENGTH_FIELD = sizeof(UINT64); // in bytes

    UINT32 hashState[8] = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    UINT64 totalLength = 0;

    LOCAL_STREAM<BLOCK_SIZE> partialBlock;

    void addMessage(BUFFER message)
    {
        if (message.length() == 0)
            return;

        totalLength += message.length();

        if (partialBlock.count() > 0)
        {
            partialBlock.writeBytes(message.readBytes(min(partialBlock.spaceLeft(), message.length()))); // spaceLeft));

            if (partialBlock.count() == BLOCK_SIZE)
            {
                sha256_process_x86(hashState, partialBlock.toBuffer());
                partialBlock.clear();
            }
        }

        sha256_process_x86(hashState, message.readBytes(message.length() & -BLOCK_SIZE));

        partialBlock.writeBytes(message);
    }

    SHA256_HASH& clone(SHA256_HASH&& other)
    {
        RtlCopyMemory(other.hashState, hashState, sizeof(hashState));
        other.totalLength = totalLength;
        other.partialBlock.writeBytes(partialBlock.toBuffer());

        return other;
    }

    template <typename STREAM>
    BUFFER getRunningHash(STREAM&& outStream)
    {
        auto&& savedState = clone(SHA256_HASH());
        return savedState.getHash(outStream);
    }

    BUFFER getHash(BYTESTREAM& outStream)
    {
        partialBlock.writeByte(0x80);
        if (partialBlock.spaceLeft() < LENGTH_FIELD)
        {
            partialBlock.writeBytes(ZeroBytes, BLOCK_SIZE - partialBlock.count());
            sha256_process_x86(hashState, partialBlock.toBuffer());
            partialBlock.clear();
        }

        partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft() - LENGTH_FIELD); // BLOCK_SIZE - LENGTH_FIELD - partialBlock.count());
        partialBlock.beWriteU64(totalLength * 8);
        sha256_process_x86(hashState, partialBlock.toBuffer());

        auto address = (UINT32*)outStream.commit(SHA256_HASH_LENGTH);
        for (UINT32 i = 0; i < 8; i++)
        {
            address[i] = _byteswap_ulong(hashState[i]);
        }
        return outStream.toBuffer();
    }
};

VARGS(BUFFER) 
BUFFER Sha256ComputeHash(BYTESTREAM&& outStream, ARGS&& ... args)
{
    SHA256_HASH hash;
    ASSERT(outStream.size() == SHA256_HASH_LENGTH);

    int dummy[] = { (hash.addMessage(args), 0) ... }; dummy;

    return hash.getHash(outStream);
}

VARGS(BUFFER)
BUFFER Sha256TempHash(ARGS&& ... args)
{
    return Sha256ComputeHash(ByteStream(SHA256_HASH_LENGTH), args ...);
}

constexpr UINT32 EDDSA_SIGNATURE_LENGTH = 64;

extern "C" void sha512_block_data_order(UINT64 *state, const void* data, size_t blocks);

template <UINT32 SZ>
struct SHA384_512_HASH
{
    constexpr static auto BLOCK_SIZE = 128;
    constexpr static auto LENGTH_FIELD = 16;

    using STATE = UINT64[8];
    STATE Sha384State = {
        0xCBBB9D5DC1059ED8, 0x629A292A367CD507, 0x9159015A3070DD17, 0x152FECD8F70E5939,
        0x67332667FFC00B31, 0x8EB44A8768581511, 0xDB0C2E0D64F98FA7, 0x47B5481DBEFA4FA4, };

    STATE Sha512State = {
        0x6a09e667f3bcc908UI64, 0xbb67ae8584caa73bUI64, 0x3c6ef372fe94f82bUI64, 0xa54ff53a5f1d36f1UI64,
        0x510e527fade682d1UI64, 0x9b05688c2b3e6c1fUI64, 0x1f83d9abfb41bd6bUI64, 0x5be0cd19137e2179UI64 };

    STATE& hashState;

    UINT64 totalLength = 0;
    LOCAL_STREAM<BLOCK_SIZE> partialBlock;

    SHA384_512_HASH() : hashState(SZ == 512 ? Sha512State : Sha384State) 
    {
        ASSERT(SZ == 512 || SZ == 384);
    }

    void addMessage(BUFFER buffer)
    {
        if (buffer.length() == 0)
            return;

        totalLength += buffer.length();

        if (partialBlock.count() > 0)
        {
            partialBlock.writeBytes(buffer.readBytes(min(partialBlock.spaceLeft(), buffer.length())));

            if (partialBlock.count() == BLOCK_SIZE)
            {
                sha512_block_data_order(hashState, partialBlock.address(), 1);
                partialBlock.clear();
            }
        }
        if (auto fullBlocks = buffer.length() / BLOCK_SIZE)
        {
            sha512_block_data_order(hashState, buffer.readBytes(fullBlocks * BLOCK_SIZE).data(), fullBlocks);
        }

        partialBlock.writeBytes(buffer);
    }

    SHA384_512_HASH<SZ>& clone(SHA384_512_HASH<SZ>&& other)
    {
        RtlCopyMemory(other.hashState, hashState, sizeof(hashState));
        other.totalLength = totalLength;
        other.partialBlock.writeBytes(partialBlock.toBuffer());

        return other;
    }

    BUFFER getRunningHash(BYTESTREAM&& outStream)
    {
        auto&& savedState = clone(SHA384_512_HASH<SZ>());
        return savedState.getHash(outStream);
    }

    BUFFER getHash(BYTESTREAM& outStream)
    {
        partialBlock.writeByte(0x80);

        if (partialBlock.spaceLeft() < LENGTH_FIELD)
        {
            partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft());
            sha512_block_data_order(hashState, partialBlock.address(), 1);
            partialBlock.clear();
        }

        partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft() - LENGTH_FIELD); // BLOCK_SIZE - (LENGTH_FIELD + partialBlock.count()));
        partialBlock.beWriteU64(0);
        partialBlock.beWriteU64(totalLength * 8);
        sha512_block_data_order(hashState, partialBlock.address(), 1);

        auto address = (UINT64*)outStream.commit(SZ/8);
        for (UINT32 i = 0, j = SZ / 64; i < j; i++)
        {
            address[i] = _byteswap_uint64(hashState[i]);
        }

        return outStream.toBuffer();
    }
};

using SHA384_HASH = SHA384_512_HASH<384>;
using SHA512_HASH = SHA384_512_HASH<512>;

VARGS(BUFFER)
void Sha384_512ComputeHash(UINT64 (&hashState)[8], ARGS&& ... args)
{
    constexpr static auto BLOCK_SIZE = 128;
    constexpr static auto LENGTH_FIELD = 16;

    UINT64 totalLength = 0;
    UINT8 partialBlockData[BLOCK_SIZE];
    BYTESTREAM partialBlock{ partialBlockData };

    BUFFER dataBuffers[] = { args ... };
    for (UINT32 i = 0; i < ARRAYSIZE(dataBuffers); i++)
    {
        auto buffer = dataBuffers[i];

        if (buffer.length() == 0)
            continue;
        
        totalLength += buffer.length();

        if (partialBlock.count() > 0)
        {
            partialBlock.writeBytes(buffer.readBytes(min(partialBlock.spaceLeft(), buffer.length())));

            if (partialBlock.count() == BLOCK_SIZE)
            {
                sha512_block_data_order(hashState, partialBlock.address(), 1);
                partialBlock.clear();
            }
        }
        if (auto fullBlocks = buffer.length() / BLOCK_SIZE)
        {
            sha512_block_data_order(hashState, buffer.readBytes(fullBlocks * BLOCK_SIZE).data(), fullBlocks);
        }

        partialBlock.writeBytes(buffer);
    }

    partialBlock.writeByte(0x80);

    if (partialBlock.spaceLeft() < LENGTH_FIELD)
    {
        partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft());
        sha512_block_data_order(hashState, partialBlock.address(), 1);
        partialBlock.clear();
    }

    partialBlock.writeBytes(ZeroBytes, partialBlock.spaceLeft() - LENGTH_FIELD); // BLOCK_SIZE - (LENGTH_FIELD + partialBlock.count()));
    partialBlock.beWriteU64(0);
    partialBlock.beWriteU64(totalLength * 8);
    sha512_block_data_order(hashState, partialBlock.address(), 1);
}

VARGS(BUFFER)
BUFFER Sha512ComputeHash(BYTESTREAM&& outStream, ARGS&& ... args)
{
    ASSERT(outStream.spaceLeft() >= SHA512_HASH_LENGTH);

    SHA512_HASH hash;
    int dummy[] = { (hash.addMessage(args), 0) ... }; dummy;

    return hash.getHash(outStream);
}

VARGS(BUFFER)
BUFFER Sha384ComputeHash(BYTESTREAM&& outStream, ARGS&& ... args)
{
    ASSERT(outStream.spaceLeft() >= SHA384_HASH_LENGTH);

    SHA384_HASH hash;
    int dummy[] = { (hash.addMessage(args), 0) ... }; dummy;

    return hash.getHash(outStream);
}

VARGS(BUFFER)
BUFFER HmacSha256(BYTESTREAM&& outStream, BUFFER secret, ARGS&& ... args)
{
    constexpr static auto BLOCK_SIZE = 64;
    U512 keyData;

    if (secret.length() > BLOCK_SIZE)
    {
        Sha256ComputeHash(BYTESTREAM(keyData.u8, SHA256_HASH_LENGTH), secret);
    }
    else
    {
        BYTESTREAM(keyData).writeBytes(secret);
    }

    U512 innerPad, outerPad;
    for (UINT32 i = 0; i < U512_QWORDS; i++)
    {
        innerPad.u64[i] = keyData.u64[i] ^ 0x3636363636363636;
        outerPad.u64[i] = keyData.u64[i] ^ 0x5c5c5c5c5c5c5c5c;
    }

    SHA256_DATA tempHash;
    Sha256ComputeHash(tempHash, innerPad, args ...);
    return Sha256ComputeHash(std::move(outStream), outerPad, tempHash);
}
VARGS(BUFFER)
BUFFER HmacSha1(BYTESTREAM&& outStream, BUFFER secret, ARGS&& ... args)
{
    constexpr static auto BLOCK_SIZE = 64;
    U512 keyData;

    if (secret.length() > BLOCK_SIZE)
    {
        Sha1ComputeHash(BYTESTREAM(keyData.u8, SHA1_HASH_LENGTH), secret);
    }
    else
    {
        BYTESTREAM(keyData).writeBytes(secret);
    }

    U512 innerPad, outerPad;
    for (UINT32 i = 0; i < U512_QWORDS; i++)
    {
        innerPad.u64[i] = keyData.u64[i] ^ 0x3636363636363636;
        outerPad.u64[i] = keyData.u64[i] ^ 0x5c5c5c5c5c5c5c5c;
    }

    SHA1_DATA tempHash;
    Sha1ComputeHash(tempHash, innerPad, args ...);
    return Sha1ComputeHash(std::move(outStream), outerPad, tempHash);
}

VARGS(BUFFER)
BUFFER HashSha(BYTESTREAM&& outStream, ARGS&& ... args)
{
    BUFFER result;
    if (outStream.size() == SHA384_HASH_LENGTH)
    {
        result = Sha384ComputeHash(std::move(outStream), args ...);
    }
    else if (outStream.size() == SHA512_HASH_LENGTH)
    {
        result = Sha512ComputeHash(std::move(outStream), args ...);
    }
    else if (outStream.size() == SHA256_HASH_LENGTH)
    {
        result = Sha256ComputeHash(std::move(outStream), args ...);
    }
    else if (outStream.size() == SHA1_HASH_LENGTH)
    {
        result = Sha1ComputeHash(std::move(outStream), args ...);
    }
    else DBGBREAK();
    return result;
}

VARGS(BUFFER)
BUFFER HmacSha384_512(BYTESTREAM& outStream, BUFFER secret, ARGS&& ... args)
{
    auto hashLength = outStream.size();
    ASSERT(hashLength == SHA384_HASH_LENGTH || hashLength == SHA512_HASH_LENGTH);

    constexpr static auto BLOCK_SIZE = 128;
    U1024 keyData;

    if (secret.length() > BLOCK_SIZE)
    {
        HashSha(BYTESTREAM(keyData.u8, hashLength), secret);
    }
    else
    {
        BYTESTREAM(keyData).writeBytes(secret);
    }

    U1024 innerPad, outerPad;
    for (UINT32 i = 0; i < U1024_QWORDS; i++)
    {
        innerPad.u64[i] = keyData.u64[i] ^ 0x3636363636363636;
        outerPad.u64[i] = keyData.u64[i] ^ 0x5c5c5c5c5c5c5c5c;
    }

    auto tempHash = HashSha(ByteStream(hashLength), innerPad, args ...);
    return HashSha(outStream.commitTo(outStream.size()), outerPad, tempHash);
}

VARGS(BUFFER)
BUFFER HmacSha384(BYTESTREAM&& outStream, BUFFER key, ARGS&& ... args)
{
    ASSERT(outStream.size() == SHA384_HASH_LENGTH);
    return HmacSha384_512(outStream, key, args ...);
}

VARGS(BUFFER)
BUFFER HmacSha512(BYTESTREAM&& outStream, BUFFER key, ARGS&& ... args)
{
    ASSERT(outStream.size() == SHA512_HASH_LENGTH);
    return HmacSha384_512(outStream, key, args ...);
}

VARGS(BUFFER)
BUFFER HmacSha(BYTESTREAM&& outStream, BUFFER key, ARGS&& ... args)
{
    if (outStream.size() == SHA512_HASH_LENGTH || outStream.size() == SHA384_HASH_LENGTH)
    {
        HmacSha384_512(outStream, key, args ...);
    }
    else if (outStream.size() == SHA256_HASH_LENGTH)
    {
        HmacSha256(std::move(outStream), key, args ...);
    }
    else DBGBREAK();
    return outStream.toBuffer();
}

struct TRANSCRIPT_HASH
{
    SHA256_HASH sha256Hash;
    SHA384_HASH sha384Hash;

    UINT32 hashLength = 0;

    void init(UINT32 length)
    {
        hashLength = length;
        ASSERT(hashLength == SHA256_HASH_LENGTH || hashLength == SHA384_HASH_LENGTH);
    }

    void addMessage(BUFFER message)
    {
        sha256Hash.addMessage(message);
        sha384Hash.addMessage(message);
    }

    BUFFER getHash(BYTESTREAM&& outStream)
    {
        if (hashLength == SHA256_HASH_LENGTH)
        {
            return sha256Hash.getRunningHash(outStream);
        }
        else if (hashLength == SHA384_HASH_LENGTH)
        {
            return sha384Hash.getRunningHash(std::move(outStream));
        }
        return outStream.toBuffer();
    }

    BUFFER getHash()
    {
        return getHash(ByteStream(hashLength));
    }
};


inline UINT64 GetCRC(BUFFER input, UINT64 crc = 0x1EDC6F41)
{
    while (input.length() / sizeof(UINT64))
    {
        crc += _mm_crc32_u64(crc, input.beReadU64());
    }

    while (input.length() / sizeof(UINT32))
    {
        UINT32 crc32 = UINT32(crc);
        crc += _mm_crc32_u32(crc32, input.beReadU32());
    }

    while (input.length() / sizeof(UINT16))
    {
        UINT32 crc32 = UINT32(crc);
        crc += _mm_crc32_u16(crc32, input.beReadU16());
    }

    ASSERT(input.length() == 0);

    return crc;
}

constexpr bool VALID_AES_KEY(UINT32 length) { return length == AES128_KEY_LENGTH || length == AES256_KEY_LENGTH; }

constexpr auto AES_MAX_ROUNDS = 14;
struct AES_KEY
{
    UINT8 roundKeys[AES_BLOCK_SIZE * (AES_MAX_ROUNDS + 1)]{ 0 };
    UINT32 rounds = 0;

    explicit operator bool() { return rounds > 0; }
};

extern "C" int aesni_set_encrypt_key(const unsigned char* userKey, int bits, AES_KEY * key);
extern "C" int aesni_set_decrypt_key(const unsigned char* userKey, int bits, AES_KEY * key);

extern "C" void aesni_ctr32_encrypt_blocks(const unsigned char* in, unsigned char* out, size_t blocks, const AES_KEY* key, const U128* ivec);
extern "C" void aesni_ecb_encrypt(const unsigned char* in, unsigned char* out, size_t bytes, const AES_KEY * key, int enc);
extern "C" void aesni_encrypt(const U128 * in, U128 * out, const AES_KEY * key);
extern "C" void aesni_decrypt(const U128* in, U128* out, const AES_KEY * key);
extern "C" void ghash_init_avx(U128 Htable[16], const UINT64 Xi[2]);
extern "C" void gcm_gmult_avx(U128 *Xi, const U128 Htable[16]);
extern "C" void ghash_avx(U128 *Xi, const U128 Htable[16], const UINT8 * inp, size_t len);

constexpr UINT32 GMAC_LENGTH = 16;
struct AES_GMAC
{
    U128 state;
    U128 precomputeTable[16];
    LOCAL_STREAM<256> lengthVectors;

    void init(U128 H)
    {
        RtlZeroMemory((PUINT8)precomputeTable, sizeof(precomputeTable));
        state.u64[0] = state.u64[1] = 0;
        H.u64[0] = _byteswap_uint64(H.u64[0]);
        H.u64[1] = _byteswap_uint64(H.u64[1]);
        ghash_init_avx(precomputeTable, H.u64);
    }

    void updateBuffer(BUFFER data)
    {
        lengthVectors.beWriteU64(data.length() * 8);
        auto blocks = data.readBytes(data.length() & -AES_BLOCK_SIZE);
        if (blocks)
        {
            ghash_avx(&state, precomputeTable, blocks.data(), blocks.length());
        }

        if (data)
        {
            U128 block;
            RtlCopyMemory(block.u8, data.data(), data.length());
            ghash_avx(&state, precomputeTable, block.u8, AES_BLOCK_SIZE);
        }
    }

    void update(BUFFER aad, BUFFER data)
    {
        updateBuffer(aad);
        updateBuffer(data);
    }

    void finalize(const U128& closure, U128& result)	{

        updateBuffer(lengthVectors.toBuffer());

        state.u64[0] ^= closure.u64[0];
        state.u64[1] ^= closure.u64[1];

        RtlCopyMemory(result.u8, state.u8, AES_BLOCK_SIZE);
        state.u64[0] = state.u64[1] = 0;
        lengthVectors.clear();
    }

    U128 multiply(UINT64 number1, UINT64 number2 = 0)
    {
        U128 result{ number1, number2 };
        gcm_gmult_avx(&result, precomputeTable);
        return result;
    }

    U128 multiply(U128 value)
    {
        gcm_gmult_avx(&value, precomputeTable);
        return value;
    }
};

struct AES_ECB
{
    AES_KEY encryptionKey;

    void setKey(BUFFER encryption)
    {
        ASSERT(VALID_AES_KEY(encryption.length()));
        aesni_set_encrypt_key(encryption.data(), encryption.length() * 8, &encryptionKey);
    }

    void encrypt(U128& data)
    {
        aesni_encrypt(&data, &data, &encryptionKey);
    }
};

struct AES_CTR
{
    AES_KEY keySchedule;
    U128 salt;

    void setKey(BUFFER key)
    {
        ASSERT(key.length() == 16 || key.length() == 24 || key.length() == 32);
        auto ret = aesni_set_encrypt_key(key.data(), key.length() * 8, &keySchedule);
        ASSERT(ret == 0);
    }

    void setSalt(BUFFER saltData)
    {
        BYTESTREAM(salt).writeBytes(saltData);
    }

    void encrypt(U128 iv, RWBUFFER text)
    {
        iv.u64[0] ^= salt.u64[0];
        iv.u64[1] ^= salt.u64[1];
        iv.u16[7] = 0;

        auto fullBlocks = text.readBytes(text.length() & -AES_BLOCK_SIZE);
        aesni_ctr32_encrypt_blocks(fullBlocks.data(), fullBlocks.data(), fullBlocks.length() / AES_BLOCK_SIZE, &keySchedule, &iv);

        if (text)
        {
            U128 block;
            iv.u16[7] = SWAP16(fullBlocks.length() / AES_BLOCK_SIZE);
            aesni_ctr32_encrypt_blocks(text.data(), block.u8, 1, &keySchedule, &iv);
            RtlCopyMemory(text.data(), block.u8, text.length());
        }
    }

    void encrypt(RWBUFFER text)
    {
        U128 iv;
        encrypt(iv, text);
    }

    void init(BUFFER keyBytes, BUFFER saltBytes)
    {
        setKey(keyBytes);
        setSalt(saltBytes);
    }
};

struct GCM_CTR
{
    U128 Yi;
    U128 Y0;
    U128 EK0;
    AES_KEY keySchedule;
    U128 H;
    UINT32 counterBase = 0;

    auto setYi(UINT32 val)
    {
        RtlCopyMemory(Yi.u8, Y0.u8, 12);
        Yi.u32[3] = _byteswap_ulong(counterBase + val);
        return &Yi;
    }

    void setKey(BUFFER key)
    {
        ASSERT(key.length() == 16 || key.length() == 24 || key.length() == 32);
        auto ret = aesni_set_encrypt_key(key.data(), key.length() * 8, &keySchedule);
        ASSERT(ret == 0);

        RtlZeroMemory(H.u8, sizeof(H));
        aesni_encrypt(&H, &H, &keySchedule);
    }

    void setIV(BUFFER iv)
    {
        if (iv.length() != 12)
        {
            AES_GMAC gmac;
            gmac.init(H);
            gmac.updateBuffer(iv);

            U128 zero;
            gmac.finalize(zero, Y0);

            counterBase = _byteswap_ulong(Y0.u32[3]);
        }
        else
        {
            counterBase = 0;
            RtlZeroMemory(Y0.u8, sizeof(Y0));
            RtlCopyMemory(Y0.u8, iv.data(), 12);
        }

        setYi(1);
        aesni_encrypt(&Yi, &EK0, &keySchedule);
    }

    void setIV(const U96& iv)
    {
        ASSERT(keySchedule);

        counterBase = 0;
        RtlCopyMemory(Y0.u8, iv.u8, U96_BYTES);
        Y0.u32[3] = 0;

        setYi(1);
        aesni_encrypt(&Yi, &EK0, &keySchedule);
    }

    void encrypt(RWBUFFER text)
    {
        auto fullBlocks = text.readBytes(text.length() & -AES_BLOCK_SIZE);
        auto blockCount = fullBlocks.length() / AES_BLOCK_SIZE;
        aesni_ctr32_encrypt_blocks(fullBlocks.data(), fullBlocks.data(), blockCount, &keySchedule, setYi(2));

        if (text)
        {
            U128 partialBlock;
            RtlCopyMemory(partialBlock.u8, text.data(), text.length());
            aesni_ctr32_encrypt_blocks(partialBlock.u8, partialBlock.u8, 1, &keySchedule, setYi(2 + blockCount));
            RtlCopyMemory(text.data(), partialBlock.u8, text.length());
        }
    }
};

using GMAC_DATA = UINT8[16];
struct GMAC
{
    struct SAVED_STATE
    {
        U128 state;
        UINT64 crc;
        UINT64 totalDataLength;
    };
    BUFFER protocol;
    U128 state;
    U128 precomputeTable[16];
    UINT64 totalDataLength = 0;
    UINT64 crc = 0x1EDC6F41;
    GCM_CTR aes;

    SAVED_STATE snapshot;

    constexpr static BUFFER SCHEME = "GMAC 1.0";

    bool init(BUFFER secret, BUFFER protocolIn = SCHEME)
    {
        protocol = protocolIn;
        ASSERT(secret.length() >= 32);

        auto key = secret.length() > 32 ? secret.readBytes(32) : secret.readBytes(16);
        aes.setKey(key);
        aes.setIV(secret.readBytes(12));
        crc = secret.beReadU32();

        auto H = aes.EK0;
        state.u64[0] = state.u64[1] = 0;
        H.u64[0] = _byteswap_uint64(H.u64[0]);
        H.u64[1] = _byteswap_uint64(H.u64[1]);
        ghash_init_avx(precomputeTable, H.u64);

        updateState(secret);

        saveState();

        return true;
    }

    void saveState()
    {
        snapshot.state = state;
        snapshot.crc = crc;
        snapshot.totalDataLength = totalDataLength;
    }

    void restoreState()
    {
        state = snapshot.state;
        crc = snapshot.crc;
        totalDataLength = snapshot.totalDataLength;
    }

    LOCAL_STREAM<128> stateStream;
    void updateState(BUFFER data)
    {
        while (data)
        {
            stateStream.clear();

            auto bytesToRead = min(stateStream.size(), data.length());
            stateStream.writeBytes(data.readBytes(bytesToRead));

            BUFFER blocks{ stateStream.address(), (UINT32)ROUNDTO(AES_BLOCK_SIZE, bytesToRead) };

            aes.setYi(UINT32(totalDataLength + 2));
            totalDataLength += bytesToRead;

            aesni_ctr32_encrypt_blocks(blocks.data(), (PUINT8)blocks.data(), blocks.length() / AES_BLOCK_SIZE, &aes.keySchedule, &aes.Yi);

            ghash_avx(&state, precomputeTable, blocks.data(), blocks.length());

            auto crcData = (UINT64*)blocks.data();
            for (UINT32 i = 0, j = blocks.length() / 8; i < j; i += 2)
            {
                crc += _mm_crc32_u64(crc, crcData[i]);
                crc += _mm_crc32_u64(crc, crcData[i+1]);
            }
        }
    }

    U128 finalize()
    {
        LOCAL_STREAM<16> outStream;
        outStream.beWriteU64(totalDataLength * 8);
        outStream.beWriteU64(crc);

        auto finalState = state;
        auto outBuffer = outStream.toBuffer();
        ghash_avx(&finalState, precomputeTable, outBuffer.data(), outBuffer.length());

        return finalState;
    }

    BUFFER keyGen(BUFFER context, BYTESTREAM&& outStream)
    {
        auto length = outStream.size();
        ASSERT((length % 16) == 0);
        restoreState();

        UINT32 index = 0;

        while (outStream.count() < length)
        {
            LOCAL_STREAM<64> keyStream;
            auto keyData = keyStream.clear().writeMany(protocol, " ", context, " ", index++);
            updateState(keyData);
            outStream.writeBytes(finalize());
        }

        return outStream.toBuffer();
    }

    BUFFER getDigest(GMAC_DATA &digest)
    {
        restoreState();

        auto finalState = finalize();

        BYTESTREAM outStream{ digest };
        outStream.writeU128(finalState);

        return BUFFER{ digest, 16 };
    }
};

VARGS(BUFFER)
BUFFER GetGMAC(BUFFER key, GMAC_DATA& digest, ARGS&& ... args)
{
    GMAC kdf;
    kdf.init(key);
    BUFFER buffers[] = { args ... };
    for (UINT32 i = 0; i < ARRAYSIZE(buffers); i++)
    {
        kdf.updateState(buffers[i]);
    }
    return kdf.getDigest(digest);
}

struct IDENTITY
{
    UINT32 authority;
    UINT32 type;
    UINT64 id;
};

struct AES_GCM
{
    GCM_CTR aes;
    AES_GMAC gmac;
    AES_GCM_IV salt;
    U128 encryptTag;

    auto saltStream() { return BYTESTREAM(salt.u8, AES_GCM_IV_LENGTH); }

    explicit operator bool() const { return aes.keySchedule.rounds > 0; }

    AES_GCM() {}

    void setKey(BUFFER key)
    {
        aes.setKey(key);
        gmac.init(aes.H);
    }

    void init(BUFFER key, BUFFER iv)
    {
        setKey(key);
        aes.setIV(iv);
    }

    void encrypt(BUFFER aad, RWBUFFER text, U128& tag)
    {
        ASSERT(aes.Y0);

        aes.encrypt(text);
        gmac.update(aad, text.toBuffer());
        gmac.finalize(aes.EK0, tag);
    }

    void mergeSalt(AES_GCM_IV& iv)
    {
        ASSERT(salt);
        iv.u32[0] ^= salt.u32[0];
        iv.u32[1] ^= salt.u32[1];
        iv.u32[2] ^= salt.u32[2];
    }

    void encrypt(AES_GCM_IV& iv, BUFFER aad, RWBUFFER text, U128& tag)
    {
        mergeSalt(iv);
        aes.setIV(iv);
        encrypt(aad, text, tag);
    }

    BUFFER encrypt(AES_GCM_IV& iv, BUFFER aad, RWBUFFER text)
    {
        encrypt(iv, aad, text, encryptTag);
        return BUFFER{ encryptTag };
    }

    VARGS(BUFFER)
    U128 hash(ARGS&& ... args)
    {
        BUFFER inputBuffers[] = { args ... };
        for (UINT32 i = 0; i < ARRAYSIZE(inputBuffers); i++)
        {
            gmac.updateBuffer(inputBuffers[i]);
        }
        U128 tag;
        gmac.finalize(aes.EK0, tag);
        return tag;
    }

    BUFFER decrypt(BUFFER aad, RWBUFFER cipherText, BUFFER receivedTag)
    {
        ASSERT(aes.Y0);
        auto decryptBuffer = NULL_BUFFER;

        U128 computedTag;
        gmac.update(aad, cipherText.toBuffer());
        gmac.finalize(aes.EK0, computedTag);

        auto tagMatch = RtlCompareMemory(computedTag.u8, receivedTag.data(), AES_TAG_LENGTH) == AES_TAG_LENGTH;
        if (tagMatch)
        {
            aes.encrypt(cipherText); // in CTR mode encrypt/decrypt is just XOR
            decryptBuffer = cipherText.toBuffer(); 
        }
        else DBGBREAK();

        return decryptBuffer;
    }

    BUFFER decrypt(AES_GCM_IV& iv, BUFFER aad, RWBUFFER cipherText)
    {
        auto tag = cipherText.shrink(AES_TAG_LENGTH).toBuffer();
        return decrypt(iv, aad, cipherText, tag);
    }

    BUFFER decrypt(AES_GCM_IV& iv, BUFFER aad, RWBUFFER text, BUFFER tag)
    {
        mergeSalt(iv);
        aes.setIV(iv);
        return decrypt(aad, text, tag);
    }
};

using DRBG_STATE = U128[8];

struct DRBG
{
    DRBG_STATE currentState;
    U128 precomputeTable[16];
    AES_KEY keySchedule;
    U128 iv;
    DRBG_STATE seedState;

    void doRound()
    {
        aesni_set_encrypt_key((PUINT8)currentState, 256, &keySchedule);

        iv = currentState[2];

        ghash_init_avx(precomputeTable, currentState[3].u64);

        aesni_ctr32_encrypt_blocks((PUINT8)currentState, (PUINT8)currentState, 8, &keySchedule, &iv);

        U128 temp;
        for (UINT32 i = 0; i < 8; i++)
        {
            ghash_avx(&temp, precomputeTable, (PUINT8)&currentState[i], AES_BLOCK_SIZE);
            currentState[i] = temp;
        }
    }

    void init(BUFFER keyBytes)
    {
        ASSERT(keyBytes.length() == 64);
        RtlCopyMemory((PUINT8)currentState, keyBytes.data(), 64);
        doRound();
        RtlCopyMemory((PUINT8)seedState, (PUINT8)currentState, sizeof(DRBG_STATE));
    }

    void reset()
    {
        RtlCopyMemory(&currentState, &seedState, sizeof(currentState));
    }

    void resetTo(DRBG& clone)
    {
        RtlCopyMemory(&clone.currentState, &seedState, sizeof(currentState));
        RtlCopyMemory(&clone.seedState, &seedState, sizeof(currentState));
    }
};

extern UINT64 TPMincrementIndex(UINT32 index);

struct DRBG_CTR
{
    DRBG drbg;
    UINT64 lastRound = 0;
    UINT32 tpmCounter;

    DRBG_CTR(UINT32 tpmCounter = 0) : tpmCounter(tpmCounter) {}

    void init(BUFFER keyBytes)
    {
        drbg.init(keyBytes);
        if (tpmCounter)
        {
            lastRound = TPMincrementIndex(tpmCounter);
        }

        for (UINT32 i = 0; i < lastRound; i++)
        {
            drbg.doRound();
        }
    }

    U128 getNextId()
    {
        drbg.doRound();
        lastRound++;
        if (tpmCounter) TPMincrementIndex(tpmCounter);
        auto nextId = drbg.currentState[4];
        return nextId;
    }

    U128 getNextId(U128& lastKey)
    {
        U128 result;
        if (drbg.currentState[4] == lastKey)
        {
            result = getNextId();
        }
        else
        {
            DRBG drbgCopy; drbg.resetTo(drbgCopy);

            for (UINT32 i = 0; i < lastRound; i++)
            {
                drbgCopy.doRound();
                if (drbgCopy.currentState[4] == lastKey)
                {
                    drbgCopy.doRound();
                    result = drbgCopy.currentState[4];
                    break;
                }
            }
        }
        ASSERT(result);
        return result;
    }
};

using DRBG_KEYGEN_DATA = UINT8[64];

struct DRBG_KEYGEN
{
    DRBG drbg;
    DRBG_STATE cache[32];

    UINT64 cacheMask;
    UINT32 cacheInterval;
    bool cacheReady = false;

    void buildCache()
    {
        UINT64 max32 = 1Ui64 << 28;
        cacheMask = max32 - 1;
        cacheInterval = (UINT32)(max32 / ARRAYSIZE(cache));

        LogInfo("cahceMask: ", cacheMask, " cacheInterval: ", cacheInterval);

        for (UINT32 j = 0; j < ARRAYSIZE(cache); j++)
        {
            auto&& cacheState = cache[j];
            for (UINT32 i = 0; i < cacheInterval; i++)
            {
                drbg.doRound();
            }
            RtlCopyMemory(&cacheState, &drbg.currentState, sizeof(DRBG_STATE));
        }
        _ReadWriteBarrier();
        cacheReady = true;
    }

    BUFFER getBytes(UINT64 hash, U128 closure, BYTESTREAM&& stream)
    {
        if (cacheReady)
        {
            auto rounds = hash & cacheMask;
            auto index = rounds / cacheInterval;
            RtlCopyMemory(&drbg.currentState, &cache[index], sizeof(drbg.currentState));

            rounds &= cacheInterval - 1;

            for (UINT32 i = 0; i < rounds; i++)
            {
                drbg.doRound();
            }
        }
        else
        {
            auto rounds = hash & 0x0FFFFF;
            for (UINT32 i = 0; i < rounds; i++)
            {
                drbg.doRound();
            }
        }
        //AVX128 gmacKey(identity.u64[0] | timestamp, identity.u64[1] | timestamp);
        ghash_init_avx(drbg.precomputeTable, closure.u64);

        U128 temp;
        for (UINT32 i = 4; i < 8; i++)
        {
            ghash_avx(&temp, drbg.precomputeTable, (PUINT8)&drbg.currentState[i], AES_BLOCK_SIZE);
            drbg.currentState[i] = temp;
        }

        BUFFER keyData((PUINT8)&drbg.currentState[4], 64);
        stream.writeBytes(keyData);

        return stream.toBuffer();
    }

    BUFFER getBytes(SHA256_DATA& sha256digest, DRBG_KEYGEN_DATA& keyData)
    {
        auto crc = GetCRC(sha256digest);
        U256& digest = *(U256*)sha256digest;
        U128 closure{ digest.u64[0] ^ digest.u64[1], digest.u64[2] ^ digest.u64[3] };

        return getBytes(crc, closure, BYTESTREAM(keyData));
    }

    BUFFER getBytes(const U128& id, UINT64 timestamp, DRBG_KEYGEN_DATA& keyData)
    {
        UINT64 hash = id.u64[0] ^ id.u64[1] ^ timestamp;
        U128 closure{ id.u64[0] ^ timestamp, id.u64[1] ^ timestamp };
        return getBytes(hash, closure, BYTESTREAM(keyData));
    }

    void init(BUFFER keyBytes, bool needCache = false)
    {
        drbg.init(keyBytes);
        if (needCache)
        {
            ThreadPool.runTask([](PVOID context, NTSTATUS, STASK_ARGV)
                {
                    auto&& drbg = *(DRBG_KEYGEN*)context;
                    drbg.buildCache();
                }, this);
        }
        else
        {
            cacheMask = 0x000FFFFF;
            cacheInterval = 1;
            cacheReady = false;
        }
    }
};

extern "C" int CRYPTO_memcmp(const void* in_a, const void* in_b, size_t len);
extern "C" size_t OPENSSL_ia32_rdrand_bytes(unsigned char* buf, size_t len);

extern "C" void x25519_scalar_mult(uint8_t out[32], const uint8_t scalar[32], const uint8_t point[32]);

extern "C" bool EcxMapKey(TOKEN nodeId, U256 & pointFrom, U256 & pointTo);

constexpr static U256 ECX_POINT_G{ 1, 2, 3, 4 };

template <typename STACK = SERVICE_STACK>
struct ECX_KEYSHARE
{
    struct POINT_MAP
    {
        U256 pointFrom;
        U256 pointTo;

        POINT_MAP(const U256& from, const U256& to)
        {
            pointFrom = from;
            pointTo = to;
        }

        bool match(const U256& point) const { return pointFrom == point; }
        explicit operator bool() const { return IsValidRef(*this); }
    };

    TOKEN nodeId;
    U256 privateKey;

    void initialize(TOKEN id)
    {
        nodeId = id;

        Random.getBytes(privateKey.u8);
        privateKey.u8[0] &= 248;
        privateKey.u8[31] &= 127;
        privateKey.u8[31] |= 64;
    }

    struct ENDPOINT
    {
        TOKEN node;
        DATASTREAM<POINT_MAP, STACK, 2> points;

        ENDPOINT(TOKEN node) : node(node)
        {
            points.clear();
        }

        bool match(const TOKEN arg) const { return node == arg; }
        explicit operator bool() const { return IsValidRef(*this); }
    };

    DATASTREAM<ENDPOINT, STACK, 2> endpointStream;

    void addEndpoint(TOKEN node, const U256& pointFrom, const U256& pointTo)
    {
        auto&& match = endpointStream.toRWBuffer().find(node);
        auto& endpoint = match ? match : endpointStream.append(node);

        auto&& pointMatch = endpoint.points.toBuffer().find(pointFrom);
        if (!pointMatch)
        {
            endpoint.points.append(pointFrom, pointTo);
        }
    }

    void mapPoint(U256& pointTo)
    {
        X25519_public_from_private(pointTo.u8, privateKey.u8);
    }

    void mapPoint(U256& pointTo, const U256& pointFrom) const
    {
        if (pointFrom == ECX_POINT_G)
        {
            X25519_public_from_private(pointTo.u8, privateKey.u8);
        }
        else
        {
            x25519_scalar_mult(pointTo.u8, privateKey.u8, pointFrom.u8);
        }
    }

    bool getKeyshare(U256& keyshare)
    {
        auto status = false;

        keyshare = U256_ZERO;
        auto&& endpoints = endpointStream.toBuffer();
        ASSERT(endpoints);

        auto&& firstNode = endpoints.shift();
        auto gMap = firstNode.points.toBuffer().find(ECX_POINT_G);
        ASSERT(gMap);

        auto nextKey = gMap.pointTo;

        for (auto&& endpoint : endpoints)
        {
            auto&& nextMap = endpoint.points.toBuffer().find(nextKey);
            if (nextMap)
            {
                nextKey = nextMap.pointTo;
            }
            else
            {
                U256 thisKey = nextKey;
                auto successful = EcxMapKey(endpoint.node, thisKey, nextKey);
                if (!successful)
                {
                    nextKey = U256_ZERO;
                    break;
                }
            }
        }

        if (nextKey)
        {
            X25519(keyshare.u8, privateKey.u8, nextKey.u8);
            status = true;
        }
        return status;
    }

    bool match(TOKEN node) const { return nodeId == node; }
    explicit operator bool() const { return IsValidRef(*this); }
};

constexpr UINT32 X25519_KEY_LENGTH = 32;

using X25519_KEY_DATA = UINT8[X25519_KEY_LENGTH];

struct X25519_KEYSHARE
{
    UINT8 privateKey[X25519_KEY_LENGTH];
    UINT8 sharedSecret[X25519_KEY_LENGTH];

    X25519_KEYSHARE()
    {
        auto key = Random.getBytes(privateKey);

        privateKey[0] &= 248;
        privateKey[31] &= 127;
        privateKey[31] |= 64;
    }

    BUFFER getPublicKey(BYTESTREAM&& keyStream)
    {
        auto address = keyStream.commit(X25519_KEY_LENGTH);
        X25519_public_from_private(address, privateKey);

        return { address, X25519_KEY_LENGTH };
    }

    void createSecret(BUFFER peerKey)
    {
        ASSERT(peerKey.length() == X25519_KEY_LENGTH);
        X25519(sharedSecret, privateKey, peerKey.data());
    }

    void importPrivateKey(BUFFER keyData)
    {
        ASSERT(keyData.length() == X25519_KEY_LENGTH);
        memcpy(privateKey, keyData.data(), keyData.length());
    }
};

constexpr ULONG ECC_KEY_SIZE = 0x20;
constexpr ULONG ECC_KEY_XY_SIZE = 0x40;
using ECC_KEY = UINT8[ECC_KEY_SIZE];
using ECC_KEY_STREAM = LOCAL_STREAM<ECC_KEY_SIZE>;

int ecc_gen_privkey(unsigned int curve_id, UINT64* privkey);
int ecc_make_pub_key(unsigned int curve_id, const UINT64* private_key, UINT64* public_key);
int crypto_ecdh_shared_secret(unsigned int curve_id, const UINT64* private_key, const UINT64* public_key, UINT64* secret);

struct ECDH_KEYSHARE
{
    ECDH256_PRIVATE_KEY_DATA privateKey;
    ECDH256_PUBLIC_KEY_DATA publicKey;
    ECDH256_PUBLIC_KEY_DATA sharedSecret;

    void initialize(SUPPORTED_GROUPS group)
    {
        ASSERT(group == SUPPORTED_GROUPS::secp256r1);
        do
        {
            ecc_gen_privkey(ECC_CURVE_NIST_P256, (UINT64*)privateKey);
            ecc_make_pub_key(ECC_CURVE_NIST_P256, (UINT64*)privateKey, (UINT64*)publicKey);

        } while (false);
    }

    BUFFER getPublicKey(BYTESTREAM& outStream)
    {
        auto start = outStream.getPosition();
        outStream.writeByte(0x04); // non compressed
        outStream.writeBytes(publicKey);
        return start.toBuffer();
    }

    BUFFER createSharedSecret(BUFFER peerKey)
    {
        BUFFER result;
        if (peerKey.peek() == 0x04)
            peerKey.shift();

        crypto_ecdh_shared_secret(ECC_CURVE_NIST_P256, (UINT64 *)privateKey, (UINT64*)peerKey.data(), (UINT64*)sharedSecret);
        return BUFFER{ sharedSecret, ECDH256_KEY_SIZE };
    }
};

struct CRYPTO
{
    BUFFER ZeroHmac256;
    BUFFER ZeroHmac384;
    BUFFER ZeroHmac512;

    BUFFER NullHash256;
    BUFFER NullHash384;
    BUFFER NullHash512;

    void Init()
    {
        auto&& outStream = GlobalStack().blobStream;
        ZeroHmac256 = HmacSha256(outStream.commitTo(SHA256_HASH_LENGTH), ZeroBytes.toBuffer(SHA256_HASH_LENGTH), ZeroBytes.toBuffer(SHA256_HASH_LENGTH));
        ZeroHmac384 = HmacSha384(outStream.commitTo(SHA384_HASH_LENGTH), ZeroBytes.toBuffer(SHA384_HASH_LENGTH), ZeroBytes.toBuffer(SHA384_HASH_LENGTH));
        ZeroHmac512 = HmacSha512(outStream.commitTo(SHA512_HASH_LENGTH), ZeroBytes.toBuffer(SHA512_HASH_LENGTH), ZeroBytes.toBuffer(SHA512_HASH_LENGTH));

        NullHash256 = Sha256ComputeHash(outStream.commitTo(SHA256_HASH_LENGTH), NULL_BUFFER);
        NullHash384 = Sha384ComputeHash(outStream.commitTo(SHA384_HASH_LENGTH), NULL_BUFFER);
        NullHash512 = Sha512ComputeHash(outStream.commitTo(SHA512_HASH_LENGTH), NULL_BUFFER);
    }

    BUFFER getZeroHmac(UINT32 hashLength)
    {
        BUFFER result;
        if (hashLength == SHA256_HASH_LENGTH)
        {
            result = ZeroHmac256;
        }
        else if (hashLength == SHA384_HASH_LENGTH)
        {
            result = ZeroHmac384;
        }
        else if (hashLength == SHA512_HASH_LENGTH)
        {
            result = ZeroHmac512;
        }
        else DBGBREAK();
        return result;
    }

    BUFFER getNullHash(UINT32 hashLength)
    {
        BUFFER result;
        if (hashLength == SHA256_HASH_LENGTH)
        {
            result = NullHash256;
        }
        else if (hashLength == SHA384_HASH_LENGTH)
        {
            result = NullHash384;
        }
        else if (hashLength == SHA512_HASH_LENGTH)
        {
            result = NullHash512;
        }
        else DBGBREAK();
        return result;
    }
};
inline CRYPTO Crypto;

UINT32 UpdateCrc32(UINT32 start, const void* buf, size_t len);

inline UINT32 ComputeCrc32(BUFFER buffer)
{
    return UpdateCrc32(0, buffer.data(), buffer.length());
}

constexpr UINT32 ECDSA_SIGN_LENGTH = 64;
using ECDSA_DATA = UINT8[ECDSA_SIGN_LENGTH];

bool ecdsa_verify(BUFFER publicKey, BUFFER hashData, BUFFER signature, BUFFER norValue = NULL_BUFFER);
void ecdsa_sign(BUFFER privateKey, BUFFER hashData, ECDSA_DATA& signature);

extern CRYPTO Crypto;
