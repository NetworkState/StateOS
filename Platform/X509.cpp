
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#include "pch.h"
#include "Types.h"
#include "X509.h"

X509_OPS X509;

template <typename STREAM>
void EncodeOid(const char* inString, STREAM&& outString)
{
    outString.writeString("{ ");
    UINT32 first = 0, second = 0;
    char* endPtr;
    while (auto number = strtoul(inString, &endPtr, 10))
    {
        if (first == 0)
        {
            first = number;
        }
        else if (second == 0)
        {
            second = number;
            UINT8 byte = first * 40 + second;
            outString.writeString("0x");
            outString.writeHex(byte);
            outString.writeString(", ");
        }
        else
        {
            UINT8 encodedBytes[4];
            UINT8 encodedLength = 0;

            encodedBytes[encodedLength++] = (UINT8)(number & 0x7F);
            number >>= 7;

            while (number > 0)
            {
                auto byte = (UINT8)(number & 0x7F);
                encodedBytes[encodedLength++] = byte | 0x80;
                number >>= 7;
            }

            for (UINT8 i = encodedLength; i > 0; i--)
            {
                outString.writeString("0x");
                outString.writeHex(encodedBytes[i - 1]);
                outString.writeString(", ");
                //oid.data[oid.length++] = encodedBytes[i - 1];
            }
        }
        if (endPtr == nullptr || *endPtr == 0)
            break;
        else
            inString = endPtr + 1;
    }
    outString.writeChar('}');
}
