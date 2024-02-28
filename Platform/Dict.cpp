
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#include "pch.h"
#include "Types.h"

void TestDict()
{
    auto buf1 = PString.trimSpaces("   test2  ");
    auto buf2 = PString.trimSpaces("test2");
    auto number = PString.toNumber("12345", 10);
    auto name1 = CreateName("123ABCDEF123qrstuv789");
    auto length = GetNameLength(name1);
    auto name2 = CreateName("test");
    auto length2 = GetNameLength(name2);
    auto name21 = CreateName("TEST");
    auto name22 = CreateName("123");
    auto nameString = GetName(name1);
    auto nameString2 = GetName(name2);
    auto nameString21 = GetName(name21);
    auto name3 = CreateName("123abcdef123qrstuv789");
    auto name4 = CreateName("testanother");
    auto name5 = CreateName("BIGBADDUMMY");
    auto nameString5 = GetName(name5);
    printf("done\n");
}