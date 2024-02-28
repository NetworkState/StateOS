
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

//constexpr void* operator new (size_t, void* ptr) { return ptr; }

template <typename T, typename ... Args>
T& MemAlloc(Args&& ... args)
{
    auto address = (T*)VirtualAlloc(nullptr, sizeof(T), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    ASSERT(address);
    new (address) T(args ...);
    return *address;
}

inline PVOID MemAlloc(UINT32 size)
{
    ASSERT(size > 4000);
    return VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
}

inline PVOID MemAllocLarge(UINT32 size)
{
    ASSERT(size >= LargePageSize);
    ASSERT(IS_ALIGNED(size, LARGE_PAGE_SIZE));
    size = ROUND_TO(size, LargePageSize);

    auto address = (PVOID)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (address == nullptr)
    {
        DBGBREAK();
        address = (PVOID)VirtualAlloc(nullptr, size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    }
    return address;
}

inline void MemFree(PVOID address)
{
    VirtualFree(address, 0, MEM_RELEASE);
}

template <typename ST>
void* StackAlloc(UINT32 size);

struct STACK_MEMORY
{
    UINT32 stackSize = 0;
    PUINT8 startAddress = nullptr;
    PUINT8 currentAddress = nullptr;

    UINT32 overflowStackSize = 0;
    PUINT8 overflowStart = nullptr;
    PUINT8 overflowCurrent = nullptr;

    STACK_MEMORY() {}

    void init(PVOID staticMemory)
    {
        ASSERT(startAddress == nullptr);
        startAddress = (PUINT8)staticMemory;
        *(PVOID*)startAddress = startAddress;
        currentAddress = startAddress + 64;
    }

    void free()
    {
        if (overflowStart)
        {
            MemFree(overflowStart);
            overflowStart = overflowCurrent = nullptr;
        }
        if (startAddress)
        {
            MemFree(startAddress);
            startAddress = currentAddress = nullptr;
        }
    }

    void init(UINT32 staticSize, UINT32 dynamicSize = 0)
    {
        stackSize = staticSize;
        overflowStackSize = dynamicSize;

        //auto staticPool = MemAlloc(stackSize);
        auto staticPool = MemAllocLarge(stackSize);
        if (staticPool == nullptr)
        {
            LogError("Stack: VirtualAlloc failed");
        }
        else
        {
            init(staticPool);
        }
    }

    void clear()
    {
        ASSERT(*(PVOID*)startAddress == startAddress);
        RtlZeroMemory(startAddress + 64, currentAddress - (startAddress + 64));
        currentAddress = startAddress + 64;
        if (overflowStackSize > 0 && overflowStart != nullptr)
        {
            MemFree(overflowStart);
            overflowCurrent = overflowStart = nullptr;
        }
    }
};

template <typename T, typename ST, typename ... Args>
T& StackAlloc(Args&& ... args)
{
    auto newAddress = (PUINT8)StackAlloc<ST>(sizeof(T));
    new (newAddress) T(args ...);

    return *(T*)newAddress;
}
extern PVOID StackAllocNoLock(STACK_MEMORY& stackInfo, UINT32 size);
