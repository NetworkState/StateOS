
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#include "pch.h"
#include "Types.h"
#include "TPM.h"
#include "File.h"

CLOCK SystemClock;
SCLOCK SecondsClock;

UINT32 LargePageSize;
bool LargePageSupport;

template <typename ST>
void* StackAllocInternal(UINT32 size)
{
    auto& stackInfo = ST::GetCurrent().memory;
    ASSERT(stackInfo.currentAddress);
    PVOID newAddress = nullptr;
    if ((stackInfo.currentAddress + size) < (stackInfo.startAddress + stackInfo.stackSize))
    {
        auto current = stackInfo.currentAddress;
        newAddress = InterlockedCompareExchangePointer((volatile PVOID*)&stackInfo.currentAddress, (current + size), current);
        ASSERT(newAddress == current);
    }
    else
    {
        ASSERT(stackInfo.overflowStackSize != 0);
        if (stackInfo.overflowStart == nullptr)
        {
            auto overflowStart = (PUINT8)MemAlloc(stackInfo.overflowStackSize);
            ASSERT(overflowStart != nullptr);
            auto oldValue = InterlockedCompareExchangePointer((volatile PVOID*)&stackInfo.overflowStart, overflowStart, nullptr);
            ASSERT(oldValue == nullptr);
            stackInfo.overflowCurrent = stackInfo.overflowStart;
        }
        auto current = stackInfo.overflowCurrent;
        if ((stackInfo.overflowCurrent + size) < (stackInfo.overflowStart + stackInfo.overflowStackSize))
        {
            newAddress = InterlockedCompareExchangePointer((volatile PVOID*)&stackInfo.overflowCurrent, current + size, current);
            ASSERT(newAddress == current);
        }
        else DBGBREAK();
    }
    return newAddress;
}

PVOID StackAllocNoLock(STACK_MEMORY& stackInfo, UINT32 size)
{
    ASSERT(stackInfo.currentAddress);
    PVOID newAddress = nullptr;
    if ((stackInfo.currentAddress + size) < (stackInfo.startAddress + stackInfo.stackSize))
    {
        newAddress = stackInfo.currentAddress;
        stackInfo.currentAddress += size;
    }
    else
    {
        ASSERT(stackInfo.overflowStackSize != 0);
        if (stackInfo.overflowStart == nullptr)
        {
            stackInfo.overflowCurrent = stackInfo.overflowStart = (PUINT8)MemAlloc(stackInfo.overflowStackSize);
            ASSERT(stackInfo.overflowCurrent != nullptr);
        }
        auto current = stackInfo.overflowCurrent;
        if ((stackInfo.overflowCurrent + size) < (stackInfo.overflowStart + stackInfo.overflowStackSize))
        {
            newAddress = stackInfo.overflowCurrent;
            stackInfo.overflowCurrent += size;
        }
        else DBGBREAK();
    }
    return newAddress;
}

template<>
void* StackAlloc<GLOBAL_STACK>(UINT32 size)
{
    return StackAllocInternal<GLOBAL_STACK>(size);
}

template<>
void* StackAlloc<SERVICE_STACK>(UINT32 size)
{
    return StackAllocInternal<SERVICE_STACK>(size);
}

template<>
void* StackAlloc<SESSION_STACK>(UINT32 size)
{
    return StackAllocNoLock(GetSessionStack().memory, size);
}

template<>
void* StackAlloc<SCHEDULER_STACK>(UINT32 size)
{
    return StackAllocNoLock(GetSchedulerStack().memory, size);
}

template<>
void* StackAlloc<THREAD_STACK>(UINT32 size)
{
    DBGBREAK();
    return _malloca(size);
}

SCHEDULER_INFO<>& GetCurrentScheduler()
{
    auto scheduler = CONTAINING_RECORD(&GetSchedulerStack(), SCHEDULER_INFO<>, schedulerStack);
    return *scheduler;
}

static const UINT32 kCrc32Polynomial = 0xEDB88320;
static UINT32 kCrc32Table[256] = { 0 };

static void InitCrc32Table()
{
    for (UINT32 i = 0; i < ARRAYSIZE(kCrc32Table); ++i)
    {
        UINT32 c = i;
        for (size_t j = 0; j < 8; ++j) {
            if (c & 1) {
                c = kCrc32Polynomial ^ (c >> 1);
            }
            else {
                c >>= 1;
            }
        }
        kCrc32Table[i] = c;
    }
}

UINT32 UpdateCrc32(UINT32 start, const void* buf, size_t len)
{
    UINT32 c = start ^ 0xFFFFFFFF;
    const UINT8* u = static_cast<const UINT8*>(buf);
    for (size_t i = 0; i < len; ++i) {
        c = kCrc32Table[(c ^ u[i]) & 0xFF] ^ (c >> 8);
    }
    return c ^ 0xFFFFFFFF;
}

extern void PopulateNames();
extern void ServiceMain();

SYSTEM_SERVICE* SystemServicePtr;
SYSTEM_SERVICE& SystemService() { return *SystemServicePtr; }

LPFN_CONNECTEX ConnectExFunc;
LPFN_ACCEPTEX AcceptExFunc;
LPFN_DISCONNECTEX DisconnectExFunc;

ADDRINFOEX DnsResolverHints;

HRESULT InitWinsock()
{
    auto result = STATUS_UNSUCCESSFUL;
    do
    {
        WSADATA wsaData;
        auto ret = WSAStartup(MAKEWORD(2, 2), &wsaData);
        if (ret != 0)
        {
            printf("WSAStartup failed, 0x%x\n", GetLastError());
            break;
        }

        auto socket = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, WSA_FLAG_OVERLAPPED);
        if (socket == INVALID_SOCKET)
        {
            printf("WSASocket failed, error=0x%x\n", GetLastError());
            break;
        }

        GUID guid = WSAID_CONNECTEX;
        DWORD bytesReturned;
        auto ioctlRet = WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(GUID), &ConnectExFunc, sizeof(ConnectExFunc), &bytesReturned, NULL, NULL);
        if (ioctlRet == SOCKET_ERROR)
        {
            printf("WSAIoctl GetConnextEx Ptr failed, error=0x%x\n", WSAGetLastError());
            break;
        }

        guid = WSAID_ACCEPTEX;
        ioctlRet = WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(GUID), &AcceptExFunc, sizeof(AcceptExFunc), &bytesReturned, NULL, NULL);
        if (ioctlRet == SOCKET_ERROR)
        {
            break;
        }

        guid = WSAID_DISCONNECTEX;
        ioctlRet = WSAIoctl(socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(GUID), &DisconnectExFunc, sizeof(DisconnectExFunc), &bytesReturned, NULL, NULL);
        if (ioctlRet == SOCKET_ERROR)
        {
            break;
        }

        closesocket(socket);

        ZeroMemory(&DnsResolverHints, sizeof(DnsResolverHints));
        DnsResolverHints.ai_family = AF_INET;
        DnsResolverHints.ai_socktype = SOCK_STREAM;

        result = STATUS_SUCCESS;

    } while (false);

    return result;
}

extern NTSTATUS InitWinsock();
extern "C" unsigned int OPENSSL_ia32cap_P[4];
extern "C" UINT64 OPENSSL_ia32_cpuid(UINT32*);

extern "C" void OPENSSL_cpuid_setup(void)
{
    auto cpuid = OPENSSL_ia32_cpuid(OPENSSL_ia32cap_P);
    OPENSSL_ia32cap_P[0] = (unsigned int)cpuid | (1 << 10);
    OPENSSL_ia32cap_P[1] = (unsigned int)(cpuid >> 32);
}

template <>
TOKEN_OPS<SERVICE_STACK>& TokenOps<SERVICE_STACK>() { return ServiceTokens; }

template <>
TOKEN_OPS<SESSION_STACK>& TokenOps<SESSION_STACK>() { return SessionTokens; }

THREAD_POOL ThreadPool;

UINT64 QPCfrequency;
UINT64 TicksAtStartup;

void InitializeClock()
{
    QueryPerformanceFrequency((PLARGE_INTEGER)&QPCfrequency);
    ASSERT(QPCfrequency == TICKS_PER_SECOND);

    TicksAtStartup = GetTicks();
}

bool IsVM;

bool AVX512_ON = false;
void GetCPUfeatures()
{
    UINT32 cpuIdInfo[4];
    __cpuid((int *)cpuIdInfo, 7);

    AVX512_ON = (cpuIdInfo[1] & BIT32(16)) != 0;

    __cpuid((int *)cpuIdInfo, 1);

    IsVM = (cpuIdInfo[2] & BIT32(31)) != 0;
}

void InitDefaults()
{
    File.downloadDirectory = "Downloads\\";
}

AVX3_STRING PString;
ASCII_TOLOWER_ST ASCII_TOLOWER = ASCII_TOLOWER_ST();
ASCII_VOWEL_ST ASCII_VOWEL = ASCII_VOWEL_ST();
M512_PERMUTE PERMUTE0 = M512_PERMUTE(0);

extern void TestDict();
extern void TestJson();
extern void InitJson();

void StartPlatform()
{
    // runs under system scheduler
    InitDefaults();
    PopulateNames();
    TestDict();
    InitJson();
    File.Init();
    Crypto.Init();
    ThreadPool.init();
    TPM.init();
}

void RunSystemService()
{
    SystemServicePtr = &MemAlloc<SYSTEM_SERVICE>();
    SystemServicePtr->init();
    SystemService().scheduler.runTask([](PVOID, NTSTATUS, STASK_ARGV)
        {
            StartPlatform();
            SystemService().start();
            ServiceMain();
        }, SystemServicePtr);
}

bool EnableLargePages();

NTSTATUS InitPlatform()
{
    auto result = STATUS_SUCCESS;
    do
    {
        LargePageSupport = EnableLargePages();
        ASSERT(LargePageSupport);

        SYSTEMTIME stateOSTime{ .wYear = 2020, .wMonth = 2, .wDay = 20, .wHour = 20, .wMinute = 20, .wSecond = 20, .wMilliseconds = 20 };
        UINT64 timestampOrigin;
        SystemTimeToFileTime(&stateOSTime, (LPFILETIME)&timestampOrigin);

        GetCPUfeatures();
        ASSERT(AVX512_ON);

        for (UINT32 i = 0; i < Base64Chars.length(); i++)
        {
            Base64Index[Base64Chars.at(i)] = (UINT8)i;
        }

        InitializeClock();
        InitCrc32Table();
        InitWinsock();
        SystemClock.reset();

        RunSystemService();
    } while (false);
    return result;
}

extern void HttpServiceMain();
extern void MediaRouterMain();
extern void StateServiceMain();

//extern void QMsgServiceMain();

extern void TestXmlParser();

void ServiceMain()
{
    //TPM.test();
    //TestXmlParser();
    StateServiceMain();
    //HttpServiceMain();
    //QMsgServiceMain();
    //MediaRouterMain();
}

int main()
{
    EnableLargePages();
    InitPlatform();
    (void)getchar();
}

void InitLsaString(PLSA_UNICODE_STRING LsaString, LPWSTR String)
{
    DWORD StringLength;

    if (String == NULL) {
        LsaString->Buffer = NULL;
        LsaString->Length = 0;
        LsaString->MaximumLength = 0;
        return;
    }

    StringLength = (DWORD)wcslen(String);
    LsaString->Buffer = String;
    LsaString->Length = (USHORT)StringLength * sizeof(WCHAR);
    LsaString->MaximumLength = (USHORT)(StringLength + 1) * sizeof(WCHAR);
}

NTSTATUS OpenPolicy(LPWSTR ServerName, DWORD DesiredAccess, PLSA_HANDLE PolicyHandle)
{
    LSA_OBJECT_ATTRIBUTES ObjectAttributes;
    LSA_UNICODE_STRING ServerString;
    PLSA_UNICODE_STRING Server = NULL;

    // 
    // Always initialize the object attributes to all zeroes.
    // 
    ZeroMemory(&ObjectAttributes, sizeof(ObjectAttributes));

    if (ServerName != NULL) {
        // 
        // Make a LSA_UNICODE_STRING out of the LPWSTR passed in
        // 
        InitLsaString(&ServerString, ServerName);
        Server = &ServerString;
    }

    // 
    // Attempt to open the policy.
    // 
    return LsaOpenPolicy(
        Server,
        &ObjectAttributes,
        DesiredAccess,
        PolicyHandle
    );
}

NTSTATUS SetPrivilegeOnAccount(LSA_HANDLE PolicyHandle, PSID AccountSid, LPWSTR PrivilegeName, BOOL bEnable)
{
    LSA_UNICODE_STRING PrivilegeString;

    // 
    // Create a LSA_UNICODE_STRING for the privilege name.
    // 
    InitLsaString(&PrivilegeString, PrivilegeName);

    // 
    // grant or revoke the privilege, accordingly
    // 
    if (bEnable) {
        return LsaAddAccountRights(
            PolicyHandle,       // open policy handle
            AccountSid,         // target SID
            &PrivilegeString,   // privileges
            1                   // privilege count
        );
    }
    else {
        return LsaRemoveAccountRights(
            PolicyHandle,       // open policy handle
            AccountSid,         // target SID
            FALSE,              // do not disable all rights
            &PrivilegeString,   // privileges
            1                   // privilege count
        );
    }
}

// Code from https://stackoverflow.com/questions/42354504/enable-large-pages-in-windows-programmatically
bool EnableLargePages()
{
    LargePageSize = LARGE_PAGE_SIZE;

    HANDLE hToken = NULL;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
    {
        printf( "OpenProcessToken failed. GetLastError returned: %d\n", GetLastError());
        return false;
    }

    DWORD dwBufferSize = 0;

    // Probe the buffer size reqired for PTOKEN_USER structure
    if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) && (GetLastError() != ERROR_INSUFFICIENT_BUFFER))
    {
        printf( "GetTokenInformation failed. GetLastError returned: %d\n", GetLastError());

        // Cleanup
        CloseHandle(hToken);
        hToken = NULL;

        return false;
    }

    PTOKEN_USER pTokenUser = (PTOKEN_USER)malloc(dwBufferSize);

    // Retrieve the token information in a TOKEN_USER structure
    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwBufferSize, &dwBufferSize))
    {
        printf("GetTokenInformation failed. GetLastError returned: %d\n", GetLastError());

        // Cleanup
        CloseHandle(hToken);
        hToken = NULL;

        return false;
    }

    // Print SID string
    LPWSTR strsid;
    ConvertSidToStringSid(pTokenUser->User.Sid, &strsid);

    // Cleanup
    CloseHandle(hToken);
    hToken = NULL;

    NTSTATUS status;
    LSA_HANDLE policyHandle;

    if (status = OpenPolicy(NULL, POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES, &policyHandle))
    {
        printf("OpenPolicy %d", status);
    }

    // Add new privelege to the account
    if (status = SetPrivilegeOnAccount(policyHandle, pTokenUser->User.Sid, (LPWSTR)SE_LOCK_MEMORY_NAME, TRUE))
    {
        printf("OpenPSetPrivilegeOnAccountolicy %d", status);
    }

    // Enable this priveledge for the current process
    hToken = NULL;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, &hToken))
    {
        printf("OpenProcessToken #2 failed. GetLastError returned: %d\n", GetLastError());
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!LookupPrivilegeValue(NULL, SE_LOCK_MEMORY_NAME, &tp.Privileges[0].Luid))
    {
        printf("LookupPrivilegeValue failed. GetLastError returned: %d\n", GetLastError());
        return false;
    }

    BOOL result = AdjustTokenPrivileges(hToken, FALSE, &tp, 0, (PTOKEN_PRIVILEGES)NULL, 0);
    DWORD error = GetLastError();

    if (!result || (error != ERROR_SUCCESS))
    {
        printf("AdjustTokenPrivileges failed. GetLastError returned: %d\n", error);
        return false;
    }

    // Cleanup
    CloseHandle(hToken);
    hToken = NULL;

    LargePageSize = (UINT32)GetLargePageMinimum();
    ASSERT(IS_ALIGNED(LargePageSize, LARGE_PAGE_SIZE));

    auto largeBuffer = VirtualAlloc(NULL, LargePageSize, MEM_RESERVE | MEM_COMMIT | MEM_LARGE_PAGES, PAGE_READWRITE);
    if (!largeBuffer)
    {
        printf("VirtualAlloc failed, error 0x%x", GetLastError());
        return false;
    }

    result = VirtualFree(largeBuffer, 0, MEM_RELEASE);
    if (!result)
    {
        printf("VirtualFree failed, error=%d\n", GetLastError());
        return false;
    }

    return true;
}
