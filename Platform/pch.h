#pragma once
#pragma warning(disable  : 4577 4530)
#include <sdkddkver.h>

#define SECURITY_WIN32
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
#define UMDF_USING_NTSTATUS
#define _NTDEF_

#include <windows.h>
#include <sddl.h>
#include <winternl.h>
typedef NTSTATUS* PNTSTATUS;

#include <ntstatus.h>
#include <NTSecAPI.h>
#include <assert.h>
#include <memory>
#include <time.h>
#include <wininet.h>
#include <WinSock2.h>
#include <MSWSock.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <intrin.h>