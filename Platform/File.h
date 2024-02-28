
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

struct IOBUF
{
    IOBUF* next;
    BYTESTREAM dataStream;
    UINT64 offset = -1;
    IOCALLBACK ioState = IO_FILE_READ;

    void init(PUINT8 data, UINT32 size)
    {
        NEW(dataStream, data, size);
    }
    void reset(UINT64 newOffset)
    {
        dataStream.clear();
        offset = newOffset;
        next = nullptr;
    }

    UINT64 getOffset(const BUFFER& buf)
    {
        ASSERT(offset != -1);
        ASSERT(buf.data() <= dataStream.end());

        return offset + (buf.data() - dataStream.address());
    }
};
using PIOBUF = IOBUF*;

struct IOBUF_POOL
{
    UINT32 bufSize;

    PIOBUF freeBufs = nullptr;

    IOBUF_POOL(UINT32 bufSize) : bufSize(bufSize) {}

    NTSTATUS addBufs()
    {
        auto allocSize = max(bufSize, LARGE_PAGE_SIZE);
        auto count = allocSize / bufSize;
        auto dataMemoy = PUINT8(MemAllocLarge(allocSize));
        ASSERT(dataMemoy);

        auto&& ioBufs = ServiceBufAlloc<IOBUF>(count);
        //auto bufMemory = (PIOBUF)StackAlloc<SERVICE_STACK>(sizeof(IOBUF) * count);
        for (UINT32 i = 0; i < count; i++)
        {
            auto&& newBuf = ioBufs[i];
            newBuf.init(dataMemoy + (i * bufSize), bufSize);

            newBuf.next = freeBufs;
            freeBufs = &newBuf;
        }
        return STATUS_SUCCESS;
    }

    IOBUF& alloc(UINT64 offset)
    {
        if (freeBufs == nullptr)
        {
            addBufs();
        }
        auto&& newBuf = *freeBufs;
        freeBufs = newBuf.next;

        newBuf.reset(offset);
        return newBuf;
    }

    void free(IOBUF& buf)
    {
        buf.next = freeBufs;
        freeBufs = &buf;
    }

    NTSTATUS init()
    {
        return addBufs();
    }
};

struct IOBUF_MANAGER
{
    DATASTREAM<IOBUF_POOL, SERVICE_STACK, 8> bufPoolStream;
    UINT32 baseBufSize = 4096;
    UINT32 poolCount = 6;

    IOBUF_MANAGER(UINT32 size, UINT32 count) : baseBufSize(size), poolCount(count) {}

    void init()
    {
        bufPoolStream.reserve(8);
        UINT32 initBufCount = 256;

        for (UINT32 i = 0; i < poolCount; i++)
        {
            auto bufSize = baseBufSize << (i * 2);
            auto&& bufPool = bufPoolStream.append(bufSize);
            bufPool.init();
        }
    }

    IOBUF_POOL& getBufPool(UINT32 size)
    {
        size = max(size, baseBufSize) / baseBufSize;
        auto poolIndex = size / 4;
        
        poolIndex = min(bufPoolStream.count() - 1, poolIndex);

        return bufPoolStream.at(poolIndex);
    }

    IOBUF& alloc(UINT32 size, UINT64 offset)
    {
        return getBufPool(size).alloc(offset);
    }

    void free(IOBUF& buf)
    {
        auto size = buf.dataStream.size();
        getBufPool(size).free(buf);
    }
};

struct FILE_OPS
{
    HANDLE CurrentDirectory;

    void Init()
    {
        auto&& nameStream = ByteStream(1024);
        nameStream.writeString("\\DosDevices\\");
        auto size = GetCurrentDirectoryA(nameStream.spaceLeft(), (LPSTR)nameStream.end());
        nameStream.expand(size);

        OBJECT_ATTRIBUTES attrs;
        InitializeObjectAttributes(&attrs, nameStream.toBuffer().toUnicodeString(), OBJ_CASE_INSENSITIVE, nullptr, nullptr);

        IO_STATUS_BLOCK ioStatus;
        auto status = NtCreateFile(&CurrentDirectory, FILE_LIST_DIRECTORY, &attrs, &ioStatus, nullptr, 0, FILE_SHARE_READ, FILE_OPEN, FILE_DIRECTORY_FILE, nullptr, 0);
        
        ASSERT(NT_SUCCESS(status));
    }

    BUFFER downloadDirectory;

    BUFFER CreateTempFilename(UINT64 index)
    {
        auto byteStream = ByteStream(128);
        SYSTEMTIME currentTime;
        GetSystemTime(&currentTime);
        return byteStream.writeMany(downloadDirectory, SystemClock.elapsedTime(), ".", index);
    }

    NTSTATUS _open(BUFFER filename, HANDLE& fileHandle, DWORD flags = 0, PVOID context = nullptr)
    {
        OBJECT_ATTRIBUTES attrs;
        InitializeObjectAttributes(&attrs, filename.toUnicodeString(), OBJ_CASE_INSENSITIVE, CurrentDirectory, nullptr);
        IO_STATUS_BLOCK ioStatus;
        auto status = NtCreateFile(&fileHandle, GENERIC_ALL, &attrs, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | flags, nullptr, 0);
        return status;
    }

    NTSTATUS _create(BUFFER filename, HANDLE& fileHandle, DWORD flags = 0, PVOID context = nullptr)
    {
        OBJECT_ATTRIBUTES attrs;
        InitializeObjectAttributes(&attrs, filename.toUnicodeString(), OBJ_CASE_INSENSITIVE, CurrentDirectory, nullptr);
        IO_STATUS_BLOCK ioStatus;
        auto status = NtCreateFile(&fileHandle, GENERIC_ALL, &attrs, &ioStatus, nullptr, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OVERWRITE_IF, FILE_FLAG_OVERLAPPED | flags, nullptr, 0);
        return status;
    }

    NTSTATUS Open(BUFFER filename, HANDLE& fileHandle, UINT64& fileSize, DWORD flags = 0, PVOID context = nullptr)
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            auto&& scheduler = GetCurrentScheduler();

            fileHandle = CreateFileA(filename.toString(), GENERIC_ALL, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED | flags, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                status = STATUS_NO_SUCH_FILE;
                break;
            }

            auto result = scheduler.registerHandle(fileHandle, context);
            if (!NT_SUCCESS(result))
                break;

            LARGE_INTEGER largeInteger;
            if (GetFileSizeEx(fileHandle, &largeInteger) == 0)
            {
                status = STATUS_FILE_INVALID;
                break;
            }
            fileSize = largeInteger.QuadPart;

            status = STATUS_SUCCESS;
        } while (false);
        ASSERT(NT_SUCCESS(status));
        return status;
    }

    NTSTATUS OpenNoCache(BUFFER filename, HANDLE& fileHandle, UINT64& fileSize, PVOID context = nullptr)
    {
        return Open(filename, fileHandle, fileSize, FILE_FLAG_NO_BUFFERING, context);
    }

    NTSTATUS Create(BUFFER filename, HANDLE& fileHandle, UINT64 fileSize = 0, DWORD flags = 0, PVOID context = nullptr)
    {
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            auto&& scheduler = GetCurrentScheduler();

            fileHandle = CreateFileA(filename.toString(), GENERIC_ALL, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_FLAG_OVERLAPPED | flags, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                status = STATUS_NO_SUCH_FILE;
                break;
            }

            auto result = scheduler.registerHandle(fileHandle, context);
            if (!NT_SUCCESS(result))
                break;

            if (fileSize > 0)
            {
                auto ret = SetFilePointerEx(fileHandle, *(LARGE_INTEGER*)&fileSize, nullptr, FILE_BEGIN);
                if (ret == 0)
                    break;

                ret = SetEndOfFile(fileHandle);
                if (ret == 0)
                    break;
            }
            status = STATUS_SUCCESS;
        } while (false);

        return status;
    }

    NTSTATUS CreateNoCache(BUFFER filename, HANDLE& fileHandle, UINT64 fileSize = 0, PVOID context = nullptr)
    {
        return Create(filename, fileHandle, fileSize, FILE_FLAG_NO_BUFFERING|FILE_FLAG_WRITE_THROUGH, context);
    }

    UINT64 GetFileTime(HANDLE fileHandle)
    {
        UINT64 fileTime;
        auto result = ::GetFileTime(fileHandle, (LPFILETIME) &fileTime, nullptr, nullptr);
        ASSERT(result != 0);
        return fileTime;
    }

    NTSTATUS Read(HANDLE fileHandle, UINT64 fileOffset, BYTESTREAM& dataStream, IOCALLBACK& ioState)
    {
        auto&& overlap = *ioState.start();

        if (fileOffset)
        {
            overlap.Offset = UINT32(fileOffset);
            overlap.OffsetHigh = UINT32(fileOffset > 32);
        }

        auto result = ::ReadFile(fileHandle, dataStream.end(), dataStream.spaceLeft(), nullptr, &overlap);
        if (result == 0 && GetLastError() != ERROR_IO_PENDING)
        {
            return STATUS_FILE_INVALID;
        }
        return STATUS_SUCCESS;
    }

    //NTSTATUS Read(HANDLE fileHandle, UINT64 fileOffset, BYTESTREAM& dataStream, LPOVERLAPPED overlap)
    //{
    //    if (fileOffset > 0)
    //    {
    //        auto&& largeInteger = *(LARGE_INTEGER*)&fileOffset;
    //        overlap->Offset = largeInteger.LowPart;
    //        overlap->OffsetHigh = largeInteger.HighPart;
    //    }

    //    auto result = ::ReadFile(fileHandle, dataStream.end(), dataStream.spaceLeft(), nullptr, overlap);
    //    if (result == 0 && GetLastError() != ERROR_IO_PENDING)
    //    {
    //        return STATUS_FILE_INVALID;
    //    }
    //    return STATUS_SUCCESS;
    //}

    NTSTATUS Read(HANDLE fileHandle, BYTESTREAM& dataStream, IOCALLBACK& ioState)
    {
        return Read(fileHandle, 0, dataStream, ioState);
    }

    NTSTATUS Write(HANDLE fileHandle, UINT64 fileOffset, BUFFER data, LPOVERLAPPED overlap)
    {
        if (fileOffset > 0)
        {
            auto&& largeInteger = *(LARGE_INTEGER*)&fileOffset;
            overlap->Offset = largeInteger.LowPart;
            overlap->OffsetHigh = largeInteger.HighPart;
        }

        auto result = ::WriteFile(fileHandle, data.data(), data.length(), nullptr, overlap);
        if (result == 0 && GetLastError() != ERROR_IO_PENDING)
        {
            return STATUS_FILE_INVALID;
        }
        return STATUS_SUCCESS;
    }

    NTSTATUS Write(HANDLE fileHandle, IOBUF& iobuf)
    {
        ASSERT(iobuf.dataStream.spaceLeft() < 4096);
        return Write(fileHandle, iobuf.offset, iobuf.dataStream.toMaxBuffer(), iobuf.ioState.start());
    }

    void Close(HANDLE fileHandle)
    {
        CloseHandle(fileHandle);
    }

    template <typename STACK>
    BUFFER ReadFile(USTRING filename)
    {
        BUFFER result;
        auto status = STATUS_SUCCESS;
        HANDLE fileHandle = nullptr;
        do
        {
            fileHandle = CreateFileA(filename.toString(), GENERIC_ALL, 0, nullptr, OPEN_EXISTING, 0, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                status = STATUS_NO_SUCH_FILE;
                break;
            }

            UINT32 fileSize;
            LARGE_INTEGER fileSizeValue;
            if (GetFileSizeEx(fileHandle, &fileSizeValue) == 0)
            {
                status = STATUS_FILE_INVALID;
                break;
            }

            fileSize = (UINT32)fileSizeValue.QuadPart;
            
            auto&& buffer = (PUINT8)StackAlloc<STACK>(fileSize);
            DWORD bytesRead;

            if (::ReadFile(fileHandle, buffer, fileSize, &bytesRead, nullptr) == 0)
            {
                status = STATUS_FILE_INVALID;
                break;
            }
            result = { buffer, fileSize };
        } while (false);

        if (fileHandle) CloseHandle(fileHandle);

        return result;
    }

    void WriteFile(BUFFER filename, BUFFER fileData)
    {
        do
        {
            auto fileHandle = CreateFileA(filename.toString(), GENERIC_ALL, 0, nullptr, CREATE_ALWAYS, 0, nullptr);
            if (fileHandle == INVALID_HANDLE_VALUE)
            {
                DBGBREAK();
                break;
            }

            DWORD bytesWritten;
            ::WriteFile(fileHandle, fileData.data(), fileData.length(), &bytesWritten, nullptr);

            CloseHandle(fileHandle);
        } while (false);
    }

    NTSTATUS CreateDirectory(BUFFER directoryName)
    {
        auto result = ::CreateDirectoryA(directoryName.toString(), nullptr);
        return result ? STATUS_SUCCESS : STATUS_IO_DEVICE_ERROR;
    }

    NTSTATUS DeleteFile(BUFFER filename)
    {
        auto ret = DeleteFileA(filename.toString());
        return ret ? STATUS_SUCCESS : NTSTATUS_FROM_WIN32(GetLastError());
    }
};

inline FILE_OPS File;

struct FILE_STREAM
{
    constexpr static UINT32 FILE_STREAM_BUFSIZE = 32 * 1024 * 1024;
    constexpr static UINT32 PAGESIZE = 0x1000;
    constexpr static UINT32 PAGESIZE_MASK = PAGESIZE - 1;

    static UINT32 ROUNDUP(UINT32 val) { return (val + PAGESIZE_MASK) & ~PAGESIZE_MASK; }
    static UINT32 ROUNDDN(UINT32 val) { return val & ~PAGESIZE_MASK; }

    static UINT64 ROUNDUP(UINT64 val) { return (val + PAGESIZE_MASK) & ~PAGESIZE_MASK; }
    static UINT64 ROUNDDN(UINT64 val) { return val & ~PAGESIZE_MASK; }

    HANDLE fileHandle;
    UINT64 fileSize;

    UINT32 bufSize;
    PUINT8 buffer;

    BUFFER readBuffer;
    UINT64 fileOffset;

    IOCALLBACK ioCallback{ IO_FILE_READ };

    NTSTATUS open(USTRING filename, UINT32 bufSizeArg = FILE_STREAM_BUFSIZE)
    {
        bufSize = bufSizeArg;
        auto status = STATUS_UNSUCCESSFUL;
        do
        {
            File.Open(filename, fileHandle, fileSize);
            bufSize = min(bufSize, ROUNDUP((UINT32)fileSize));

            buffer = (PUINT8)VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if (buffer == nullptr)
            {
                status = STATUS_NO_MEMORY;
                break;
            }

            status = STATUS_SUCCESS;
        } while (false);
        ASSERT(NT_SUCCESS(status));
        return status;
    }

    OVERLAPPED& setOverlap(UINT64 offset)
    {
        offset = ROUNDDN(offset);
        ZeroMemory(&ioCallback.overlap, sizeof(OVERLAPPED));
        ioCallback.overlap.Offset = UINT32(offset);
        ioCallback.overlap.OffsetHigh = UINT32(offset >> 32);
        return ioCallback.overlap;
    }

    bool atEOF()
    {
        return fileOffset >= fileSize;
    }

    STASK readCallback;
    NTSTATUS read(UINT32 bytesToRead, TASK_HANDLER callback, PVOID context, auto&& ... args)
    {
        if (atEOF())
        {
            DBGBREAK();
            return STATUS_END_OF_FILE;
        }

        ASSERT(readCallback.status != TASK_STATUS::SCHEDULED);
        NEW(readCallback, callback, context, args ...);

        auto&& scheduler = GetCurrentScheduler();
        if (bytesToRead <= readBuffer.length())
        {
            scheduler.updateTask(readCallback, STATUS_SUCCESS, readBuffer.readBytes(bytesToRead));
            scheduler.invokeTask(readCallback);
        }
        else
        {
            fileOffset -= readBuffer.length();
            auto bytesAvailable = fileSize - fileOffset;

            if (bytesToRead > bufSize)
            {
                bufSize = ROUNDUP(bytesToRead);
                VirtualFree(buffer, 0, MEM_RELEASE);
                buffer = (PUINT8)VirtualAlloc(nullptr, bufSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                if (buffer == nullptr)
                {
                    return STATUS_NO_MEMORY;
                }
            }

            ioCallback.task = scheduler.createTask([](PVOID context, NTSTATUS status, STASK_ARGV argv)
                {
                    auto&& fileStream = *(FILE_STREAM<SCHEDULER> *)context;
                    ASSERT(NT_SUCCESS(status));

                    auto bytesRead = argv.read<DWORD>(1);

                    fileStream.readBuffer = BUFFER(fileStream.buffer, fileStream.fileOffset.LowPart & PAGESIZE_MASK, bytesRead);
                    fileStream.fileOffset.QuadPart += bytesRead;

                    auto bytesToRead = argv.read<UINT32>(0);
                    auto&& data = fileStream.readBuffer.readBytes(bytesToRead);

                    auto&& callback = fileStream.readCallback;
                    GetCurrentScheduler().updateTask(callback, STATUS_SUCCESS, data);
                    GetCurrentScheduler().invokeTask(callback);
                }, this, bytesToRead);

            auto&& overlap = setOverlap(fileOffset);
            auto result = ReadFile(fileHandle, buffer, bufSize, nullptr, &overlap);
            ASSERT(result == 0 && GetLastError() == ERROR_IO_PENDING);
        }

        return STATUS_SUCCESS;
    }

    UINT64 getFileOffset(PUINT8 address)
    {
        return fileOffset + (address - buffer);
    }

    UINT64 getFileOffset()
    {
        return fileOffset - readBuffer.length();
    }

    void seek(UINT64 newFileOffset)
    {
        fileOffset = newFileOffset;
        readBuffer = NULL_BUFFER;
    }

    void close()
    {
        CloseHandle(fileHandle);
        fileHandle = INVALID_HANDLE_VALUE;
        VirtualFree(buffer, 0, MEM_RELEASE);
        buffer = nullptr;
    }
};
