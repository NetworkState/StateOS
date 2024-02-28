
// Copyright (C) 2024 Network State. (networkstate.com)
// All rights reserved.

#pragma once

constexpr UINT32 PRIORITY_COUNT = 1;

constexpr UINT32 MAX_SCHEDULER_PRIORITY = 0;
constexpr UINT32 MIN_SCHEDULER_PRIORITY = 0;

using TASK_ID = UINT32;
constexpr UINT32 INVALID_TASKID = 0xFFFFFFFF;

#define MAKE_TASKID(priority, id_) (((priority & 0xFF) << 16) | (id_ & 0xFFFF))
#define GET_QUEUE_PRIORITY(taskid_) ((taskid_ & 0xFF0000) >> 16)
#define GET_QUEUE_INDEX(taskid_) (taskid_ & 0xFFFF)

#define MAX_PROCESSOR_COUNT	64

constexpr UINT8 ARG_NUMBERED = 0;

struct SERVICE_STACK;
struct SESSION_STACK;

struct STASK_ARGV
{
    BUFFER paramData;

    template <typename T>
    T read(UINT8 pos)
    {
        UINT8 index = 0;
        T value = T();
        paramData.rewind();
        while (paramData)
        {
            auto type = paramData.readByte();
            auto length = paramData.readByte();
            auto data = paramData.readBytes(length);
            if (type == ARG_NUMBERED && index++ == pos)
            {
                ASSERT(length <= sizeof(T));
                data.copyTo((PUINT8)&value, min(length, sizeof(T)));
                break;
            }
        }
        return value;
    }

    STASK_ARGV(BUFFER dataArg) : paramData(dataArg) {}
};

struct STASK_PARAM
{
    LOCAL_STREAM<64> param;

    template <typename T>
    void writeParam(UINT8 pos, T&& arg)
    {
        param.writeByte(pos);
        param.writeByte(sizeof(arg));
        param.writeBytes((PUINT8)&arg, sizeof(arg));
    }

    void addParam() {}

    template <typename T, typename ... ARGS>
    void addParam(T&& arg, ARGS&& ... args)
    {
        writeParam(ARG_NUMBERED, arg);
        addParam(args ...);
    }

    void clear()
    {
        param.clear();
    }

    void copy(const STASK_PARAM& other)
    {
        param.clear().writeBytes(other.param.toBuffer());
    }

    STASK_ARGV getArgv() {
        return STASK_ARGV(param.toBuffer());
    }

    template <typename ... ARGS>
    STASK_PARAM(ARGS&& ... args)
    {
        addParam(args ...);
    }
};

using TASK_HANDLER = void(*)(PVOID context, NTSTATUS result, STASK_ARGV argv);

using SYSTASK_HANDLER = void(*)(STASK_ARGV argv);

enum class TASK_STATUS : UINT8
{
    STATUS_UNKNOWN,
    STATUS_SCHEDULED,
    STATUS_READY,
    STATUS_RUNNING,
    STATUS_COMPLETE,
};
using enum TASK_STATUS;

struct STASK
{
    STASK_PARAM paramStream;
    NTSTATUS result;

    TASK_STATUS status;
    UINT8 paramStreamInitMark;
    TASK_HANDLER handlerFunction;
    PVOID handlerContext;

    SESSION_STACK* sessionStack = nullptr;

    template <typename ... ARGS>
    STASK(TASK_HANDLER handlerFunction, PVOID handlerContext, ARGS&& ... params) : 
        handlerFunction(handlerFunction), handlerContext(handlerContext), paramStream(params ...)
    {
        result = STATUS_SUCCESS;
        status = STATUS_SCHEDULED;
        paramStreamInitMark = (UINT8)paramStream.param.mark();
    }

    template <typename ... ARGS>
    STASK(SESSION_STACK& sessionStack, TASK_HANDLER handlerFunction, PVOID handlerContext, ARGS&& ... params) :
        handlerFunction(handlerFunction), handlerContext(handlerContext), sessionStack(&sessionStack), paramStream(params ...)
    {
        result = STATUS_SUCCESS;
        status = STATUS_SCHEDULED;
        paramStreamInitMark = (UINT8)paramStream.param.mark();
    }

    STASK() : handlerFunction(nullptr), result(STATUS_SUCCESS), handlerContext(nullptr), status(STATUS_UNKNOWN)
    {
        paramStreamInitMark = (UINT8)paramStream.param.mark();
    }

    void reset()
    {
        result = STATUS_SUCCESS;
        status = STATUS_SCHEDULED;
        paramStream.param.restore(paramStreamInitMark);
    }

    void clear()
    {
        paramStream.clear();
        paramStreamInitMark = 0;
        handlerFunction = nullptr;
        status = STATUS_UNKNOWN;
    }

    STASK(const STASK& other)
    {
        paramStream.copy(other.paramStream);
        result = other.result;
        status = other.status;
        paramStreamInitMark = other.paramStreamInitMark;
        handlerFunction = other.handlerFunction;
        handlerContext = other.handlerContext;
    }

    explicit operator bool() { return handlerFunction != nullptr; }
};

enum class IO_TYPE
{
    IO_SOCK_RECV,
    IO_SOCK_SEND,
    IO_SOCK_CTRL,
    IO_FILE_READ,
    IO_FILE_WRITE,
};
using enum IO_TYPE;

struct IOCALLBACK
{
    IO_TYPE type;
    OVERLAPPED overlap;
    STASK task;

    IOCALLBACK(IO_TYPE type)  : type(type)
    {
        ZeroMemory(&overlap, sizeof(overlap));
    }

    LPOVERLAPPED start()
    {
        ZeroMemory(&overlap, sizeof(overlap));
        task.reset();
        return &overlap;
    }

    void clear()
    {
        ZeroMemory(&overlap, sizeof(overlap));
        task.clear();
    }
};

struct TIMER_TASK
{
    STASK task;
    UINT32 targetTime;
};

struct QUEUE_HEAD
{
    LONG read;
    LONG write;
};

inline static void ResetCurrentStacks()
{
    SCHEDULER_STACK::ResetCurrent();
    SESSION_STACK::ResetCurrent();
    SERVICE_STACK::ResetCurrent();
}

constexpr UINT32 BASE_PRIORITY = 0;
constexpr UINT32 MAX_OVERLAP_ENTRIES = 32;
constexpr UINT32 MAX_TIMERS = 4;

constexpr ULONG_PTR SCHED_CHECK_QUEUE = 0xFFFFFFF0;
constexpr ULONG_PTR SCHED_TERMINATE = 0xFFFFFFF1;

template <UINT32 QUEUE_SIZE = 128>
struct SCHEDULER_INFO
{
    constexpr static UINT32 QUEUE_MASK = QUEUE_SIZE - 1;
    struct TASK_QUEUE
    {
        STASK taskQueue[QUEUE_SIZE];
    };

    SCHEDULER_STACK schedulerStack;

    UINT32 runLock = 0;
    DWORD threadId;

    TIMER_TASK timerTable[MAX_TIMERS];
    HANDLE completionPort;

    SESSION_STACK* sessionStack = nullptr;
    SERVICE_STACK& serviceStack;
    
    QUEUE_HEAD queueHead[PRIORITY_COUNT];
    TASK_QUEUE taskQueues[PRIORITY_COUNT];

    SCHEDULER_INFO(SERVICE_STACK& serviceStackArg, SESSION_STACK *sessionStack = nullptr) : serviceStack(serviceStackArg), sessionStack(sessionStack)
    {
    };

    void init()
    {
        schedulerStack.init(LARGE_PAGE_SIZE, 32 * 1024 * 1024);

        ZeroMemory(queueHead, sizeof(queueHead));
        ZeroMemory(taskQueues, sizeof(taskQueues));

        for (UINT32 i = 0; i < PRIORITY_COUNT; i++)
        {
            queueHead[i].read = queueHead[i].read = 0;
        }

        for (UINT32 i = 0; i < PRIORITY_COUNT; i++)
        {
            auto& taskQueue = taskQueues[i];
            for (UINT32 j = 0; j < QUEUE_SIZE; j++)
            {
                new (&taskQueue.taskQueue[j]) STASK();
            }
        }
        completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, nullptr, NULL, 1);

        CreateThread(NULL, 0, ThreadEntry, this, 0, &threadId);
    }

    NTSTATUS registerHandle(HANDLE ioHandle, PVOID contextArg)
    {
        auto result = CreateIoCompletionPort(ioHandle, completionPort, (ULONG_PTR) contextArg, 0);
        return result == completionPort ? STATUS_SUCCESS: STATUS_UNSUCCESSFUL;
    }

    INT32 startTimer(UINT32 dueTime, STASK callback)
    {
        ASSERT(isRunning());
        INT32 slotFound = -1;
        for (UINT32 i = 0; i < MAX_TIMERS; i++)
        {
            auto&& timer = timerTable[i];
            if (timer.targetTime == 0)
            {
                timer.targetTime = SystemClock.elapsedTime() + dueTime;
                timer.task = callback;
                slotFound = i;
                break;
            }
        }

        ASSERT(slotFound >= 0);
        PostQueuedCompletionStatus(completionPort, 0, SCHED_CHECK_QUEUE, nullptr); // let the scheduler update timeout
        return slotFound;
    }

    void stopTimer(INT32 handle)
    {
        ASSERT(handle >= 0 && handle < MAX_TIMERS);
        auto&& timer = timerTable[handle];

        timer.targetTime = 0;
    }

    void resetTimer(INT32 handle, UINT32 newTimeout)
    {
        ASSERT(handle >= 0 && handle < MAX_TIMERS);
        timerTable[hande].targetTime = SystemClock.elapsedTime() + newTimeout;
    }

    auto findReadyTask(INT32 lowPriority)
    {
        STASK* taskFound = nullptr;
        for (INT32 i = MAX_SCHEDULER_PRIORITY; i >= lowPriority; i--)
        {
            auto& currentQueue = taskQueues[i];
            auto& currentIndex = queueHead[i];

            while (currentIndex.read != currentIndex.write)
            {
                auto read = currentIndex.read;
                auto& task = currentQueue.taskQueue[read];
                if (task.status == STATUS_RUNNING)
                {
                    task.status = STATUS_COMPLETE;
                    currentIndex.read = (read + 1) & QUEUE_MASK;
                }
                else if (task.status == STATUS_READY)
                {
                    task.status = STATUS_RUNNING;
                    if (task.handlerFunction)
                    {
                        taskFound = &task;
                        break;
                    }
                    else DBGBREAK();
                }
                else break;
            }

            if (taskFound)
                break;

            if (currentIndex.read != currentIndex.write)
                break;
        }

        return taskFound;
    }

    void invokeTask(STASK& task)
    {
        ASSERT(task.status == STATUS_READY || task.status == STATUS_RUNNING);
        auto argv = task.paramStream.getArgv();
        SESSION_STACK::CurrentStack =  task.sessionStack ? task.sessionStack : sessionStack;
        task.handlerFunction(task.handlerContext, task.result, argv);
    }

    void runReadyTasks(INT32 lowPriority)
    {
        while (auto nextTask = findReadyTask(lowPriority))
        {
            invokeTask(*nextTask);
        }
    }

    bool isRunning()
    {
        return SCHEDULER_STACK::CurrentStack == &schedulerStack;
    }

    TASK_QUEUE& getTaskQueue(TASK_ID taskId)
    {
        auto priority = GET_QUEUE_PRIORITY(taskId);
        return taskQueues[priority];
    }

    STASK& getTask(TASK_ID taskId)
    {
        auto&& taskStack = getTaskQueue(taskId);
        return taskStack.taskQueue[GET_QUEUE_INDEX(taskId)];
    }

    template <typename ... ARGS>
    TASK_ID queueTaskInternal(ARGS&& ... args)
    {
        volatile auto& taskQueue = taskQueues[0];
        volatile auto& header = queueHead[0];

        UINT32 taskId;
        while (true)
        {
            auto currentIndex = header.write;
            auto nextIndex = (currentIndex + 1) & QUEUE_MASK;

            ASSERT((LONG)nextIndex != header.read);

            if (InterlockedCompareExchange(&header.write, nextIndex, currentIndex) == currentIndex)
            {
                auto& newTask = taskQueue.taskQueue[currentIndex];
                new ((PUINT8) &newTask) STASK(args ...);
                newTask.status = STATUS_SCHEDULED;
                taskId = MAKE_TASKID(0, currentIndex);
                break;
            }
        }

        return taskId;
    }

    template <typename ... ARGS>
    STASK createTask(TASK_HANDLER handler, PVOID context, ARGS&& ... args)
    {
        STASK newTask{ handler, context, args ... };
        return newTask;
    }

    template <typename ... ARGS>
    STASK createTask(SESSION_STACK& sessionStack, TASK_HANDLER handler, PVOID context, ARGS&& ... args)
    {
        STASK newTask{ &sessionStack, handler, context, args ... };
        return newTask;
    }

    template <typename ... ARGS>
    TASK_ID queueTask(TASK_HANDLER handler, PVOID handlerContext, ARGS&& ... args)
    {
        return queueTaskInternal(handler, handlerContext, args ...);
    }

    template <typename ... ARGS>
    TASK_ID queueTask(SESSION_STACK& sessionStack, TASK_HANDLER handler, PVOID handlerContext, ARGS&& ... args)
    {
        return queueTaskInternal(sessionStack, handler, handlerContext, args ...);
    }

    template <typename ... ARGS>
    VOID updateTask(STASK& task, NTSTATUS result = STATUS_SUCCESS, ARGS&& ... args)
    {	
        ASSERT(task.status == STATUS_SCHEDULED);
        task.result = result;

        task.paramStream.addParam(args ...);
        task.status = STATUS_READY;
    }

    template <typename ... ARGS>
    VOID updateTask(TASK_ID taskId, NTSTATUS result = STATUS_SUCCESS, ARGS&& ... args)
    {
        auto& task = getTask(taskId);
        updateTask(task, result, args...);
        PostQueuedCompletionStatus(completionPort, 0, SCHED_CHECK_QUEUE, nullptr);
    }

    template <typename ... ARGS>
    void runTask(TASK_HANDLER handler, PVOID context, ARGS&& ... args)
    {
        auto taskId = queueTask(handler, context, args ...);
        updateTask(taskId, STATUS_SUCCESS);
    }

    template <typename ... ARGS>
    void runTask(SESSION_STACK& sessionStack, TASK_HANDLER handler, PVOID context, ARGS&& ... args)
    {
        auto taskId = queueTask(sessionStack, handler, context, args ...);
        updateTask(taskId, STATUS_SUCCESS);
    }

    template <typename ... ARGS>
    void runTask(STASK& other, NTSTATUS result = STATUS_SUCCESS, ARGS&& ... args)
    {
        auto taskId = queueTaskInternal(other);
        updateTask(taskId, result, args ...);
    }

    UINT32 getWaitTimeout()
    {
        INT32 delay = INT32_MAX;
        auto currentTime = (UINT32)SystemClock.elapsedTime();

        for (UINT32 i = 0; i < MAX_TIMERS; i++)
        {
            auto& targetTime = timerTable[i].targetTime;
            if (targetTime != 0 && targetTime > currentTime)
            {
                DBGBREAK();
                delay = __min((INT32)(targetTime - currentTime), delay);
            }
        }
        return delay < 0 ? 0 : delay;
    }

    void runTimeoutTasks()
    {
        auto currentTime = (UINT32)SystemClock.elapsedTime();

        for (UINT32 i = 0; i < MAX_TIMERS; i++)
        {
            auto& targetTime = timerTable[i].targetTime;
            if (targetTime != 0 && targetTime <= currentTime)
            {
                DBGBREAK();
                invokeTask(timerTable[i].task);
                targetTime = 0;
            }
        }
    }

    static DWORD __stdcall ThreadEntry(PVOID contextArg)
    {
        //CoInitializeEx(NULL, COINIT_MULTITHREADED);

        auto&& scheduler = *(SCHEDULER_INFO*)contextArg;

        OVERLAPPED_ENTRY overlapEntries[MAX_OVERLAP_ENTRIES];
        ULONG entryCount = 0;

        while (true)
        {
            auto timeout = scheduler.getWaitTimeout();
            GetQueuedCompletionStatusEx(scheduler.completionPort, overlapEntries, MAX_OVERLAP_ENTRIES, &entryCount, timeout, TRUE);

            SetSchedulerStack(scheduler.schedulerStack);
            SetServiceStack(scheduler.serviceStack);

            scheduler.runTimeoutTasks();

            for (UINT32 i = 0; i < entryCount; i++)
            {
                auto&& overlapEntry = overlapEntries[i];
                if (overlapEntry.lpCompletionKey == SCHED_TERMINATE)
                {
                    return 0;
                }
                else if (overlapEntry.lpCompletionKey == SCHED_CHECK_QUEUE)
                {
                    scheduler.runReadyTasks(0);
                }
                else
                {
                    ASSERT(overlapEntry.lpOverlapped != nullptr);
                    auto ioCallback = CONTAINING_RECORD(overlapEntry.lpOverlapped, IOCALLBACK, overlap);

                    auto&& task = ioCallback->task;
                    auto status = (NTSTATUS)overlapEntry.lpOverlapped->Internal;
                    scheduler.updateTask(task, status, overlapEntry.dwNumberOfBytesTransferred, ioCallback);
                    scheduler.invokeTask(task);
                }
            }
            scheduler.runTimeoutTasks();

            scheduler.schedulerStack.clear();
            ResetCurrentStacks();
        }

        return 0;
    }
};
extern SCHEDULER_INFO<>& GetCurrentScheduler();

struct THREAD_POOL
{
    struct TP_THREAD
    {
        SCHEDULER_STACK stack;
        HANDLE event;
        STASK task;
        HANDLE threadHandle;

        TP_THREAD() : stack()
        {
            event = CreateEvent(nullptr, FALSE, FALSE, nullptr);
        }

        static DWORD __stdcall ThreadEntry(PVOID contextArg)
        {
            auto& tpInfo = *(TP_THREAD*)contextArg;

            tpInfo.runTasks();

            return 0;
        }

        void runTasks()
        {
            SetSchedulerStack(stack);

            while (true)
            {
                auto waitResult = WaitForSingleObject(event, INFINITE);
                if (waitResult != WAIT_OBJECT_0)
                    break;

                auto argv = task.paramStream.getArgv();
                SESSION_STACK::CurrentStack = task.sessionStack;
                task.handlerFunction(task.handlerContext, task.result, argv);

                task.handlerFunction = nullptr;
            }
        }
    
        void start()
        {
            stack.init(4 * 1024 * 1024, 4 * 1024 * 1024);
            DWORD threadId;
            threadHandle = CreateThread(NULL, 0, ThreadEntry, this, 0, &threadId);

        }

        void stop()
        {
            TerminateThread(threadHandle, 0);
        }
    };

    constexpr static UINT32 MAX_THREADS = 65;
    UINT32 threadCount;
    TP_THREAD* threadTable[MAX_THREADS];

    void init()
    {
        threadCount = 8;
        for (UINT32 i = 0; i < threadCount; i++)
        {
            auto&& threadInfo = StackAlloc<TP_THREAD, GLOBAL_STACK>();
            threadInfo.start();
            threadTable[i] = &threadInfo;
        }
    }
    
    void runTask(STASK& task)
    {
        auto complete = false;
        for (UINT32 i = 0; i < threadCount; i++)
        {
            auto&& threadInfo = *threadTable[i];
            if (threadInfo.task.handlerFunction == nullptr)
            {
                NEW(threadInfo.task, task);
                SetEvent(threadInfo.event);
                complete = true;
                break;
            }
        }

        if (complete == false && threadCount < MAX_THREADS)
        {
            auto&& threadInfo = StackAlloc<TP_THREAD, GLOBAL_STACK>();
            threadInfo.start();
            threadTable[threadCount++] = &threadInfo;
            NEW(threadInfo.task, task);
            SetEvent(threadInfo.event);
            complete = true;
        }
        ASSERT(complete);
    }
    template <typename FUNC, typename ... ARGS>
    void runTask(FUNC handler, PVOID handlerContext, ARGS&& ... args)
    {
        STASK task{ handler, handlerContext, args ... };
        runTask(task);
    }
};

extern THREAD_POOL ThreadPool;
