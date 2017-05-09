#include "TitanEngine.h"
#include <Psapi.h>
#include <TlHelp32.h>
#include <unordered_map>
#include "ntdll.h"

#pragma comment(lib, "psapi.lib")

//https://www.codeproject.com/Questions/78801/How-to-get-the-main-thread-ID-of-a-process-known-b

#ifndef MAKEULONGLONG
#define MAKEULONGLONG(ldw, hdw) ((ULONGLONG(hdw) << 32) | ((ldw) & 0xFFFFFFFF))
#endif

#ifndef MAXULONGLONG
#define MAXULONGLONG ((ULONGLONG)~((ULONGLONG)0))
#endif

class Emulator
{
public:
    //Debugger
    PROCESS_INFORMATION* InitDebugW(const wchar_t* szFileName, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder)
    {
        //TODO
        mCbATTACHBREAKPOINT = nullptr;
        return nullptr;
    }

    PROCESS_INFORMATION* InitDLLDebugW(const wchar_t* szFileName, bool ReserveModuleBase, const wchar_t* szCommandLine, const wchar_t* szCurrentFolder, LPVOID EntryCallBack)
    {
        //TODO
        return nullptr;
    }

    bool StopDebug()
    {
        SetEvent(hEvent);
        return true;
    }

    static std::vector<HMODULE> enumModules(HANDLE hProcess)
    {
        std::vector<HMODULE> result;
        DWORD cbNeeded = 0;
        if(EnumProcessModules(hProcess, nullptr, 0, &cbNeeded))
        {
            result.resize(cbNeeded / sizeof(HMODULE));
            if(!EnumProcessModules(hProcess, result.data(), cbNeeded, &cbNeeded))
                result.clear();
        }
        return result;
    }

    static std::wstring getModuleName(HANDLE hProcess, HMODULE hModule)
    {
        wchar_t szFileName[MAX_PATH] = L"";
        if(!GetModuleFileNameExW(hProcess, hModule, szFileName, _countof(szFileName)))
            *szFileName = L'\0';
        return szFileName;
    }

    static MODULEINFO getModuleInfo(HANDLE hProcess, HMODULE hModule)
    {
        MODULEINFO info;
        if(!GetModuleInformation(hProcess, hModule, &info, sizeof(MODULEINFO)))
            memset(&info, 0, sizeof(info));
        return info;
    }

    void getThreadList(DWORD dwProcessId)
    {
        //https://blogs.msdn.microsoft.com/oldnewthing/20060223-14/?p=32173
        HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if(h != INVALID_HANDLE_VALUE)
        {
            THREADENTRY32 te;
            te.dwSize = sizeof(te);
            ULONGLONG ullMinCreateTime = MAXULONGLONG;
            dwMainThreadId = 0;
            if(Thread32First(h, &te))
            {
                do
                {
                    if(te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(te.th32OwnerProcessID) && te.th32OwnerProcessID == dwProcessId)
                    {
                        auto hThread = TitanOpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
                        mThreadList[te.th32ThreadID] = hThread;
                        FILETIME afTimes[4] = { 0 };
                        if(GetThreadTimes(hThread, &afTimes[0], &afTimes[1], &afTimes[2], &afTimes[3]))
                        {
                            ULONGLONG ullTest = MAKEULONGLONG(afTimes[0].dwLowDateTime, afTimes[0].dwHighDateTime);
                            if(ullTest && ullTest < ullMinCreateTime)
                            {
                                ullMinCreateTime = ullTest;
                                dwMainThreadId = te.th32ThreadID;
                            }
                        }
                        else if(!dwMainThreadId)
                            dwMainThreadId = te.th32ThreadID;
                    }
                    te.dwSize = sizeof(te);
                } while(Thread32Next(h, &te));
            }
            CloseHandle(h);
        }
    }

    DWORD dwMainThreadId;
    std::unordered_map<DWORD, HANDLE> mThreadList;
    bool mIsDebugging = false;
    PVOID mEntryPoint;
    HANDLE hEvent;

    bool cleanup(bool result)
    {
        if(mProcessInfo.hProcess)
            CloseHandle(mProcessInfo.hProcess);
        if(mProcessInfo.hThread)
            CloseHandle(mProcessInfo.hThread);
        for(auto it : mThreadList)
            CloseHandle(it.second);
        mThreadList.clear();
        mIsDebugging = false;
        return result;
    }

    bool AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
    {
        //initialization + open process
        mCbATTACHBREAKPOINT = STEPCALLBACK(CallBack);
        mAttachProcessInfo = (PROCESS_INFORMATION*)DebugInfo;
        memset(&mProcessInfo, 0, sizeof(PROCESS_INFORMATION));
        mProcessInfo.dwProcessId = ProcessId;
        mProcessInfo.hProcess = TitanOpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessId);
        if(!mProcessInfo.hProcess)
            return cleanup(false);

        //get threads
        getThreadList(mProcessInfo.dwProcessId);
        if(!mThreadList.count(dwMainThreadId))
            return cleanup(false);
        mProcessInfo.dwThreadId = dwMainThreadId;
        mProcessInfo.hThread = mThreadList[dwMainThreadId];
        *mAttachProcessInfo = mProcessInfo;
        
        //create process
        CREATE_PROCESS_DEBUG_INFO createProcess;
        memset(&createProcess, 0, sizeof(CREATE_PROCESS_DEBUG_INFO));
        auto mods = enumModules(mProcessInfo.hProcess);
        if(mods.empty())
            return cleanup(false);
        auto mainMod = mods[0]; //undocumented might not be always true
        auto mainName = getModuleName(mProcessInfo.hProcess, mainMod);
        auto mainInfo = getModuleInfo(mProcessInfo.hProcess, mainMod);
        if(!mainInfo.lpBaseOfDll || mainName.empty())
            return cleanup(false);
        mIsDebugging = true;
        createProcess.hFile = CreateFileW(mainName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        createProcess.hProcess = mProcessInfo.hProcess;
        createProcess.hThread = mProcessInfo.hThread;
        createProcess.lpBaseOfImage = mainMod;
        createProcess.lpStartAddress = LPTHREAD_START_ROUTINE(mEntryPoint = mainInfo.EntryPoint);
        createProcess.lpThreadLocalBase = GetTEBLocation(createProcess.hThread);
        mCbCREATEPROCESS(&createProcess);
        CloseHandle(createProcess.hFile);

        memset(&mDebugEvent, 0, sizeof(DEBUG_EVENT));
        mDebugEvent.dwProcessId = mProcessInfo.dwProcessId;
        mDebugEvent.dwThreadId = mProcessInfo.dwThreadId;

        //load modules
        for(size_t i = 1; i < mods.size(); i++)
        {
            LOAD_DLL_DEBUG_INFO loadDll;
            memset(&loadDll, 0, sizeof(LOAD_DLL_DEBUG_INFO));
            loadDll.lpBaseOfDll = mods[i];
            auto dllName = getModuleName(mProcessInfo.hProcess, mods[i]);
            if(!dllName.empty())
                loadDll.hFile = CreateFileW(dllName.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
            mCbLOADDLL(&loadDll);
            if(!dllName.empty())
                CloseHandle(loadDll.hFile);
        }
        
        //create threads
        for(auto it : mThreadList)
        {
            if(it.first == dwMainThreadId)
                continue;
            CREATE_THREAD_DEBUG_INFO createThread;
            memset(&createThread, 0, sizeof(CREATE_THREAD_DEBUG_INFO));
            createThread.hThread = it.second;
            ULONG len = sizeof(PVOID);
            if(NtQueryInformationThread(createThread.hThread, ThreadQuerySetWin32StartAddress, &createThread.lpStartAddress, len, &len))
                createThread.lpStartAddress = nullptr;
            createThread.lpThreadLocalBase = GetTEBLocation(createThread.hThread);
            mCbCREATETHREAD(&createThread);
        }

        //create the event that gets trigged in StopDebug
        hEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);

        //attach breakpoint
        mCbATTACHBREAKPOINT();
        
        //system breakpoint
        mCbSYSTEMBREAKPOINT(nullptr);

        //return after stop/detach is called
        WaitForSingleObject(hEvent, INFINITE);
        CloseHandle(hEvent);
        return cleanup(true);
    }

    bool DetachDebuggerEx(DWORD ProcessId)
    {
        //TODO
        return false;
    }

    void DebugLoop()
    {
        //TODO
    }

    void SetNextDbgContinueStatus(DWORD SetDbgCode)
    {
        //TODO
    }

    //Memory
    bool MemoryReadSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesRead) const
    {
        SIZE_T s;
        if(!lpNumberOfBytesRead)
            lpNumberOfBytesRead = &s;
        return !!ReadProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesRead);
    }

    bool MemoryWriteSafe(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten)
    {
        SIZE_T s;
        if(!lpNumberOfBytesWritten)
            lpNumberOfBytesWritten = &s;
        return !!WriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
    }

    bool Fill(LPVOID MemoryStart, DWORD MemorySize, PBYTE FillByte)
    {
        //TODO
        return false;
    }

    //Engine
    bool EngineCheckStructAlignment(DWORD StructureType, ULONG_PTR StructureSize) const
    {
        if (StructureType == UE_STRUCT_TITAN_ENGINE_CONTEXT)
            return StructureSize == sizeof(TITAN_ENGINE_CONTEXT_t);
        return false;
    }

    bool IsFileBeingDebugged() const
    {
        return mIsDebugging;
    }

    DEBUG_EVENT mDebugEvent;

    DEBUG_EVENT* GetDebugData()
    {
        return &mDebugEvent;
    }

    void SetCustomHandler(DWORD ExceptionId, PVOID CallBack)
    {
        switch (ExceptionId)
        {
        case UE_CH_CREATEPROCESS:
            mCbCREATEPROCESS = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_EXITPROCESS:
            mCbEXITPROCESS = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_CREATETHREAD:
            mCbCREATETHREAD = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_EXITTHREAD:
            mCbEXITTHREAD = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_SYSTEMBREAKPOINT:
            mCbSYSTEMBREAKPOINT = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_LOADDLL:
            mCbLOADDLL = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_UNLOADDLL:
            mCbUNLOADDLL = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_OUTPUTDEBUGSTRING:
            mCbOUTPUTDEBUGSTRING = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_UNHANDLEDEXCEPTION:
            mCbUNHANDLEDEXCEPTION = CUSTOMHANDLER(CallBack);
            break;
        case UE_CH_DEBUGEVENT:
            mCbDEBUGEVENT = CUSTOMHANDLER(CallBack);
            break;
        default:
            break;
        }
    }

    void SetEngineVariable(DWORD VariableId, bool VariableSet)
    {
        if(VariableId == UE_ENGINE_SET_DEBUG_PRIVILEGE)
            mSetDebugPrivilege = VariableSet;
    }

    PROCESS_INFORMATION* TitanGetProcessInformation()
    {
        return &mProcessInfo;
    }

    STARTUPINFOW* TitanGetStartupInformation()
    {
        //TODO
        return nullptr;
    }

    //Misc
    void* GetPEBLocation(HANDLE hProcess)
    {
        ULONG RequiredLen = 0;
        void* PebAddress = 0;
        PROCESS_BASIC_INFORMATION myProcessBasicInformation[5] = { 0 };

        if(NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, sizeof(PROCESS_BASIC_INFORMATION), &RequiredLen) == 0)
        {
            PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
        }
        else
        {
            if(NtQueryInformationProcess(hProcess, ProcessBasicInformation, myProcessBasicInformation, RequiredLen, &RequiredLen) == 0)
            {
                PebAddress = (void*)myProcessBasicInformation->PebBaseAddress;
            }
        }

        return PebAddress;
    }

    void* GetTEBLocation(HANDLE hThread)
    {
        ULONG RequiredLen = 0;
        void* TebAddress = 0;
        THREAD_BASIC_INFORMATION myThreadBasicInformation[5] = { 0 };

        if(NtQueryInformationThread(hThread, ThreadBasicInformation, myThreadBasicInformation, sizeof(THREAD_BASIC_INFORMATION), &RequiredLen) == 0)
        {
            TebAddress = (void*)myThreadBasicInformation->TebBaseAddress;
        }
        else
        {
            if(NtQueryInformationThread(hThread, ThreadBasicInformation, myThreadBasicInformation, RequiredLen, &RequiredLen) == 0)
            {
                TebAddress = (void*)myThreadBasicInformation->TebBaseAddress;
            }
        }

        return TebAddress;
    }

    bool HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
    {
        //TODO
        return false;
    }

    HANDLE TitanOpenProcess(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
    {
        //TODO
        return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    HANDLE TitanOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId)
    {
        //TODO: debug privilege
        return OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    }

    ULONG_PTR ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        //TODO: debug privilege
        return 0;
    }

    //Stepping
    void StepOver(LPVOID CallBack)
    {
        //TODO
    }

    void StepInto(LPVOID CallBack)
    {
        //TODO
    }

    //Registers
    ULONG_PTR GetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister) const
    {
        switch(IndexOfRegister)
        {
        case UE_EIP:
        case UE_RIP:
        case UE_CIP:
            return ULONG_PTR(mEntryPoint);
        }
        //TODO
        return 0;
    }

    bool SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
    {
        //TODO
        return false;
    }

    bool GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext) const
    {
        //TODO
        titcontext->cip = ULONG_PTR(mEntryPoint);
        return true;
    }

    bool SetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext)
    {
        //TODO
        return false;
    }

    void GetMMXRegisters(uint64_t mmx[8], TITAN_ENGINE_CONTEXT_t* titcontext)
    {
        //TODO
        memset(mmx, 0, sizeof(uint64_t) * 8);
    }

    void Getx87FPURegisters(x87FPURegister_t x87FPURegisters[8], TITAN_ENGINE_CONTEXT_t* titcontext)
    {
        //TODO
        memset(x87FPURegisters, 0, sizeof(x87FPURegister_t) * 8);
    }

    //PE
    bool StaticFileLoadW(const wchar_t* szFileName, DWORD DesiredAccess, bool SimulateLoad, LPHANDLE FileHandle, LPDWORD LoadedSize, LPHANDLE FileMap, PULONG_PTR FileMapVA)
    {
        //TODO
        return false;
    }

    bool StaticFileUnloadW(const wchar_t* szFileName, bool CommitChanges, HANDLE FileHandle, DWORD LoadedSize, HANDLE FileMap, ULONG_PTR FileMapVA)
    {
        //TODO
        return false;
    }

    ULONG_PTR ConvertFileOffsetToVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert, bool ReturnType)
    {
        //TODO
        return 0;
    }

    ULONG_PTR ConvertVAtoFileOffsetEx(ULONG_PTR FileMapVA, DWORD FileSize, ULONG_PTR ImageBase, ULONG_PTR AddressToConvert, bool AddressIsRVA, bool ReturnType)
    {
        //TODO
        return 0;
    }

    ULONG_PTR GetPE32DataFromMappedFile(ULONG_PTR FileMapVA, DWORD WhichSection, DWORD WhichData)
    {
        //TODO
        return 0;
    }

    ULONG_PTR GetPE32DataW(const wchar_t* szFileName, DWORD WhichSection, DWORD WhichData)
    {
        //TODO
        return 0;
    }

    bool IsFileDLLW(const wchar_t* szFileName, ULONG_PTR FileMapVA)
    {
        //TODO
        return false;
    }

    long GetPE32SectionNumberFromVA(ULONG_PTR FileMapVA, ULONG_PTR AddressToConvert)
    {
        //TODO
        return 0;
    }

    bool TLSGrabCallBackDataW(const wchar_t* szFileName, LPVOID ArrayOfCallBacks, LPDWORD NumberOfCallBacks)
    {
        //TODO
        return false;
    }

    //Software Breakpoints
    bool SetBPX(ULONG_PTR bpxAddress, DWORD bpxType, LPVOID bpxCallBack)
    {
        //TODO
        return false;
    }

    bool DeleteBPX(ULONG_PTR bpxAddress)
    {
        //TODO
        return false;
    }

    bool IsBPXEnabled(ULONG_PTR bpxAddress)
    {
        //TODO
        return false;
    }

    void SetBPXOptions(long DefaultBreakPointType)
    {
    }

    //Memory Breakpoints
    bool SetMemoryBPXEx(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory, DWORD BreakPointType, bool RestoreOnHit, LPVOID bpxCallBack)
    {
        //TODO
        return false;
    }

    bool RemoveMemoryBPX(ULONG_PTR MemoryStart, SIZE_T SizeOfMemory)
    {
        //TODO
        return false;
    }

    //Hardware Breakpoints
    bool SetHardwareBreakPoint(ULONG_PTR bpxAddress, DWORD IndexOfRegister, DWORD bpxType, DWORD bpxSize, LPVOID bpxCallBack)
    {
        //TODO
        return false;
    }

    bool DeleteHardwareBreakPoint(DWORD IndexOfRegister)
    {
        //TODO
        return false;
    }

    bool GetUnusedHardwareBreakPointRegister(LPDWORD RegisterIndex)
    {
        //TODO
        return false;
    }

    //Librarian Breakpoints
    bool LibrarianSetBreakPoint(const char* szLibraryName, DWORD bpxType, bool SingleShoot, LPVOID bpxCallBack)
    {
        //TODO
        return false;
    }

    bool LibrarianRemoveBreakPoint(const char* szLibraryName, DWORD bpxType)
    {
        //TODO
        return false;
    }

    //Generic Breakpoints
    bool RemoveAllBreakPoints(DWORD RemoveOption)
    {
        //TODO
        return false;
    }

private: //variables
    bool mSetDebugPrivilege = false;
    typedef void(*CUSTOMHANDLER)(const void*);
    typedef void(*STEPCALLBACK)();
    typedef STEPCALLBACK BPCALLBACK;
    typedef CUSTOMHANDLER HWBPCALLBACK;
    typedef CUSTOMHANDLER MEMBPCALLBACK;
    CUSTOMHANDLER mCbCREATEPROCESS = nullptr;
    CUSTOMHANDLER mCbEXITPROCESS = nullptr;
    CUSTOMHANDLER mCbCREATETHREAD = nullptr;
    CUSTOMHANDLER mCbEXITTHREAD = nullptr;
    CUSTOMHANDLER mCbSYSTEMBREAKPOINT = nullptr;
    CUSTOMHANDLER mCbLOADDLL = nullptr;
    CUSTOMHANDLER mCbUNLOADDLL = nullptr;
    CUSTOMHANDLER mCbOUTPUTDEBUGSTRING = nullptr;
    CUSTOMHANDLER mCbUNHANDLEDEXCEPTION = nullptr;
    CUSTOMHANDLER mCbDEBUGEVENT = nullptr;
    STEPCALLBACK mCbATTACHBREAKPOINT = nullptr;
    PROCESS_INFORMATION* mAttachProcessInfo = nullptr;
    PROCESS_INFORMATION mProcessInfo;
};