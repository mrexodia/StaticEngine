#include "TitanEngine.h"

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
        //TODO
        return false;
    }

    bool AttachDebugger(DWORD ProcessId, bool KillOnExit, LPVOID DebugInfo, LPVOID CallBack)
    {
        mCbATTACHBREAKPOINT = STEPCALLBACK(CallBack);
        mAttachProcessInfo = (PROCESS_INFORMATION*)DebugInfo;
        //TODO
        return false;
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
        //TODO
        return false;
    }

    DEBUG_EVENT* GetDebugData()
    {
        //TODO
        return nullptr;
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
        //TODO
    }

    PROCESS_INFORMATION* TitanGetProcessInformation()
    {
        //TODO
        return nullptr;
    }

    STARTUPINFOW* TitanGetStartupInformation()
    {
        //TODO
        return nullptr;
    }

    //Misc
    void* GetPEBLocation(HANDLE hProcess)
    {
        //TODO
        return nullptr;
    }

    void* GetTEBLocation(HANDLE hProcess)
    {
        //TODO
        return nullptr;
    }

    bool HideDebugger(HANDLE hProcess, DWORD PatchAPILevel)
    {
        //TODO
        return false;
    }

    HANDLE TitanOpenProces(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwProcessId)
    {
        //TODO
        return OpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
    }

    HANDLE TitanOpenThread(DWORD dwDesiredAccess, bool bInheritHandle, DWORD dwThreadId)
    {
        //TODO
        return OpenThread(dwDesiredAccess, bInheritHandle, dwThreadId);
    }

    ULONG_PTR ImporterGetRemoteAPIAddress(HANDLE hProcess, ULONG_PTR APIAddress)
    {
        //TODO
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
        //TODO
        return false;
    }

    bool SetContextDataEx(HANDLE hActiveThread, DWORD IndexOfRegister, ULONG_PTR NewRegisterValue)
    {
        //TODO
        return false;
    }

    bool GetFullContextDataEx(HANDLE hActiveThread, TITAN_ENGINE_CONTEXT_t* titcontext) const
    {
        //TODO
        return false;
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
};