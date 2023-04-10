#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <Windows.h>

#pragma region Misc Macros
#define Log(...) printf(__VA_ARGS__)
#pragma endregion

#pragma region Windows Internals Stuff
typedef struct _PEB {
    BOOLEAN InheritedAddressSpace;
    BOOLEAN ReadImageFileExecOptions;
    BOOLEAN BeingDebugged;
    union
    {
        BOOLEAN BitField;
        struct
        {
            BOOLEAN ImageUsesLargePages : 1;
            BOOLEAN IsProtectedProcess : 1;
            BOOLEAN IsImageDynamicallyRelocated : 1;
            BOOLEAN SkipPatchingUser32Forwarders : 1;
            BOOLEAN IsPackagedProcess : 1;
            BOOLEAN IsAppContainer : 1;
            BOOLEAN IsProtectedProcessLight : 1;
            BOOLEAN SpareBits : 1;
        };
    };
    HANDLE Mutant;

    PVOID ImageBaseAddress;
    struct _PEB_LDR_DATA* Ldr;
    struct _RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
    PVOID SubSystemData;
    PVOID ProcessHeap;
    PRTL_CRITICAL_SECTION FastPebLock;
    PVOID AtlThunkSListPtr;
    PVOID IFEOKey;
    union
    {
        ULONG CrossProcessFlags;
        struct
        {
            ULONG ProcessInJob : 1;
            ULONG ProcessInitializing : 1;
            ULONG ProcessUsingVEH : 1;
            ULONG ProcessUsingVCH : 1;
            ULONG ProcessUsingFTH : 1;
            ULONG ReservedBits0 : 27;
        };
        ULONG EnvironmentUpdateCount;
    };
    union
    {
        PVOID KernelCallbackTable;
        PVOID UserSharedInfoPtr;
    };
    ULONG SystemReserved[1];
    ULONG AtlThunkSListPtr32;
    PVOID ApiSetMap;
    ULONG TlsExpansionCounter;
    PVOID TlsBitmap;
    ULONG TlsBitmapBits[2];
    PVOID ReadOnlySharedMemoryBase;
    PVOID HotpatchInformation;
    PVOID *ReadOnlyStaticServerData;
    PVOID AnsiCodePageData;
    PVOID OemCodePageData;
    PVOID UnicodeCaseTableData;

    ULONG NumberOfProcessors;
    ULONG NtGlobalFlag;

    LARGE_INTEGER CriticalSectionTimeout;
    SIZE_T HeapSegmentReserve;
    SIZE_T HeapSegmentCommit;
    SIZE_T HeapDeCommitTotalFreeThreshold;
    SIZE_T HeapDeCommitFreeBlockThreshold;

    ULONG NumberOfHeaps;
    ULONG MaximumNumberOfHeaps;
    PVOID *ProcessHeaps;
} PEB, *PPEB;

__declspec(naked) PPEB GetPeb() {
    __asm {
        mov eax, fs: [0x30]
        retn
    }
}
#pragma endregion

#pragma region Minhook Structs

#pragma pack(push, 1)
typedef struct _JMP_REL_SHORT { UINT8  opcode; UINT8  operand; } JMP_REL_SHORT, * PJMP_REL_SHORT;
typedef struct _JMP_REL { UINT8  opcode; UINT32 operand; } JMP_REL, * PJMP_REL, CALL_REL;
#pragma pack(pop)

/* HOOK_ENTRY */
typedef struct MH_ENTRY_T {
    LPVOID pTarget;
    LPVOID pDetour;
    LPVOID pTrampoline;
    UINT8 backup[8];
    UINT8 patchAbove : 1;
    UINT8 isEnabled : 1;
    UINT8 queueEnable : 1;
    UINT nIP : 4;
    UINT8 oldIPs[8];
    UINT8 newIPs[8];
} MHENTRY;

#pragma endregion

BOOL CheckHookEntry(MHENTRY* pMem) {
    if (pMem == NULL) {
        return FALSE;
    }

    /* check if pTarget & pDetour & pTrampoline are valid executable addresses */
    for (SIZE_T i = 0; i < 3; ++i) {

        /* ensure data isnt null */
        PVOID pFn = ((PVOID*)pMem)[i];
        if (pFn == NULL) {
            return FALSE;
        }

        MEMORY_BASIC_INFORMATION mbi;
        if (!VirtualQuery(pFn, &mbi, sizeof(mbi))) {
            // current entry is not minhook shit 
            return FALSE;
        }

        /* ensure address is executable */
        {
#define EXEC_FLAGS (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)

            if (mbi.State != MEM_COMMIT) {
                return FALSE;
            }
            if (!(mbi.Protect & EXEC_FLAGS)) {
                return FALSE;
            }

#undef EXEC_FLAGS
        }
    }

    /* check if trampoline begins with prologue stored in backup */
    MHENTRY* pMinhookEntry = (MHENTRY*)pMem;
    UINT8* pTrampolineBytes = (UINT8*)pMinhookEntry->pTrampoline;
    for (SIZE_T i = 0; i < 8; ++i) {
        const BYTE cur = pMinhookEntry->backup[i];
        if (cur == 0) {
            break;
        }

        if (cur != pTrampolineBytes[i]) {
            return FALSE;
        }
    }

    return TRUE;
}

typedef VOID(*fnHookDetectedCallback)(MHENTRY*);
BOOL DetectMinhook(fnHookDetectedCallback pCallback) {
    if (pCallback == NULL) {
        return FALSE;
    }

    PPEB pCurrentPeb = GetPeb();
    if (pCurrentPeb == NULL) {
        return FALSE;
    }

    const DWORD dwNumberOfHeaps = pCurrentPeb->NumberOfHeaps;

    for (SIZE_T i = 0; i < dwNumberOfHeaps; ++i) {

        /* note: if something modifies this while were using it everything can explode */
        PVOID pHeap = pCurrentPeb->ProcessHeaps[i];
        HeapLock(pHeap);


        /* enumerate heap entries & try to find minhook hook entries */
        PROCESS_HEAP_ENTRY entry;
        entry.lpData = NULL;

        while (HeapWalk(pHeap, &entry) != FALSE) {
            
            const DWORD dwEntryBufferSize = entry.cbData;

            /* ensure size is a multiple of sizeof(MHENTRY) */
            if (dwEntryBufferSize % sizeof(MHENTRY) != 0) {
                continue;
            }

            MHENTRY* pMinhookEntries = (MHENTRY*)entry.lpData;

            /* enumerate possible data */
            const DWORD dwNumberOfHooks = dwEntryBufferSize / sizeof(MHENTRY);
            for (DWORD b = 0; b < dwNumberOfHooks; b++) {

                /* validate data */
                MHENTRY* pEntry = (MHENTRY*)((DWORD)pMinhookEntries + (sizeof(MHENTRY) * b));
                if (CheckHookEntry(pEntry) == FALSE) {
                    break;
                }

                pCallback(pEntry);
            }

        }

        HeapUnlock(pHeap);
    }

    return TRUE;
}

VOID OnHookDetected(MHENTRY* pEntry) {
  if(pEntry == NULL) return; // this check is pointless as the function will only be called with valid data
  
    printf("\n [ minhook killer ] Found Hook {\n  Function: %x\n  Detour: %x\n  Trampoline: %x\n }\n", (DWORD)pEntry->pTarget, (DWORD)pEntry->pDetour, (DWORD)pEntry->pTrampoline);

    /* get number of bytes to copy */
    DWORD dwNumberOfBytesToRestore = sizeof(JMP_REL);
    if (pEntry->patchAbove == TRUE) dwNumberOfBytesToRestore = sizeof(JMP_REL) + sizeof(JMP_REL_SHORT);

    /* restore / remove hook */
    DWORD dwOldProtect;
    if (VirtualProtect(pEntry->pTarget, dwNumberOfBytesToRestore, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
        
        if (pEntry->patchAbove)
            memcpy(pEntry->pTarget, pEntry->backup, sizeof(JMP_REL) + sizeof(JMP_REL_SHORT));
        else
            memcpy(pEntry->pTarget, pEntry->backup, sizeof(JMP_REL));
   
        if (VirtualProtect(pEntry->pTarget, dwNumberOfBytesToRestore, dwOldProtect, &dwOldProtect)) {
        
        }
    }

    /* invalidate entry ( note: nothing is freed here / this leaks memory ) */
    pEntry->isEnabled = FALSE;
    //pEntry->queueEnable = FALSE;
    //pEntry->pDetour = NULL;
    //pEntry->pTarget = NULL;
    //pEntry->pTrampoline = NULL;
}

DWORD WINAPI MainThreadProcedure(LPVOID lpParam) {
    /* open console & say hello */
    {
        AllocConsole();
        FILE* pDummyFile = NULL;
        freopen_s(&pDummyFile, "CONOUT$", "w", stdout);

        SetConsoleTitleA(" [ minhook killer ] - Heuristic Hook Detector");
        Log(" [ minhook killer ] meow \n");
    }

    /* run scan */
    DetectMinhook(OnHookDetected);

    /* unload */
    FreeLibraryAndExitThread((HMODULE)lpParam, EXIT_SUCCESS);
    return 0;
}

BOOL WINAPI DllMain(
    HINSTANCE hCurrentInstance,
    DWORD dwReason,
    LPVOID lpParam) {
    
    if (dwReason == DLL_PROCESS_ATTACH) {
       HANDLE hThread = CreateThread(NULL, 0, MainThreadProcedure, hCurrentInstance, 0, NULL);
       if (hThread) {
           CloseHandle(hThread);
       }
    }

    return TRUE;
}
