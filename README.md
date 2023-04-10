# minhook-killer
Proof of concept demonstrating how heap entry enumeration & simple checks can be used to to locate, modify, and otherwise fiddle with hooks made by the minhook hooking library.

## Background
Awhile ago while reading the source code for minhook I realized it would be fairly easy to heuristically find the HOOK_ENTRY memory buffer and enumerate the data stored. The concept is very simple, since we know minhook creates a heap and allocates an array of HOOK_ENTRY(s) we can use checks ( verifying/checking entries stored ) to determine if a given heap entry is minhook's HOOK_ENTRY buffer.

## Disclaimer
Please do not critisize my code, I will cry. Yes, theres very clear better ways of doing this. To implementing safer, better, more efficient code i say, too much effort + dont care. You could easily check that the hook calls the detour calls the blah blah blah along with a bunch of other checks... it would just take fucking forever to write and not be remotely worth it. This worked for my use case, if it doesnt work for yours dont tell me as it will make me self conscious and sad.

## ~ Step 1 | 📏 Check Heap Entry Size

The following is the minhook function AddHookEntry which adds new hooks to the list of created hooks.
```c
/* minhook add hook entry to list function ( called upon hook creation ) */
static PHOOK_ENTRY AddHookEntry() {
    if (g_hooks.pItems == NULL) {
        g_hooks.capacity = INITIAL_HOOK_CAPACITY;
        
        /* Note how the size of the allocation will always be a multiple of sizeof(HOOK_ENTRY) */
        g_hooks.pItems = (PHOOK_ENTRY)HeapAlloc(
            g_hHeap, 0, g_hooks.capacity * sizeof(HOOK_ENTRY));
        if (g_hooks.pItems == NULL)
            return NULL;
    } else if (g_hooks.size >= g_hooks.capacity) {
    
    /* Note how the size of the allocation will always be a multiple of sizeof(HOOK_ENTRY) */
        PHOOK_ENTRY p = (PHOOK_ENTRY)HeapReAlloc(
            g_hHeap, 0, g_hooks.pItems, (g_hooks.capacity * 2) * sizeof(HOOK_ENTRY));
        if (p == NULL)
            return NULL;
        g_hooks.capacity *= 2;
        g_hooks.pItems = p;
    }
    return &g_hooks.pItems[g_hooks.size++];
}
```
Since the size of the HOOK_ENTRY buffer will always be a multiple of sizeof(HOOK_ENTRY), an initial check based on the size is done.
```c
/* BOOL DetectMinhook(fnHookDetectedCallback pCallback) */
    if (dwEntryBufferSize % sizeof(MHENTRY) != 0) // ensure size is a multiple of sizeof(MHENTRY)
        continue;
    //...

```

## ~ Step 2 | ☝️ Check Stored Pointers
In MH_CreateHook we can see 2 checks for IsExecutableAddress, done to prevent writing hooks where hooks shouldnt be written.
```c

MH_STATUS WINAPI MH_CreateHook(LPVOID pTarget, LPVOID pDetour, LPVOID *ppOriginal) {
// ...

      // this check is done to prevent writing hooks where hooks shouldnt be written.
      // we can use these same checks on the data stored in a heap entry to see if its contents match
      // that which would be expected in a valid/actual HOOK_ENTRY. 
        if (IsExecutableAddress(pTarget) && IsExecutableAddress(pDetour))
        {
        // the function then does other shit and if successful, adds the new hook info to the buffer.
        // ...

```
We use these same checks on the members of HOOK_ENTRY ( shown below ) to see if the data in our heap entry matches what would be seen in a valid HOOK_ENTRY buffer/list.
```c
typedef struct MH_ENTRY_T { // _HOOK_ENTRY
    LPVOID pTarget; // 0x0 - 0x4
    LPVOID pDetour; // 0x4 - 0x8
    LPVOID pTrampoline; // 0x8 - 0xC...
    // (and so on ) ...
} MHENTRY; // HOOK_ENTRY
```
Check the pointers are valid / point to executable mem
```c
/* CheckHookEntry(MHENTRY* pMem) */

    /* check if pTarget & pDetour & pTrampoline are valid executable addresses */
    for (auto i = 0; i < 3; ++i) {

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


```

## ~ Step 3 | 🦘 Compare Trampoline To Backup
- This is the final check, it is here i recommend modifying my code to ensure the function calls the detour, calls the trampoline, restores execution flow. To avoid all that mess we just do a shit check that will cause less accuracy but is like.. so much smaller and less work.
- The 'trampoline' virtually always begins with a copy of the first instruction(s) / the prologue from whatever function was hooked ( as space is needed for writing a jump instruction ). Minhook also stores another copy of this in the HOOK_ENTRY structure for restoring the hooked functions to their original state. A comparison of the HOOK_ENTRY->pTrampoline to the HOOK_ENTRY->backup can be used to verify with a high degree of certainty that a given hook entry is valid. Note: after the initial bytes their is generally an instruction to return execution flow to the original ( hooked ) function, this can also be checked for.

```c
/* BOOL CheckHookEntry(MHENTRY* pMem) */
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
```

## ~ Step 4 | 🥱 Overkill & Better Accuracy
- The mentioned checks provide a mostly accurate and, (important) SIMPLIFIED procedure for locating hooks. The checks of hook information could be expanded on, and i would recommend doing so if youre going to use this for anything ( this should ideally only be used on programs you already know use minhook ( if at all ) )
- A disasm library should be used such as hde32 to further check if a hooked function jumps to a detour which calls a trampoline which restores code execution to the original ( hooked function ). Doing this would allow you to be far more certain especially in regards to the number of hooks & the validity of hook information. Unfortunately, im far to lazy to actually implement that.


## Issues & Excuses For Poor Code Quality 😟

### Note On Use Cases
- The use cases for this are scarce. This code can detect minhook and locate hooks fairly easily however, using this as a standalone check for minhook usage would not be ideal as theres many possible false positives & failures which can arise. With that said, this does have use in debugging and analyzing programs which you already know use minhook.
- My use case for this was reverse engineering software which uses minhook. For that it works well but, is very preventable - Removing the created heap from the peb, using different means of allocation ( NtAllocateVirtualMemory ), obfuscating data stored, etc... are all simple ways to make this fail.
