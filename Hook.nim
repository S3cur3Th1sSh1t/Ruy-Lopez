

import winim

type
    typeNtCreateSection* = proc (SectionHandle: PHANDLE, DesiredAccess: ULONG, ObjectAttributes: POBJECT_ATTRIBUTES,
                       MaximumSize: PLARGE_INTEGER, PageAttributess: ULONG, SectionAttributes: ULONG,
                       FileHandle: HANDLE): NTSTATUS {.stdcall.}


type
    MyNtFlushInstructionCache* = proc (ProcessHandle: HANDLE, BaseAddress: PVOID, NumberofBytestoFlush: ULONG): NTSTATUS {.stdcall.}


type
  HookedNtCreate* {.bycopy.} = object
    origNtCreate*: typeNtCreateSection
    ntCreateStub*: array[24, BYTE]

  HookTrampolineBuffers* {.bycopy.} = object
    originalBytes*: HANDLE    ##  (Input) Buffer containing bytes that should be restored while unhooking.
    originalBytesSize*: DWORD  ##  (Output) Buffer that will receive bytes present prior to trampoline installation/restoring.
    previousBytes*: HANDLE
    previousBytesSize*: DWORD

var ntdlldll = LoadLibraryA("ntdll.dll")
if (ntdlldll == 0):
    echo "[X] Failed to load ntdll.dll"


var NtFlushInstructionCacheAddress = GetProcAddress(ntdlldll,"NtFlushInstructionCache")
if isNil(NtFlushInstructionCacheAddress):
    echo "[X] Failed to get the address of 'NtFlushInstructionCache'"


var NtFlushInstructionCache*: MyNtFlushInstructionCache
NtFlushInstructionCache = cast[MyNtFlushInstructionCache](NtFlushInstructionCacheAddress)


proc fastTrampoline*(targetProc: HANDLE, addressToHook: LPVOID, jumpAddress: LPVOID, buffers: ptr HookTrampolineBuffers = nil): bool

var g_hookedNtCreate*: HookedNtCreate

var ntCreate_Address*: HANDLE

var NtCreateSection*: typeNtCreateSection

proc fastTrampoline*(targetProc: HANDLE, addressToHook: LPVOID, jumpAddress: LPVOID, buffers: ptr HookTrampolineBuffers): bool =
    var trampoline: seq[byte]
    if defined(amd64):
        trampoline = @[
            byte(0x49), byte(0xBA), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov r10, addr
            byte(0x00),byte(0x00),byte(0x41), byte(0xFF),byte(0xE2)                                         # jmp r10
        ]
        var tempjumpaddr: uint64 = cast[uint64](jumpAddress)
        copyMem(&trampoline[2] , &tempjumpaddr, 6)
    elif defined(i386):
        trampoline = @[
            byte(0xB8), byte(0x00), byte(0x00), byte(0x00), byte(0x00), # mov eax, addr
            byte(0x00),byte(0x00),byte(0xFF), byte(0xE0)                                      # jmp eax
        ]
        var tempjumpaddr: uint32 = cast[uint32](jumpAddress)
        copyMem(&trampoline[1] , &tempjumpaddr, 3)
    
    var dwSize: DWORD = DWORD(len(trampoline))
    var dwOldProtect: DWORD = 0
    var output: bool = false
    


    if (buffers != nil):
        if ((buffers.previousBytes == 0) or buffers.previousBytesSize == 0):
            echo "Previous Bytes == 0"
            return false
        copyMem(unsafeAddr buffers.previousBytes, addressToHook, buffers.previousBytesSize)

    if (VirtualProtect(addressToHook, dwSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)):
        #echo "Virtual Protect to RWX success!"
        #echo toHex((&trampoline[0]))
        var yeah: WINBOOL = WriteProcessMemory(targetProc, addressToHook, addr trampoline[0], dwSize, nil)
        if (yeah == 0):
            echo "[-] WriteProcessMemory failed: ", toHex(GetLastError())
        else:
            echo "[+] WriteProcessMemory success"
        #copyMem(addressToHook, addr trampoline[0], dwSize)
        output = true
    
    
    var status = NtFlushInstructionCache(GetCurrentProcess(), addressToHook, dwSize)
    if (status == 0):
        echo "[+] NtFlushInstructionCache success"
    else:
        echo "[-] NtFlushInstructionCache failed: ", toHex(status)
    
    #VirtualProtect(addressToHook, dwSize, dwOldProtect, &dwOldProtect)

    return output