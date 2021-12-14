#pragma once
#include <Windows.h>
#include <Winternl.h>
#include <tchar.h>
#include <stdio.h>
#include <sddl.h>
#include <shellapi.h>
#include <strsafe.h>

#define REGISTRY_USER_PREFIX _T("\\Registry\\User\\")
#define IMAGE_PATH _T("\\??\\")

int fullsend(LPWSTR, LPWSTR);