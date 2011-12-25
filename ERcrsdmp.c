/*----------------------------------------------------------------------
   CrashDump.c
----------------------------------------------------------------------*/
#include <windows.h>

#include <time.h>
#include <stdio.h>
#include <winnt.h>
#include <crtdbg.h>
#include <malloc.h>
#include <tlhelp32.h>
#include <imagehlp.h>

#define EXCEPTION_ACCESS_VIOLATION_STR          "The thread tried to read from or write to a virtual address for which it does not have the appropriate access."
#define EXCEPTION_ARRAY_BOUNDS_EXCEEDED_STR     "The thread tried to access an array element that is out of bounds and the underlying hardware supports bounds checking."
#define EXCEPTION_BREAKPOINT_STR                "A breakpoint was encountered."
#define EXCEPTION_DATATYPE_MISALIGNMENT_STR     "The thread tried to read or write data that is misaligned on hardware that does not provide alignment. For example, 16-bit values must be aligned on 2-byte boundaries; 32-bit values on 4-byte boundaries, and so on."
#define EXCEPTION_FLT_DENORMAL_OPERAND_STR      "One of the operands in a floating-point operation is denormal. A denormal value is one that is too small to represent as a standard floating-point value."
#define EXCEPTION_FLT_DIVIDE_BY_ZERO_STR        "The thread tried to divide a floating-point value by a floating-point divisor of zero."
#define EXCEPTION_FLT_INEXACT_RESULT_STR        "The result of a floating-point operation cannot be represented exactly as a decimal fraction."
#define EXCEPTION_FLT_INVALID_OPERATION_STR     "This exception represents any floating-point exception not included in this list."
#define EXCEPTION_FLT_OVERFLOW_STR              "The exponent of a floating-point operation is greater than the magnitude allowed by the corresponding type."
#define EXCEPTION_FLT_STACK_CHECK_STR           "The stack overflowed or underflowed as the result of a floating-point operation."
#define EXCEPTION_FLT_UNDERFLOW_STR             "The exponent of a floating-point operation is less than the magnitude allowed by the corresponding type."
#define EXCEPTION_ILLEGAL_INSTRUCTION_STR       "The thread tried to execute an invalid instruction."
#define EXCEPTION_IN_PAGE_ERROR_STR             "The thread tried to access a page that was not present, and the system was unable to load the page. For example, this exception might occur if a network connection is lost while running a program over the network."
#define EXCEPTION_INT_DIVIDE_BY_ZERO_STR        "The thread tried to divide an integer value by an integer divisor of zero."
#define EXCEPTION_INT_OVERFLOW_STR              "The result of an integer operation caused a carry out of the most significant bit of the result."
#define EXCEPTION_INVALID_DISPOSITION_STR       "An exception handler returned an invalid disposition to the exception dispatcher. Programmers using a high-level language such as C should never encounter this exception."
#define EXCEPTION_NONCONTINUABLE_EXCEPTION_STR  "The thread tried to continue execution after a noncontinuable exception occurred."
#define EXCEPTION_PRIV_INSTRUCTION_STR          "The thread tried to execute an instruction whose operation is not allowed in the current machine mode."
#define EXCEPTION_SINGLE_STEP_STR               "A trace trap or other single-instruction mechanism signaled that one instruction has been executed."
#define EXCEPTION_STACK_OVERFLOW_STR            "The thread used up its stack."

#define _USE_VERSIONING_
#ifdef _USE_VERSIONING_
#include <winver.h>
#endif

#define _USE_PSAPI_
#ifdef _USE_PSAPI_
// Copied from psapi.h
	typedef struct _MODULEINFO {
		LPVOID lpBaseOfDll;
		DWORD SizeOfImage;
		LPVOID EntryPoint;
	} MODULEINFO, *LPMODULEINFO;

//#include <psapi.h>
#endif

#define ASSERT _ASSERTE

// The original unhandled exception filter
static LPTOP_LEVEL_EXCEPTION_FILTER g_pfnOrigFilt = NULL ;
static char g_szPathName[_MAX_PATH];

LONG __stdcall ERCrashDumpExceptionFilter(EXCEPTION_POINTERS* pExPtrs);
LONG __stdcall ERCrashDumpExceptionFilterEx(const char* pAppName, const char* pPath, EXCEPTION_POINTERS* pExPtrs);

#if defined(_IMAGEHLP_) && defined(_X86_)

#define MAX_SYMNAME_SIZE  1024
CHAR symBuffer[sizeof(IMAGEHLP_SYMBOL)+MAX_SYMNAME_SIZE];
PIMAGEHLP_SYMBOL g_sym = (PIMAGEHLP_SYMBOL) symBuffer;
static void ERLogStackWalk(FILE *fdump, EXCEPTION_POINTERS* pExPtrs);

#endif //defined(_IMAGEHLP_) && defined(_X86_)


DWORD g_ERFlags;

#define ER_FLG_GENREPORT    0x01
#define ER_FLG_GENHEAP      0x02
#define ER_FLG_GENTHREADS   0x04


/*----------------------------------------------------------------------
   Initialize
----------------------------------------------------------------------*/
int ERinqhdl()
{
	return g_ERFlags;
}

void ERsethdl(int bSetHook)
{
	g_ERFlags = bSetHook;
}

/*----------------------------------------------------------------------
   IsNT - Detect if this is an NT installation
----------------------------------------------------------------------*/

/*----------------------------------------------------------------------
"Debugging Applications" (Microsoft Press)
Copyright (c) 1997-2000 John Robbins -- All rights reserved.
----------------------------------------------------------------------*/

BOOL __stdcall IsNT ( void )
{
	static BOOL s_bHasVersion = FALSE ; // Indicates that the version information is valid.
	static BOOL s_bIsNT = TRUE ; // Indicates NT or 95/98.
	BOOL bRet;
    OSVERSIONINFO stOSVI ;

    if ( TRUE == s_bHasVersion )
        return ( TRUE == s_bIsNT ) ;

    memset ( &stOSVI , 0, sizeof ( OSVERSIONINFO ) ) ;
    stOSVI.dwOSVersionInfoSize = sizeof ( OSVERSIONINFO ) ;

    bRet = GetVersionEx ( &stOSVI ) ;
    ASSERT ( TRUE == bRet ) ;
    if ( FALSE == bRet )
        return ( FALSE ) ;

    // Check the version and call the appropriate thing.
    if ( VER_PLATFORM_WIN32_NT == stOSVI.dwPlatformId )
        s_bIsNT = TRUE ;
    else
        s_bIsNT = FALSE ;
    s_bHasVersion = TRUE ;
    return ( TRUE == s_bIsNT ) ;
}


/*----------------------------------------------------------------------
   Version.dll Wrappers
----------------------------------------------------------------------*/
#ifdef _USE_VERSIONING_

typedef DWORD (__stdcall *FVN_GetFileVersionInfoSize)(LPCTSTR, LPDWORD );
static FVN_GetFileVersionInfoSize g_GetFileVersionInfoSize = NULL;

static DWORD __stdcall 
ERGetFileVersionInfoSize(LPCTSTR lptstrFilename, LPDWORD lpdwHandle)
{
	if (g_GetFileVersionInfoSize)
	{
		return (*g_GetFileVersionInfoSize)(lptstrFilename, lpdwHandle);
	}
	return 0;
}


typedef BOOL (__stdcall *FVN_GetFileVersionInfo)(LPCTSTR, DWORD, DWORD, LPVOID);
static FVN_GetFileVersionInfo g_GetFileVersionInfo = NULL;

static BOOL __stdcall
ERGetFileVersionInfo(LPCTSTR lptstrFilename, DWORD dwHandle, 
						  DWORD dwLen, LPVOID lpData)
{
	if (g_GetFileVersionInfo)
	{
		return (*g_GetFileVersionInfo)(lptstrFilename, dwHandle, dwLen, lpData);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_VerQueryValue)(const LPVOID, LPTSTR, LPVOID *, PUINT);
static FVN_VerQueryValue g_VerQueryValue = NULL;

static BOOL __stdcall
ERVerQueryValue(const LPVOID pBlock, LPTSTR lpSubBlock, 
			  	            LPVOID *lplpBuffer, PUINT puLen)
{
	if (g_VerQueryValue)
	{
		return (*g_VerQueryValue)(pBlock, lpSubBlock, lplpBuffer, puLen);
	}
	return 0;
}

static HMODULE g_VerMod = NULL;
static BOOL ERLoadVersionDLL()
{
	if (!g_VerMod)
	{
		g_VerMod = LoadLibrary("Version.dll");
		if (g_VerMod)
		{
			g_GetFileVersionInfoSize = (FVN_GetFileVersionInfoSize)GetProcAddress(g_VerMod, "GetFileVersionInfoSizeA");
			g_GetFileVersionInfo     = (FVN_GetFileVersionInfo)    GetProcAddress(g_VerMod, "GetFileVersionInfoA");
			g_VerQueryValue          = (FVN_VerQueryValue)         GetProcAddress(g_VerMod, "VerQueryValueA");
		}
	}
	if (g_VerMod && g_GetFileVersionInfoSize && g_GetFileVersionInfo && g_VerQueryValue)
		return TRUE;
	return FALSE;
}

#endif //_USE_VERSIONING_

/*----------------------------------------------------------------------
   imagehlp.dll Wrappers
----------------------------------------------------------------------*/
#if defined(_IMAGEHLP_) && defined(_X86_)

typedef BOOL (__stdcall *FVN_SymInitialize)(HANDLE, PSTR, BOOL);
static FVN_SymInitialize g_SymInitialize = NULL;

static BOOL __stdcall
ERSymInitialize(HANDLE hProcess, PSTR UserSearchPath, BOOL fInvadeProcess)
{
	if (g_SymInitialize)
	{
		return (*g_SymInitialize)(hProcess, UserSearchPath, fInvadeProcess);
	}
	return 0;
}


typedef BOOL (__stdcall *FVN_SymCleanup)(HANDLE);
static FVN_SymCleanup g_SymCleanup = NULL;

static BOOL __stdcall ERSymCleanup(HANDLE hProcess)
{
	if (g_SymCleanup)
	{
		return (*g_SymCleanup)(hProcess);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_StackWalk)(DWORD, HANDLE, HANDLE, LPSTACKFRAME, PVOID, 
			  PREAD_PROCESS_MEMORY_ROUTINE,  PFUNCTION_TABLE_ACCESS_ROUTINE ,
			  PGET_MODULE_BASE_ROUTINE, PTRANSLATE_ADDRESS_ROUTINE);
static FVN_StackWalk g_StackWalk = NULL;

static BOOL __stdcall ERStackWalk(
  DWORD MachineType, 
  HANDLE hProcess, 
  HANDLE hThread, 
  LPSTACKFRAME StackFrame, 
  PVOID ContextRecord, 
  PREAD_PROCESS_MEMORY_ROUTINE ReadMemoryRoutine,  
  PFUNCTION_TABLE_ACCESS_ROUTINE FunctionTableAccessRoutine,
  PGET_MODULE_BASE_ROUTINE GetModuleBaseRoutine, 
  PTRANSLATE_ADDRESS_ROUTINE TranslateAddress 
)
{
	if (g_StackWalk)
	{
		return (*g_StackWalk)(MachineType, hProcess, hThread, StackFrame, 
				ContextRecord, ReadMemoryRoutine,  FunctionTableAccessRoutine, 
				GetModuleBaseRoutine, TranslateAddress 
			);
	}
	return 0;
}

typedef LPVOID (__stdcall *FVN_SymFunctionTableAccess)(HANDLE,  DWORD);
static FVN_SymFunctionTableAccess g_SymFunctionTableAccess = NULL;

static LPVOID __stdcall 
ERSymFunctionTableAccess(HANDLE hProcess,  DWORD AddrBase)
{
	if (g_SymFunctionTableAccess)
	{
		return (*g_SymFunctionTableAccess)(hProcess,  AddrBase);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_SymGetModuleBase)(HANDLE, DWORD);
static FVN_SymGetModuleBase g_SymGetModuleBase = NULL;

static DWORD __stdcall 
ERSymGetModuleBase(HANDLE hProcess, DWORD dwAddr)
{
	if (g_SymGetModuleBase)
	{
		return (*g_SymGetModuleBase)(hProcess, dwAddr);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_SymGetModuleInfo)(HANDLE, DWORD, PIMAGEHLP_MODULE);
static FVN_SymGetModuleInfo g_SymGetModuleInfo = NULL;

static BOOL __stdcall 
ERSymGetModuleInfo(HANDLE hProcess, DWORD dwAddr, PIMAGEHLP_MODULE ModuleInfo)
{
	if (g_SymGetModuleInfo)
	{
		return (*g_SymGetModuleInfo)(hProcess, dwAddr, ModuleInfo);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_SymGetSymFromAddr)(HANDLE, DWORD, PDWORD, PIMAGEHLP_SYMBOL);
static FVN_SymGetSymFromAddr g_SymGetSymFromAddr = NULL;

static BOOL __stdcall 
ERSymGetSymFromAddr(HANDLE hProcess, DWORD Address, PDWORD Displacement, PIMAGEHLP_SYMBOL Symbol)
{
	if (g_SymGetSymFromAddr)
	{
		return (*g_SymGetSymFromAddr)(hProcess, Address, Displacement, Symbol);
	}
	return 0;
}


typedef BOOL (WINAPI *FVN_MiniDumpWriteDump)(	HANDLE hProcess,
	DWORD dwPid,
	HANDLE hFile,
	MINIDUMP_TYPE DumpType,
	CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam);
static FVN_MiniDumpWriteDump g_MiniDumpWriteDump = NULL;

static CRITICAL_SECTION g_miniCritSec;

static BOOL __stdcall 
	ERMiniDumpWriteDump(HANDLE hProcess,
	DWORD dwPid,
	HANDLE hFile,
	MINIDUMP_TYPE DumpType,
	CONST PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
	CONST PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
	CONST PMINIDUMP_CALLBACK_INFORMATION CallbackParam)
{
	if (g_MiniDumpWriteDump)
	{
		// DBGHELP.DLL is not thread safe
		BOOL result;
		EnterCriticalSection(&g_miniCritSec);
		result = (*g_MiniDumpWriteDump)(hProcess, dwPid, hFile, DumpType, ExceptionParam, UserStreamParam, CallbackParam);
		LeaveCriticalSection(&g_miniCritSec);
		return result;
	}
	return 0;
}


static HMODULE g_ImgHlpMod = NULL;
static BOOL ERLoadImageHlpDLL()
{
	if (!g_ImgHlpMod)
	{
		g_ImgHlpMod = LoadLibrary("dbghelp.dll");
		if (!g_ImgHlpMod)
			g_ImgHlpMod = LoadLibrary("Imagehlp.dll");

		if (g_ImgHlpMod)
		{
			g_SymInitialize = (FVN_SymInitialize)GetProcAddress(g_ImgHlpMod, "SymInitialize");
			g_SymCleanup = (FVN_SymCleanup)GetProcAddress(g_ImgHlpMod, "SymCleanup");
			g_StackWalk = (FVN_StackWalk)GetProcAddress(g_ImgHlpMod, "StackWalk");
			g_SymFunctionTableAccess = (FVN_SymFunctionTableAccess)GetProcAddress(g_ImgHlpMod, "SymFunctionTableAccess");
			g_SymGetModuleBase = (FVN_SymGetModuleBase)GetProcAddress(g_ImgHlpMod, "SymGetModuleBase");
			g_SymGetModuleInfo = (FVN_SymGetModuleInfo)GetProcAddress(g_ImgHlpMod, "SymGetModuleInfo");
			g_SymGetSymFromAddr = (FVN_SymGetSymFromAddr)GetProcAddress(g_ImgHlpMod, "SymGetSymFromAddr");

			InitializeCriticalSection(&g_miniCritSec);
			g_MiniDumpWriteDump = (FVN_MiniDumpWriteDump)GetProcAddress(g_ImgHlpMod, "MiniDumpWriteDump");
		}
	}
	if (g_ImgHlpMod && 
		g_SymInitialize    && g_SymCleanup && 
		g_StackWalk        && g_SymFunctionTableAccess && 
		g_SymGetModuleBase && g_SymGetModuleInfo &&
		g_SymGetSymFromAddr)
		return TRUE;
	return FALSE;
}
#endif // defined(_IMAGEHLP_) && defined(_X86_)


/*----------------------------------------------------------------------
   Version.dll Wrappers
----------------------------------------------------------------------*/
#ifdef _USE_PSAPI_

typedef BOOL (__stdcall *FVN_EnumProcessModules)(HANDLE, HMODULE *, DWORD , LPDWORD );
static FVN_EnumProcessModules g_EnumProcessModules = NULL;

static BOOL __stdcall 
EREnumProcessModules(HANDLE hProcess, HMODULE *lphModule, DWORD cb, LPDWORD lpcbNeeded)
{
	if (g_EnumProcessModules)
	{
		return (*g_EnumProcessModules)(hProcess, lphModule, cb, lpcbNeeded);
	}
	return 0;
}

typedef BOOL (__stdcall *FVN_GetModuleInformation)(HANDLE, HMODULE, LPMODULEINFO, DWORD);
static FVN_GetModuleInformation g_GetModuleInformation = NULL;

static BOOL __stdcall 
ERGetModuleInformation(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb)
{
	if (g_GetModuleInformation)
	{
		return (*g_GetModuleInformation)(hProcess, hModule, lpmodinfo, cb);
	}
	return 0;
}

static HMODULE g_PSAPIMod = NULL;
static BOOL ERLoadPSAPIDLL()
{
	if (!g_PSAPIMod)
	{
		g_PSAPIMod = LoadLibrary("psapi.dll");
		if (g_PSAPIMod)
		{
			g_EnumProcessModules = (FVN_EnumProcessModules)GetProcAddress(g_PSAPIMod, "EnumProcessModules");
			g_GetModuleInformation = (FVN_GetModuleInformation)GetProcAddress(g_PSAPIMod, "GetModuleInformation");
		}
	}
	if (g_PSAPIMod && g_EnumProcessModules && g_GetModuleInformation)
		return TRUE;
	return FALSE;
}


#endif //_USE_PSAPI_


#pragma region Crash MiniDump Handler

static BOOL ERGetImpersonationToken(HANDLE* phToken)
{
	*phToken = NULL;
	if(!OpenThreadToken(GetCurrentThread(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, TRUE, phToken))
	{
		if(GetLastError() == ERROR_NO_TOKEN)
		{
			// No impersonation token for the current thread available - go for the process token
			if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY | TOKEN_ADJUST_PRIVILEGES, phToken))
			{
				return FALSE;
			}
		}
		else
		{
			return FALSE;
		}
	}
	return TRUE;
}

static BOOL EREnablePriv(LPCTSTR pszPriv, HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
{
	BOOL bOk = FALSE;

	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	bOk = LookupPrivilegeValue( 0, pszPriv, &tp.Privileges[0].Luid);
	if(bOk)
	{
		DWORD cbOld = sizeof(*ptpOld);
		bOk = AdjustTokenPrivileges(hToken, FALSE, &tp, cbOld, ptpOld, &cbOld);
	}

	return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}

static BOOL ERRestorePriv(HANDLE hToken, TOKEN_PRIVILEGES* ptpOld)
{
	BOOL bOk = AdjustTokenPrivileges(hToken, FALSE, ptpOld, 0, 0, 0);	
	return (bOk && (ERROR_NOT_ALL_ASSIGNED != GetLastError()));
}

static BOOL ERGenerateMiniDump(CHAR *szFileName, PEXCEPTION_POINTERS pExceptionInfo)
{
	BOOL bRet = FALSE;
	DWORD dwLastError = 0;
	HANDLE hDumpFile = 0;
	MINIDUMP_EXCEPTION_INFORMATION stInfo = {0};
	TOKEN_PRIVILEGES tp;
	HANDLE hImpersonationToken = NULL;
	BOOL bPrivilegeEnabled;

	if(!ERGetImpersonationToken(&hImpersonationToken))
	{
		return FALSE;
	}

	// Create the dump file
	hDumpFile = CreateFileA(szFileName, 
		GENERIC_READ | GENERIC_WRITE, 
		FILE_SHARE_WRITE | FILE_SHARE_READ, 
		0, CREATE_ALWAYS, 0, 0);
	if(hDumpFile == INVALID_HANDLE_VALUE)
	{
		CloseHandle(hImpersonationToken);
		return FALSE;
	}

	// Write the dump
	stInfo.ThreadId = GetCurrentThreadId();
	stInfo.ExceptionPointers = pExceptionInfo;
	stInfo.ClientPointers = TRUE;

	// We need the SeDebugPrivilege to be able to run MiniDumpWriteDump
	bPrivilegeEnabled = EREnablePriv(SE_DEBUG_NAME, hImpersonationToken, &tp);

	bRet = ERMiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hDumpFile
		, (MINIDUMP_TYPE)MiniDumpWithHandleData|MiniDumpWithThreadInfo|MiniDumpWithDataSegs, &stInfo, NULL, NULL);
	if(bPrivilegeEnabled)
	{
		// Restore the privilege
		ERRestorePriv(hImpersonationToken, &tp);
	}
	
	CloseHandle(hDumpFile);
	CloseHandle(hImpersonationToken);

	return bRet;
}


/*----------------------------------------------------------------------
   Handler
----------------------------------------------------------------------*/

LONG __stdcall ERCrashDumpExceptionFilterEx(const CHAR *pAppName, const CHAR* pPath, EXCEPTION_POINTERS* pExPtrs)
{
	LONG lRet = EXCEPTION_CONTINUE_SEARCH ;
	FILE *fdump = NULL;
	HANDLE hProc = GetCurrentProcess();
	SYSTEMTIME stTime;
	CHAR pszFilename[MAX_PATH];
	size_t cbFilename = sizeof(pszFilename) / sizeof(pszFilename[0]) - 1;

	// __asm { int 3 }; // Used to debug this routine
	if (!ERLoadImageHlpDLL())
		return lRet;

	__try
	{
		g_szPathName[0] = 0;
		if (pPath && *pPath)
			GetFullPathNameA(pPath, MAX_PATH, g_szPathName, NULL);
		if (g_szPathName[strlen(g_szPathName)-1] != '\\')
			lstrcat(g_szPathName, "\\");

		// Create filename
		GetLocalTime(&stTime); 

		if (pAppName == NULL) pAppName = "App";

		// Filename is composed like this, to avoid collisions;
		// <DumpPath>\<APP>-Crash-<PID>-<TID>-YYYYMMDD-HHMMSS.dmp
		_snprintf_s(pszFilename, cbFilename, cbFilename, "%s-Crash-%ld-%ld-%04d%02d%02d-%02d%02d%02d", pAppName, GetCurrentProcessId(), GetCurrentThreadId(), stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour, stTime.wMinute, stTime.wSecond);
		lstrcat(g_szPathName, pszFilename);
		lstrcpy(g_szPathName, ".dmp");

		// Generate proper mini dump
		ERGenerateMiniDump(g_szPathName, pExPtrs);
	}	
	__except ( EXCEPTION_EXECUTE_HANDLER )
	{
		lRet = EXCEPTION_CONTINUE_SEARCH ;
	}
	if (hProc != (HANDLE)0xFFFFFFFF) CloseHandle(hProc);
	if (fdump) fclose(fdump);
	return ( lRet ) ;
}

LONG __stdcall ERCrashLogExceptionFilterEx(const CHAR *pAppName, const CHAR* pPath, EXCEPTION_POINTERS* pExPtrs)
{
    LONG lRet = EXCEPTION_CONTINUE_SEARCH ;
	FILE *fdump = NULL;
	HANDLE hProc = GetCurrentProcess();
	SYSTEMTIME stTime;
	CHAR pszFilename[MAX_PATH];
	size_t cbFilename = sizeof(pszFilename) / sizeof(pszFilename[0]) - 1;
	time_t ltime = 0;

	// __asm { int 3 }; // Used to debug this routine
	if (!ERLoadImageHlpDLL())
		return lRet;

    __try
    {
		g_szPathName[0] = 0;
		if (pPath && *pPath)
			GetFullPathNameA(pPath, MAX_PATH, g_szPathName, NULL);
		if (g_szPathName[strlen(g_szPathName)-1] != '\\')
			lstrcat(g_szPathName, "\\");

		// Create filename
		GetLocalTime(&stTime); 

		if (pAppName == NULL) pAppName = "App";

		// Filename is composed like this, to avoid collisions;
		// <DumpPath>\<APP>-Crash-<PID>-<TID>-YYYYMMDD-HHMMSS.dmp
		_snprintf_s(pszFilename, cbFilename, cbFilename, "%s-Crash-%ld-%ld-%04d%02d%02d-%02d%02d%02d", pAppName, GetCurrentProcessId(), GetCurrentThreadId(), stTime.wYear,stTime.wMonth,stTime.wDay,stTime.wHour, stTime.wMinute, stTime.wSecond);
		lstrcat(g_szPathName, pszFilename);
		lstrcat(g_szPathName, ".log");

		// Generate a text base mini dump here
		fdump = fopen( g_szPathName, "w");

		time(&ltime);
		fprintf(fdump, "Crash Report\n");
		fprintf(fdump, "     Generated on: %s\n\n", ctime( &ltime ));

		fprintf(fdump, "System Information:  \n");
		{
			char buffer[_MAX_PATH];
			int len = _MAX_PATH;
			SYSTEM_INFO si;
			HKEY hKey;
			DWORD rc, dwType;
	
			GetSystemInfo( &si );
			fprintf(fdump, "     Number of Processors: %d\n", si.dwNumberOfProcessors );

			rc = RegOpenKeyEx( HKEY_LOCAL_MACHINE, "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
							  0, KEY_QUERY_VALUE, &hKey);
			if (rc == ERROR_SUCCESS) 
			{
				len = sizeof(buffer);
				rc = RegQueryValueEx( hKey, "Identifier", 0, &dwType, (LPBYTE)buffer, &len );

				if (rc == ERROR_SUCCESS && dwType == REG_SZ)
					fprintf(fdump, "     Processor Type: %s\n", buffer);
				RegCloseKey(hKey);
			}

			rc = GetVersion();
			fprintf(fdump, "     Windows Version: %d.%d\n", LOBYTE(LOWORD(rc)), HIBYTE(LOWORD(rc)) );
		}
		fprintf(fdump, "\n");

		fprintf(fdump, "File:  \n\n");
		// TODO:  add file info

		{
			EXCEPTION_RECORD *pRecord;

			for ( pRecord = pExPtrs->ExceptionRecord; 
				  pRecord ; 
				  pRecord = pRecord->ExceptionRecord)
			{
				fprintf(fdump, "Exception Information:  \n");
				fprintf(fdump, "     Address:     0x%.8x\n", pExPtrs->ExceptionRecord->ExceptionAddress);
				fprintf(fdump, "     Code:        0x%.8x\n", pRecord->ExceptionCode);

				switch(pRecord->ExceptionCode)
				{
				case EXCEPTION_ACCESS_VIOLATION: 
					fprintf(fdump, "     Exception:   EXCEPTION_ACCESS_VIOLATION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_ACCESS_VIOLATION_STR);
					if (pRecord->NumberParameters > 0)
					{
						if (pRecord->ExceptionInformation[0])
							fprintf(fdump, "     Write to inaccessible location:  0x%.8x\n", pRecord->ExceptionInformation[1]);
						else
							fprintf(fdump, "     Read from inaccessible location: 0x%.8x\n", pRecord->ExceptionInformation[1]);
					}
					break;
				case EXCEPTION_ARRAY_BOUNDS_EXCEEDED: 
					fprintf(fdump, "     Exception:   EXCEPTION_ARRAY_BOUNDS_EXCEEDED\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_ARRAY_BOUNDS_EXCEEDED_STR);
					break;
				case EXCEPTION_BREAKPOINT: 
					fprintf(fdump, "     Exception:   EXCEPTION_BREAKPOINT\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_BREAKPOINT_STR);
					break;
				case EXCEPTION_DATATYPE_MISALIGNMENT: 
					fprintf(fdump, "     Exception:   EXCEPTION_DATATYPE_MISALIGNMENT\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_DATATYPE_MISALIGNMENT_STR);
					break;
				case EXCEPTION_FLT_DENORMAL_OPERAND: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_DENORMAL_OPERAND\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_DENORMAL_OPERAND_STR);
					break;
				case EXCEPTION_FLT_DIVIDE_BY_ZERO: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_DIVIDE_BY_ZERO\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_DIVIDE_BY_ZERO_STR);
					break;
				case EXCEPTION_FLT_INEXACT_RESULT: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_INEXACT_RESULT\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_INEXACT_RESULT_STR);
					break;
				case EXCEPTION_FLT_INVALID_OPERATION: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_INVALID_OPERATION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_INVALID_OPERATION_STR);
					break;
				case EXCEPTION_FLT_OVERFLOW: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_OVERFLOW\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_OVERFLOW_STR);
					break;
				case EXCEPTION_FLT_STACK_CHECK: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_STACK_CHECK\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_STACK_CHECK_STR);
					break;
				case EXCEPTION_FLT_UNDERFLOW: 
					fprintf(fdump, "     Exception:   EXCEPTION_FLT_UNDERFLOW\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_FLT_UNDERFLOW_STR);
					break;
				case EXCEPTION_ILLEGAL_INSTRUCTION: 
					fprintf(fdump, "     Exception:   EXCEPTION_ILLEGAL_INSTRUCTION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_ILLEGAL_INSTRUCTION_STR);
					break;
				case EXCEPTION_IN_PAGE_ERROR: 
					fprintf(fdump, "     Exception:   EXCEPTION_IN_PAGE_ERROR\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_IN_PAGE_ERROR_STR);
					break;
				case EXCEPTION_INT_DIVIDE_BY_ZERO: 
					fprintf(fdump, "     Exception:   EXCEPTION_INT_DIVIDE_BY_ZERO\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_INT_DIVIDE_BY_ZERO_STR);
					break;
				case EXCEPTION_INT_OVERFLOW: 
					fprintf(fdump, "     Exception:   EXCEPTION_INT_OVERFLOW\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_INT_OVERFLOW_STR);
					break;
				case EXCEPTION_INVALID_DISPOSITION: 
					fprintf(fdump, "     Exception:   EXCEPTION_INVALID_DISPOSITION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_INVALID_DISPOSITION_STR);
					break;
				case EXCEPTION_NONCONTINUABLE_EXCEPTION: 
					fprintf(fdump, "     Exception:   EXCEPTION_NONCONTINUABLE_EXCEPTION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_NONCONTINUABLE_EXCEPTION_STR);
					break;
				case EXCEPTION_PRIV_INSTRUCTION: 
					fprintf(fdump, "     Exception:   EXCEPTION_PRIV_INSTRUCTION\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_PRIV_INSTRUCTION_STR);
					break;
				case EXCEPTION_SINGLE_STEP: 
					fprintf(fdump, "     Exception:   EXCEPTION_SINGLE_STEP\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_SINGLE_STEP_STR);
					break;
				case EXCEPTION_STACK_OVERFLOW: 
					fprintf(fdump, "     Exception:   EXCEPTION_STACK_OVERFLOW\n");
					fprintf(fdump, "     Description: %s\n", EXCEPTION_STACK_OVERFLOW_STR);
					break;
				}
				fprintf(fdump, "\n");
			}
		}

#ifdef _X86_
		fprintf(fdump, "Registers:  \n");

		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_CONTROL)       // SS:SP, CS:IP, FLAGS, BP
		{
			fprintf(fdump, "     EIP=%.8x ESP=%.8x EBP=%.8x CS=%.4x SS=%.4x EFLAGS=%.8x \n",
				pExPtrs->ContextRecord->Eip,   pExPtrs->ContextRecord->Esp, 
				pExPtrs->ContextRecord->Ebp,   pExPtrs->ContextRecord->SegCs, 
				pExPtrs->ContextRecord->SegSs, pExPtrs->ContextRecord->EFlags);

			/* EFlags:  OV=0 UP=0 EI=1 PL=0 ZR=1 AC=0 PE=1 CY=0 */

		}
		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_INTEGER)  // AX, BX, CX, DX, SI, DI
		{
			fprintf(fdump, "     EAX=%.8x EBX=%.8x ECX=%.8x EDX=%.8x ESI=%.8x EDI=%.8x \n",
				pExPtrs->ContextRecord->Eax, pExPtrs->ContextRecord->Ebx, 
				pExPtrs->ContextRecord->Ecx, pExPtrs->ContextRecord->Edx, 
				pExPtrs->ContextRecord->Esi, pExPtrs->ContextRecord->Edi);
		}
		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_SEGMENTS) // DS, ES, FS, GS
		{
			fprintf(fdump, "     DS=%.4x ES=%.4x FS=%.4x GS=%.4x \n",
				pExPtrs->ContextRecord->SegDs, pExPtrs->ContextRecord->SegEs, 
				pExPtrs->ContextRecord->SegFs, pExPtrs->ContextRecord->SegGs);
		}
		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_FLOATING_POINT) // 387 state
		{
		}
		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_DEBUG_REGISTERS) // DB 0-3,6,7
		{
			fprintf(fdump, "     Dr0=%.8x Dr1=%.8x Dr2=%.8x Dr3=%.8x Dr6=%.8x Dr7=%.8x \n",
				pExPtrs->ContextRecord->Dr0, pExPtrs->ContextRecord->Dr1, 
				pExPtrs->ContextRecord->Dr2, pExPtrs->ContextRecord->Dr3, 
				pExPtrs->ContextRecord->Dr6, pExPtrs->ContextRecord->Dr7);
		}
		if (pExPtrs->ContextRecord->ContextFlags && CONTEXT_EXTENDED_REGISTERS) // cpu specific extensions
		{
		}
		fprintf(fdump, "\n");

#if defined(_IMAGEHLP_) && defined(_X86_)
		// Stack Walk
		ERLogStackWalk(fdump, pExPtrs);
#endif //defined(_IMAGEHLP_) && defined(_X86_)

		// Stack Dump
		{
			DWORD stack[512];
			long lesp = pExPtrs->ContextRecord->Esp;
			long i, j;

		    memset( stack, 0, sizeof(stack) );
			if (ReadProcessMemory(hProc, (LPVOID)lesp, (LPVOID)stack, sizeof(stack), &i))
			{
				fprintf(fdump, "Raw Stack:  \n");
				for( i = 0; i < (sizeof(stack)/(sizeof(DWORD)*8)); i++ ) {
					j = i * 8;
					fprintf(fdump,
						"%08x  %08x %08x %08x %08x %08x %08x %08x %08x \r\n",
						j + lesp,
						stack[ j +  0 ], stack[ j +  1 ], stack[ j +  2 ], stack[ j +  3 ],
						stack[ j +  4 ], stack[ j +  5 ], stack[ j +  6 ], stack[ j +  7 ]
						);
				}
				fprintf(fdump, "\n");
			}
		}
#endif //_X86_

#ifdef _USE_PSAPI_
		if (IsNT())
		{
			if (ERLoadPSAPIDLL())
			{
				HMODULE hMods[1024];
				DWORD cbNeeded;
				unsigned int i;
    
#ifdef _USE_VERSIONING_
				BOOL bVerOK = ERLoadVersionDLL();
#endif
				if( EREnumProcessModules(hProc, hMods, sizeof(hMods), &cbNeeded))
				{
					for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
					{
						char szModName[MAX_PATH];
						MODULEINFO mi;
						memset(&mi, 0, sizeof(MODULEINFO));

						ERGetModuleInformation(hProc, hMods[i], &mi, sizeof(MODULEINFO));

						// Get the full path to the module's file.
						if ( GetModuleFileName( hMods[i], szModName, sizeof(szModName)))
						{
							BOOL bPrintSimple = TRUE;

#ifdef _USE_VERSIONING_
							if (bVerOK)
							{
								UINT  dwBytes = 0;     
								LPVOID lpBuffer = 0; 
								LPVOID lpData;
								DWORD dwSize;
								
								dwSize = ERGetFileVersionInfoSize(szModName, 0);
								lpData = alloca(dwSize);
								ERGetFileVersionInfo(szModName, 0, dwSize, lpData);
								if (ERVerQueryValue(lpData, TEXT("\\"), &lpBuffer, &dwBytes))
								{
									VS_FIXEDFILEINFO *lpvs = (VS_FIXEDFILEINFO *)lpBuffer;
									
									fprintf(fdump, "(%.8X - %.8X) %s \t %d.%d.%d.%d \t %d.%d.%d.%d\n",
										mi.lpBaseOfDll, ((LPBYTE)(mi.lpBaseOfDll)) + mi.SizeOfImage,
										szModName,
										HIWORD(lpvs->dwFileVersionMS),    LOWORD(lpvs->dwFileVersionMS),
										HIWORD(lpvs->dwFileVersionLS),    LOWORD(lpvs->dwFileVersionLS),
										HIWORD(lpvs->dwProductVersionMS), LOWORD(lpvs->dwProductVersionMS),
										HIWORD(lpvs->dwProductVersionLS), LOWORD(lpvs->dwProductVersionLS)
										);
									bPrintSimple = FALSE;
								}
							}
#endif
							if (bPrintSimple)
							{
								fprintf(fdump, "(%.8X - %.8X) %s \t \n",
									mi.lpBaseOfDll, ((LPBYTE)(mi.lpBaseOfDll)) + mi.SizeOfImage,
									szModName);
							}
						}
					}
				}
			}
		}
#endif	
   }	
    __except ( EXCEPTION_EXECUTE_HANDLER )
    {
        lRet = EXCEPTION_CONTINUE_SEARCH ;
    }
	if (hProc != (HANDLE)0xFFFFFFFF) CloseHandle(hProc);
	if (fdump) fclose(fdump);
    return ( lRet ) ;

}

LONG __stdcall ERCrashDumpExceptionFilter (EXCEPTION_POINTERS* pExPtrs)
{
	return ERCrashDumpExceptionFilterEx(NULL, NULL, pExPtrs);
}


LONG __stdcall ERGetVersionStringA(LPCSTR szModName, LPSTR szVersion, int maxlen)
{
#ifdef _USE_VERSIONING_
	if (ERLoadVersionDLL())
	{
		UINT  dwBytes = 0;     
		LPVOID lpBuffer = 0; 
		LPVOID lpData;
		DWORD dwSize;

		szVersion[0] = 0;
		dwSize = ERGetFileVersionInfoSize(szModName, 0);
		lpData = alloca(dwSize);
		ERGetFileVersionInfo(szModName, 0, dwSize, lpData);
		if (ERVerQueryValue(lpData, TEXT("\\"), &lpBuffer, &dwBytes))
		{
			VS_FIXEDFILEINFO *lpvs = (VS_FIXEDFILEINFO *)lpBuffer;
			if (lpvs->dwFileVersionLS)
			{
				sprintf_s(szVersion, maxlen, "%d.%d.%d.%d",
					HIWORD(lpvs->dwFileVersionMS),    LOWORD(lpvs->dwFileVersionMS),
					HIWORD(lpvs->dwFileVersionLS),    LOWORD(lpvs->dwFileVersionLS)
					);
			}
			else if (lpvs->dwFileVersionMS)
			{
				sprintf_s(szVersion, maxlen, "%d.%d",
					HIWORD(lpvs->dwFileVersionMS),    LOWORD(lpvs->dwFileVersionMS)
					);
			}
			return strlen(szVersion);
		}
	}
#endif
	return 0;
}



#if defined(_IMAGEHLP_) && defined(_X86_)

BOOL __stdcall ERReadProcessMemory ( HANDLE   hProc,
                                      LPCVOID lpBaseAddress,
                                      LPVOID  lpBuffer,
                                      DWORD   nSize,
                                      LPDWORD lpNumberOfBytesRead  )
{
    return ( ReadProcessMemory ( GetCurrentProcess ( ) ,
                                 lpBaseAddress         ,
                                 lpBuffer              ,
                                 nSize                 ,
                                 lpNumberOfBytesRead    ) ) ;
}

static void ERLogStackWalk(FILE *fdump, EXCEPTION_POINTERS* pExPtrs)
{
    #define SAVE_EBP(f)        f.Reserved[0]
    #define TRAP_TSS(f)        f.Reserved[1]
    #define TRAP_EDITED(f)     f.Reserved[1]
    #define SAVE_TRAP(f)       f.Reserved[2]

    DWORD dwDisplacement = 0;
    char *szSymName;
    IMAGEHLP_MODULE mi;
    STACKFRAME stFrame;
	DWORD i;
	HANDLE hProc = (HANDLE)GetCurrentProcess();

	if (!ERLoadImageHlpDLL())
		return;

	ERSymInitialize(hProc, NULL, TRUE);

	memset(g_sym, 0, MAX_SYMNAME_SIZE + sizeof(IMAGEHLP_SYMBOL) ) ;
    g_sym->SizeOfStruct  = sizeof(IMAGEHLP_SYMBOL);
    g_sym->MaxNameLength = MAX_SYMNAME_SIZE;


    ZeroMemory( &stFrame, sizeof(stFrame) );

    stFrame.AddrPC.Offset       = pExPtrs->ContextRecord->Eip ;
    stFrame.AddrPC.Mode         = AddrModeFlat                ;
    stFrame.AddrStack.Offset    = pExPtrs->ContextRecord->Esp ;
    stFrame.AddrStack.Mode      = AddrModeFlat                ;
    stFrame.AddrFrame.Offset    = pExPtrs->ContextRecord->Ebp ;
    stFrame.AddrFrame.Mode      = AddrModeFlat                ;

    fprintf(fdump, "FramePtr ReturnAd Param#1  Param#2  Param#3  Param#4  Function Name\n");

    for (i=0; i<100; i++) 
	{
        if (!ERStackWalk( IMAGE_FILE_MACHINE_I386,
						hProc,
						GetCurrentThread(),
						&stFrame,
                        pExPtrs->ContextRecord,
                        NULL,
						ERSymFunctionTableAccess,
						ERSymGetModuleBase,
                        NULL)) 
		{
            break;
        }
        if (ERSymGetSymFromAddr(hProc, stFrame.AddrPC.Offset, &dwDisplacement, g_sym)) {
            szSymName = g_sym->Name;
        }
        else {
            szSymName = "<nosymbols>";
        }
        fprintf(fdump, "%08x %08x %08x %08x %08x %08x ",
					  stFrame.AddrFrame.Offset,
					  stFrame.AddrReturn.Offset,
					  stFrame.Params[0],
					  stFrame.Params[1],
					  stFrame.Params[2],
					  stFrame.Params[3]
                );

        if (ERSymGetModuleInfo(hProc, stFrame.AddrPC.Offset, &mi )) {
            fprintf(fdump, "%s!", mi.ModuleName );
        }

        fprintf(fdump, "%s ", szSymName );

        if (g_sym && (g_sym->Flags & SYMF_OMAP_GENERATED || g_sym->Flags & SYMF_OMAP_MODIFIED)) {
            fprintf(fdump, "[omap] " );
        }

        if (stFrame.FuncTableEntry) 
		{
            PFPO_DATA pFpoData = (PFPO_DATA)stFrame.FuncTableEntry;
            switch (pFpoData->cbFrame) 
			{
                case FRAME_FPO:
                    if (pFpoData->fHasSEH) 
					{
                        fprintf(fdump, "(FPO: [SEH])" );
                    } else 
					{
                        fprintf(fdump, " (FPO:" );
                        if (pFpoData->fUseBP) 
						{
                            fprintf(fdump, " [EBP 0x%08x]", SAVE_EBP(stFrame) );
                        }
                        fprintf(fdump, " [%d,%d,%d])",   pFpoData->cdwParams,
														 pFpoData->cdwLocals,
														 pFpoData->cbRegs);
                    }
                    break;
                case FRAME_NONFPO:
                    fprintf(fdump, "(FPO: Non-FPO [%d,%d,%d])",
                                 pFpoData->cdwParams,
                                 pFpoData->cdwLocals,
                                 pFpoData->cbRegs);
                    break;

                case FRAME_TRAP:
                case FRAME_TSS:
                default:
                    fprintf(fdump, "(UNKNOWN FPO TYPE)" );
                    break;
            }
        }

        fprintf(fdump, "\n" );
    }
    fprintf(fdump, "\n" );

	ERSymCleanup(hProc);

    return;
}
#endif //_IMAGEHLP_
