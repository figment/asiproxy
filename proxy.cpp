/*
XSO: Xodarap's Skyrim Overhaul
Tweak, Customize, Revamp!
*/

#include "common\skyscript.h"
#include "common\obscript.h"
#include "common\types.h"
#include "common\enums.h"
#include "common\plugin.h"
#include <math.h>
#include <stdio.h>
#include <iostream>
#include <string>
#include <string.h>
#include <stdlib.h>
#include <cmath>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>

//////////////////////////////////////////////////////////////////////////

extern "C" LONG __stdcall ERGetVersionStringA(LPCSTR szModName, LPSTR szVersion, int maxlen);

typedef char* STR;

// Enumeration support
typedef struct EnumLookupType {
	int value;
	const STR name;
} EnumLookupType;

// Enumeration Support
const STR EnumToString(int value, const EnumLookupType *table) {
	for (const EnumLookupType *itr = table; itr->name != NULL; ++itr) {
		if (itr->value == value) return itr->name;
	}
	return NULL;
}

int StringToEnum(const STR value, const EnumLookupType *table) {
	if (NULL == value || 0 == *value) 
		return 0;

	for (const EnumLookupType *itr = table; itr->name != NULL; ++itr) {
		if (0 == _stricmp(value, itr->name)) 
			return itr->value;
	}
	STR end = NULL;
	return (int)strtol(value, &end, 0);
}

int StringToEnum(const STR value, const EnumLookupType *table, int defaultValue) {
	if (NULL == value || 0 == *value) 
		return defaultValue;
	for (const EnumLookupType *itr = table; itr->name != NULL; ++itr) {
		if (0 == _stricmp(value, itr->name)) 
			return itr->value;
	}
	STR end = NULL;
	int retval = (int)strtol(value, &end, 0);
	if (end == value)
		return defaultValue;
	return retval;
}

int EnumToIndex(int value, const EnumLookupType *table) {
	int i = 0;
	for (const EnumLookupType *itr = table; itr->name != NULL; ++itr, ++i) {
		if (itr->value == value) return i;
	}
	return -1;
}

static inline STR Trim(STR &p) { 
	while(isspace(*p)) *p++ = 0; 
	CHAR *e = p + strlen(p) - 1;
	while (e > p && isspace(*e)) *e-- = 0;
	return p;
}

//////////////////////////////////////////////////////////////////////////

enum LogLevel
{
	LOG_OFF,
	LOG_FATAL,
	LOG_ERROR,
	LOG_WARN,
	LOG_INFO,
	LOG_DEBUG,
	LOG_VERBOSE,
	LOG_ALL
};
EnumLookupType LogLevels[] = {
	{LOG_OFF, "OFF"},
	{LOG_FATAL, "FATAL"},
	{LOG_ERROR, "ERROR"},
	{LOG_WARN, "WARN"},
	{LOG_INFO, "INFO"},
	{LOG_DEBUG, "DEBUG"},
	{LOG_VERBOSE, "VERBOSE"},
	{LOG_ERROR, NULL}
};


static LogLevel s_verboseLevel = LOG_ERROR;
static bool reinitialize = true;
static int monitor_ini = 0;
static int monitor_period = 15;
static int last_ini_check = 0;
static __time32_t lastchecktime;
static char s_configFileName[MAX_PATH];
static char s_proxyFileName[MAX_PATH];
static char s_proxyName[MAX_PATH];
static char s_ShutdownEvent[64];
static char s_ShutdownEventDone[64];
static __time32_t s_configFileModTime;
static __time32_t s_asiFileModTime;
static HANDLE s_asiShutdownEvent = INVALID_HANDLE_VALUE;
static HANDLE s_asiShutdownEventDone = INVALID_HANDLE_VALUE;
static HMODULE s_asiFileHandle = NULL;

static int s_crashdump = 0;
static int s_breakoncrash = 0;


typedef void (*TMain)();
static TMain s_mainProc = NULL;


static int GetPluginPath(char *outpath, int pathlen)
{
	extern HMODULE g_hModule;
	outpath[0] = 0;
	GetModuleFileNameA(g_hModule, outpath, pathlen);
	char *pstr = strrchr(outpath, '\\');
	if (pstr) *++pstr = 0; 
	return strlen(outpath);
}

static void GetFileName(const char *fileName, char *outpath, int pathlen)
{
	int len = GetPluginPath(outpath, pathlen);
	strncat(outpath, fileName, pathlen - len);
	outpath[pathlen-1] = 0;
}

static LPSTR GetDefaultProxyName(LPSTR outpath, int pathlen)
{
	extern HMODULE g_hModule;
	outpath[0] = 0;
	GetModuleFileNameA(g_hModule, outpath, pathlen);

	char drive[_MAX_DRIVE], path[_MAX_PATH], fname[_MAX_FNAME], ext[_MAX_EXT];
	_splitpath_s(outpath, drive, path, fname, ext);
	strcat_s(path, "\\proxy");
	_makepath_s(outpath, pathlen, drive, path, fname, ".asi");
	char *pstr = strrchr(outpath, '.');
	if (pstr) *pstr = 0;
	lstrcat(outpath, ".asi");
	return outpath;
}

static LPSTR GetProxyConfigName(LPSTR outpath, int pathlen)
{
	extern HMODULE g_hModule;
	outpath[0] = 0;
	GetModuleFileNameA(g_hModule, outpath, pathlen);
	char *pstr = strrchr(outpath, '.');
	if (pstr) *pstr = 0;
	lstrcat(outpath, ".ini");
	return outpath;
}

static LPSTR GetConfigFileName(LPCSTR proxyFileName, LPSTR outpath, int pathlen)
{
	outpath[0] = 0;
	char drive[_MAX_DRIVE], path[_MAX_PATH], fname[_MAX_FNAME], ext[_MAX_EXT];
	_splitpath_s(proxyFileName, drive, path, fname, ext);
	_makepath_s(outpath, pathlen, drive, path, fname, ".ini");
	return outpath;
}

static LPSTR GetProxyName(LPCSTR proxyFileName, LPSTR outname, int namelen)
{
	outname[0] = 0;
	_splitpath_s(proxyFileName, NULL, 0, NULL, 0, outname, namelen, NULL, 0);
	return outname;
}

// local Ini file reader
static int IniReadInt(char *section, char *param, int def)
{
	if (s_configFileName[0] == 0)
		return def;
	return GetPrivateProfileIntA(section, param, def, s_configFileName);
}

static int IniReadString(char *section, char *param, const char *def, char *value, int maxlen)
{
	if (s_configFileName[0] == 0)
	{
		strncpy(value, def, maxlen);
		value[maxlen-1] = 0;
		return strlen(value);
	}
	return GetPrivateProfileStringA(section, param, def, value, maxlen, s_configFileName);
}

static float IniReadFloat(char *section, char *param, float def)
{
	if (s_configFileName[0] == 0)
		return def;
	char floatStr[64];
	char defStr[64];
	if (def == 0) strcpy(defStr, "0");
	else _fcvt_s(defStr, def, 3, NULL, NULL);
	int len = IniReadString(section, param, defStr, floatStr, _countof(floatStr));
	return (float)atof(floatStr);
}

static int IniReadEnum(char *section, char *param, EnumLookupType *lookupMap, int defaultValue)
{
	if (s_configFileName[0] == 0)
		return defaultValue;
	char valueStr[64];
	int len = IniReadString(section, param, EnumToString(defaultValue, lookupMap), valueStr, _countof(valueStr));
	return StringToEnum(valueStr, lookupMap, defaultValue);
}

static __time32_t GetFileModTime(const char *fileName)
{
	if (fileName == NULL || fileName[0] == 0)
		return 0;
	struct _stat32 istat;
	if ( _stat32(fileName, &istat) == 0 )
		return istat.st_mtime;
	return 0;
}

void PrintNote(LogLevel level, char *pattern, ...)
{
	if (level <= s_verboseLevel)
	{
		char text[1024];
		va_list lst;
		va_start(lst, pattern);
		vsprintf_s(text, pattern, lst);
		va_end(lst);
		OutputDebugStringA(text);
		Debug::Notification(text);
	}
}

//////////////////////////////////////////////////////////////////////////

void Initialize()
{
	char szDefaultName[MAX_PATH];
	GetProxyConfigName(s_configFileName, _countof(s_configFileName));

	GetDefaultProxyName(szDefaultName, _countof(szDefaultName));
	IniReadString("PROXY", "proxy_name", szDefaultName, s_proxyFileName, _countof(s_proxyFileName));
	GetProxyName(s_proxyFileName, s_proxyName, _countof(s_proxyName));

	s_configFileModTime = GetFileModTime(s_configFileName);

	monitor_ini = IniReadInt("PROXY", "monitor_ini", 1); 
	monitor_period = IniReadInt("PROXY", "monitor_period", 30); 
	s_verboseLevel = (LogLevel)IniReadEnum("PROXY", "verboseLevel", LogLevels, LOG_VERBOSE);
	s_crashdump = IniReadInt("PROXY", "enablecrashdump", 1); 
	s_breakoncrash = IniReadInt("PROXY", "breakoncrash", 0); 

	char szTempName[256];
	if (s_asiShutdownEvent == INVALID_HANDLE_VALUE)
	{
		sprintf_s(szTempName, "TESV.ASI.%s.SHUTDOWN", s_proxyName);
		_strupr_s(szTempName);
		s_asiShutdownEvent = CreateEvent(NULL, TRUE, FALSE, szTempName);
	}
	if (s_asiShutdownEventDone == INVALID_HANDLE_VALUE)
	{
		sprintf_s(szTempName, "TESV.ASI.%s.SHUTDOWNDONE", s_proxyName);		
		_strupr_s(szTempName);
		s_asiShutdownEventDone = CreateEvent(NULL, TRUE, FALSE, szTempName);
	}
	if (s_asiFileHandle == NULL)
	{
		ResetEvent(s_asiShutdownEvent);
		ResetEvent(s_asiShutdownEventDone);

		if (s_verboseLevel >= LOG_INFO)
		{
			if (ERGetVersionStringA(s_proxyFileName, szTempName, _countof(szTempName)) > 0)
				PrintNote(LOG_VERBOSE, "%s: Initializing version %s", s_proxyName, szTempName);
			else
				PrintNote(LOG_VERBOSE, "%s: Initializing", s_proxyName);
		}
		s_asiFileHandle = LoadLibrary(s_proxyFileName);
		s_asiFileModTime = GetFileModTime(s_proxyName);
		s_mainProc = (TMain)GetProcAddress(s_asiFileHandle, "main");
	}
	reinitialize = false;
}

static void Uninitialize()
{
	if (s_asiFileHandle != NULL)
	{
		__try
		{
			PrintNote(LOG_VERBOSE, "%s: Starting Unload", s_proxyName);
			//if (s_asiShutdownEvent != INVALID_HANDLE_VALUE)
			//	SetEvent(s_asiShutdownEvent);
			//DWORD dwResult = WaitForSingleObject(s_asiShutdownEventDone, 0);
			//if (dwResult == WAIT_TIMEOUT)
			//	PrintNote(LOG_DEBUG, "%s: Timed out waiting for shutdown to complete", s_proxyName);
			//else if (dwResult == WAIT_ABANDONED)
			//	PrintNote(LOG_DEBUG, "%s: Waiting handle during shutdown was abandoned", s_proxyName);
			//else if (dwResult == WAIT_FAILED)
			//	PrintNote(LOG_DEBUG, "%s: Waiting handle failed during shutdown", s_proxyName);

			s_mainProc = NULL;
			FreeLibrary(s_asiFileHandle);
			s_asiFileHandle = NULL;

			SetEvent(s_asiShutdownEventDone);
			PrintNote(LOG_INFO, "%s: Unloaded", s_proxyName);
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			PrintNote(LOG_ERROR, "%s: Unload failed", s_proxyName);
		}
	}
}

static void InnerLoop(  )
{
	__time32_t ltime;
	if ( monitor_ini )
	{
		int tdiff = (_time32(&ltime) - lastchecktime);
		if (tdiff > monitor_period)
		{
			lastchecktime = ltime;
			ltime = GetFileModTime(s_configFileName);
			if (ltime > s_configFileModTime)
				Initialize();
		}
	}
	if (s_mainProc != NULL)
	{
		s_mainProc();
		// main routine has exited.  Unload the plugin and wait for it to be modified
		Uninitialize();
	}
	else
	{
		ltime = GetFileModTime(s_proxyFileName);
		if (ltime > s_asiFileModTime)
			Initialize();
		Wait(100);
	}
	
}



extern "C" LONG __stdcall ERCrashLogExceptionFilterEx(const char *appname, const char *dmppath, LPEXCEPTION_POINTERS p);
extern "C" LONG __stdcall ERCrashDumpExceptionFilterEx(const char *appname, const char *dmppath, LPEXCEPTION_POINTERS p);

extern "C"
	static int FilterFunction(LPEXCEPTION_POINTERS p)
{
	if (s_crashdump != 0)
	{
		PrintNote(LOG_ERROR, "%s: Unexpected exception occurred. Dumping crash log", s_proxyName);

		char crashPath[MAX_PATH];
		GetPluginPath(crashPath, MAX_PATH);

		if (s_breakoncrash)
			__asm{ int 3 };

		ERCrashLogExceptionFilterEx(s_proxyName, crashPath, p); // text log file
		if (s_crashdump > 1)
			ERCrashDumpExceptionFilterEx(s_proxyName, crashPath, p); // dump file
		//crashdump = 0; // only do this once
	}
	else
	{
		PrintNote(LOG_ERROR, "%s: Unexpected exception occurred", s_proxyName);
	}
	return EXCEPTION_EXECUTE_HANDLER;
}
// Avoid putting the exception handlers in the tight inner loop
//  Performance drops quite a bit. After unhandled exception reload the asi
static void OuterLoop()
{
	__try
	{
		Initialize();

		while (TRUE)
		{
			InnerLoop();
			Wait(0);
		}
	}
	__except(FilterFunction(GetExceptionInformation()))
	{
		Uninitialize();
	}
}

void main()
{
	while (TRUE)
	{
		OuterLoop();
		Wait(0);
	}
	Uninitialize();
	return;
}
