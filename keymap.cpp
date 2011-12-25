#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
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

typedef struct key_t {
	int incl; // included keys
	int excl; // excluded keys (typically to handle modifiers)
} key_t;

typedef char* STR;

// Enumeration support
typedef struct EnumLookupType {
	int value;
	const STR name;
} EnumLookupType;

static const STR EnumToString(int value, const EnumLookupType *table);
static int StringToEnum(const STR value, const EnumLookupType *table);
static int EnumToIndex(int value, const EnumLookupType *table);
static inline STR Trim(STR&p);

extern key_t CreateKeyBinding(int key);
static key_t empty_key = CreateKeyBinding(0);
extern BOOLEAN IsKeyBindingEmpty(key_t key);

static EnumLookupType gKeyTable[] = 
{
	{VK_LBUTTON, "LBUTTON"},
	{VK_RBUTTON, "RBUTTON"},
	{VK_CANCEL, "CANCEL"},
	{VK_MBUTTON, "MBUTTON"},
#if(_WIN32_WINNT >= 0x0500)
	{VK_XBUTTON1, "XBUTTON1"},
	{VK_XBUTTON2, "XBUTTON2"},
#endif /* _WIN32_WINNT >= 0x0500 */
	{VK_BACK, "BACK"},
	{VK_TAB, "TAB"},
	{VK_CLEAR, "CLEAR"},
	{VK_RETURN, "RETURN"},
	{VK_SHIFT, "SHIFT"},
	{VK_SHIFT, "SHFT"},
	{VK_CONTROL, "CONTROL"},
	{VK_CONTROL, "CTRL"},
	{VK_MENU, "ALT"},
	{VK_MENU, "MENU"},
	{VK_PAUSE, "PAUSE"},
	{VK_CAPITAL, "CAPITAL"},
	{VK_KANA, "KANA"},
	{VK_HANGEUL, "HANGEUL"},
	{VK_HANGUL, "HANGUL"},
	{VK_JUNJA, "JUNJA"},
	{VK_FINAL, "FINAL"},
	{VK_HANJA, "HANJA"},
	{VK_KANJI, "KANJI"},
	{VK_ESCAPE, "ESCAPE"},
	{VK_CONVERT, "CONVERT"},
	{VK_NONCONVERT, "NONCONVERT"},
	{VK_ACCEPT, "ACCEPT"},
	{VK_MODECHANGE, "MODECHANGE"},
	{VK_SPACE, "SPACE"},
	{VK_PRIOR, "PRIOR"},
	{VK_NEXT, "NEXT"},
	{VK_END, "END"},
	{VK_HOME, "HOME"},
	{VK_LEFT, "LEFT"},
	{VK_UP, "UP"},
	{VK_RIGHT, "RIGHT"},
	{VK_DOWN, "DOWN"},
	{VK_SELECT, "SELECT"},
	{VK_PRINT, "PRINT"},
	{VK_EXECUTE, "EXECUTE"},
	{VK_SNAPSHOT, "SNAPSHOT"},
	{VK_INSERT, "INSERT"},
	{VK_DELETE, "DELETE"},
	{VK_HELP, "HELP"},

	{ '0', "0"},
	{ '1', "1"},
	{ '2', "2"},
	{ '3', "3"},
	{ '4', "4"},
	{ '5', "5"},
	{ '6', "6"},
	{ '7', "7"},
	{ '8', "8"},
	{ '9', "9"},
	{ ':', ":"},
	{ ';', ";"},
	{ '<', "<"},
	{ '=', "="},
	{ '>', ">"},
	{ '?', "?"},
	{ 'A', "A"},
	{ 'B', "B"},
	{ 'C', "C"},
	{ 'D', "D"},
	{ 'E', "E"},
	{ 'F', "F"},
	{ 'G', "G"},
	{ 'H', "H"},
	{ 'I', "I"},
	{ 'J', "J"},
	{ 'K', "K"},
	{ 'L', "L"},
	{ 'M', "M"},
	{ 'N', "N"},
	{ 'O', "O"},
	{ 'P', "P"},
	{ 'Q', "Q"},
	{ 'R', "R"},
	{ 'S', "S"},
	{ 'T', "T"},
	{ 'U', "U"},
	{ 'V', "V"},
	{ 'W', "W"},
	{ 'X', "X"},
	{ 'Y', "Y"},
	{ 'Z', "Z"},

	{VK_LWIN, "LWIN"},
	{VK_RWIN, "RWIN"},
	{VK_APPS, "APPS"},
	{VK_SLEEP, "SLEEP"},
	{VK_NUMPAD0, "NUMPAD0"},
	{VK_NUMPAD1, "NUMPAD1"},
	{VK_NUMPAD2, "NUMPAD2"},
	{VK_NUMPAD3, "NUMPAD3"},
	{VK_NUMPAD4, "NUMPAD4"},
	{VK_NUMPAD5, "NUMPAD5"},
	{VK_NUMPAD6, "NUMPAD6"},
	{VK_NUMPAD7, "NUMPAD7"},
	{VK_NUMPAD8, "NUMPAD8"},
	{VK_NUMPAD9, "NUMPAD9"},
	{VK_MULTIPLY, "MULTIPLY"},
	{VK_ADD, "ADD"},
	{VK_SEPARATOR, "SEPARATOR"},
	{VK_SUBTRACT, "SUBTRACT"},
	{VK_DECIMAL, "DECIMAL"},
	{VK_DIVIDE, "DIVIDE"},
	{VK_F1, "F1"},
	{VK_F2, "F2"},
	{VK_F3, "F3"},
	{VK_F4, "F4"},
	{VK_F5, "F5"},
	{VK_F6, "F6"},
	{VK_F7, "F7"},
	{VK_F8, "F8"},
	{VK_F9, "F9"},
	{VK_F10, "F10"},
	{VK_F11, "F11"},
	{VK_F12, "F12"},
	{VK_F13, "F13"},
	{VK_F14, "F14"},
	{VK_F15, "F15"},
	{VK_F16, "F16"},
	{VK_F17, "F17"},
	{VK_F18, "F18"},
	{VK_F19, "F19"},
	{VK_F20, "F20"},
	{VK_F21, "F21"},
	{VK_F22, "F22"},
	{VK_F23, "F23"},
	{VK_F24, "F24"},
	{VK_NUMLOCK, "NUMLOCK"},
	{VK_SCROLL, "SCROLL"},
	{VK_OEM_NEC_EQUAL, "OEM_NEC_EQUAL"},
	{VK_OEM_FJ_JISHO, "OEM_FJ_JISHO"},
	{VK_OEM_FJ_MASSHOU, "OEM_FJ_MASSHOU"},
	{VK_OEM_FJ_TOUROKU, "OEM_FJ_TOUROKU"},
	{VK_OEM_FJ_LOYA, "OEM_FJ_LOYA"},
	{VK_OEM_FJ_ROYA, "OEM_FJ_ROYA"},
	{VK_LSHIFT, "LSHIFT"},
	{VK_LSHIFT, "LSHFT"},
	{VK_RSHIFT, "RSHIFT"},
	{VK_RSHIFT, "RSHFT"},
	{VK_LCONTROL, "LCONTROL"},
	{VK_LCONTROL, "LCTRL"},
	{VK_RCONTROL, "RCONTROL"},
	{VK_RCONTROL, "RCTRL"},
	{VK_LMENU, "LALT"},
	{VK_LMENU, "LMENU"},
	{VK_RMENU, "RALT"},
	{VK_RMENU, "RMENU"},

#if(_WIN32_WINNT >= 0x0500)
	{VK_BROWSER_BACK, "BROWSER_BACK"},
	{VK_BROWSER_FORWARD, "BROWSER_FORWARD"},
	{VK_BROWSER_REFRESH, "BROWSER_REFRESH"},
	{VK_BROWSER_STOP, "BROWSER_STOP"},
	{VK_BROWSER_SEARCH, "BROWSER_SEARCH"},
	{VK_BROWSER_FAVORITES, "BROWSER_FAVORITES"},
	{VK_BROWSER_HOME, "BROWSER_HOME"},

	{VK_VOLUME_MUTE, "VOLUME_MUTE"},
	{VK_VOLUME_DOWN, "VOLUME_DOWN"},
	{VK_VOLUME_UP, "VOLUME_UP"},
	{VK_MEDIA_NEXT_TRACK, "MEDIA_NEXT_TRACK"},
	{VK_MEDIA_PREV_TRACK, "MEDIA_PREV_TRACK"},
	{VK_MEDIA_STOP, "MEDIA_STOP"},
	{VK_MEDIA_PLAY_PAUSE, "MEDIA_PLAY_PAUSE"},
	{VK_LAUNCH_MAIL, "LAUNCH_MAIL"},
	{VK_LAUNCH_MEDIA_SELECT, "LAUNCH_MEDIA_SELECT"},
	{VK_LAUNCH_APP1, "LAUNCH_APP1"},
	{VK_LAUNCH_APP2, "LAUNCH_APP2"},

#endif /* _WIN32_WINNT >= 0x0500 */

	{VK_OEM_1, "OEM_1"},
	{VK_OEM_PLUS, "OEM_PLUS"},
	{VK_OEM_COMMA, "OEM_COMMA"},
	{VK_OEM_MINUS, "OEM_MINUS"},
	{VK_OEM_PERIOD, "OEM_PERIOD"},
	{VK_OEM_2, "OEM_2"},
	{VK_OEM_3, "OEM_3"},
	{VK_OEM_4, "OEM_4"},
	{VK_OEM_5, "OEM_5"},
	{VK_OEM_6, "OEM_6"},
	{VK_OEM_7, "OEM_7"},
	{VK_OEM_8, "OEM_8"},
	{VK_OEM_AX, "OEM_AX"},
	{VK_OEM_102, "OEM_102"},
	{VK_ICO_HELP, "ICO_HELP"},
	{VK_ICO_00, "ICO_00"},
#if(WINVER >= 0x0400)
	{VK_PROCESSKEY, "PROCESSKEY"},
#endif /* WINVER >= 0x0400 */
	{VK_ICO_CLEAR, "ICO_CLEAR"},
#if(_WIN32_WINNT >= 0x0500)
	{VK_PACKET, "PACKET"},
#endif /* _WIN32_WINNT >= 0x0500 */
	{VK_OEM_RESET, "OEM_RESET"},
	{VK_OEM_JUMP, "OEM_JUMP"},
	{VK_OEM_PA1, "OEM_PA1"},
	{VK_OEM_PA2, "OEM_PA2"},
	{VK_OEM_PA3, "OEM_PA3"},
	{VK_OEM_WSCTRL, "OEM_WSCTRL"},
	{VK_OEM_CUSEL, "OEM_CUSEL"},
	{VK_OEM_ATTN, "OEM_ATTN"},
	{VK_OEM_FINISH, "OEM_FINISH"},
	{VK_OEM_COPY, "OEM_COPY"},
	{VK_OEM_AUTO, "OEM_AUTO"},
	{VK_OEM_ENLW, "OEM_ENLW"},
	{VK_OEM_BACKTAB, "OEM_BACKTAB"},
	{VK_ATTN, "ATTN"},
	{VK_CRSEL, "CRSEL"},
	{VK_EXSEL, "EXSEL"},
	{VK_EREOF, "EREOF"},
	{VK_PLAY, "PLAY"},
	{VK_ZOOM, "ZOOM"},
	{VK_NONAME, "NONAME"},
	{VK_PA1, "PA1"},
	{VK_OEM_CLEAR, "OEM_CLEAR"},
	{0, NULL}
};



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

// Checks VK for each byte in the integer, all must be true to return TRUE.
extern BOOLEAN IsKeyBindingPressed(key_t value)
{
	if (value.incl == 0)
		return 0;

	BOOLEAN ok = 0;
	int len = sizeof(int) / sizeof(UINT8);
	// if any excluded keys are pressed exit
	{
		UINT8* ptr = (UINT8*)&value.excl;
		for (int i=0;i<len && ptr[i];++i) {
			if ( 0 != (GetKeyState( (INT32)ptr[i] ) & 0x80000000) )
				return 0;
		}
	}
	// all included keys must be pressed
	UINT8* ptr = (UINT8*)&value.incl;
	for (int i=0;i<len && ptr[i];++i) {
		if ( 0 != (GetKeyState( (INT32)ptr[i] ) & 0x80000000) )
			ok = 1;
		else
			return 0;
	}
	return ok;
}

key_t CreateKeyBinding(int key)
{
	key_t val = {key, VK_CONTROL<<16 | VK_MENU<<8 | VK_SHIFT};
	return val;
}
BOOLEAN IsKeyBindingEmpty(key_t key)
{
	return (key.incl == 0) ? 1 : 0;
}

BOOLEAN IsModifier(int mod)
{
	switch (mod)
	{
	case VK_CONTROL:
	case VK_LCONTROL:
	case VK_RCONTROL:
	case VK_MENU:
	case VK_LMENU:
	case VK_RMENU:
	case VK_SHIFT:
	case VK_LSHIFT:
	case  VK_RSHIFT:
		return true;
	}
	return false;
}

BOOLEAN HasInclusion(key_t& key, int mod)
{
	const int len = sizeof(int) / sizeof(UINT8);
	UINT8* ptr = (UINT8*)&key.incl;
	for (int i=0;i<len && ptr[i];++i) {
		if (ptr[i] == 0) break;
		if (ptr[i] == mod)
			return true;
	}
	return false;
}

static void AddInclusion(key_t& key, int mod);
static void RemoveInclusion(key_t& key, int mod);
static void AddExclusion(key_t& key, int mod);
static void RemoveExclusion(key_t& key, int mod);

static void AddInclusion(key_t& key, int mod)
{
	const int len = sizeof(int) / sizeof(UINT8);
	UINT8* ptr = (UINT8*)&key.incl;
	for (int i=0;i<len;++i) {
		if (ptr[i] == mod || ptr[i] == 0) {
			ptr[i] = mod;
			break;
		}
	}
}

static void RemoveInclusion(key_t& key, int mod)
{
	const int len = sizeof(int) / sizeof(UINT8);
	UINT8* ptr = (UINT8*)&key.incl;
	for (int i=0;i<len && ptr[i];++i) {
		if (ptr[i] == 0) break;
		if (ptr[i] == mod) {
			memmove(ptr+i, ptr+i+1, len-i-1);
			ptr[len-1] = 0;
			break;
		}
	}
}

static void AddExclusion(key_t& key, int mod)
{
	const int len = sizeof(int) / sizeof(UINT8);
	UINT8* ptr = (UINT8*)&key.excl;
	for (int i=0;i<len;++i) {
		if (ptr[i] == mod || ptr[i] == 0) {
			ptr[i] = mod;
			break;
		}
	}
}

static void RemoveExclusion(key_t& key, int mod)
{
	const int len = sizeof(int) / sizeof(UINT8);
	UINT8* ptr = (UINT8*)&key.excl;
	for (int i=0;i<len && ptr[i];++i) {
		if (ptr[i] == 0) break;
		if (ptr[i] == mod) {
			memmove(ptr+i, ptr+i+1, len-i-1);
			ptr[len-1] = 0;
			break;
		}
	}
}

void AddKeyBindingModifier(key_t& key, int mod)
{
	AddInclusion(key, mod);
	if (mod == VK_LCONTROL||mod == VK_RCONTROL)
		mod = VK_CONTROL;
	if (mod == VK_LMENU||mod == VK_RMENU)
		mod = VK_MENU;
	if (mod == VK_LSHIFT||mod == VK_RSHIFT)
		mod = VK_SHIFT;
	RemoveExclusion(key, mod);
}

void RemoveKeyBindingModifier(key_t& key, int mod)
{
	RemoveInclusion(key, mod);
}

key_t ParseKeyString(const char* value)
{
	if (value == NULL || value[0] == 0)
		return empty_key;
	char buffer[512];
	strncpy(buffer, value, _countof(buffer));
	buffer[_countof(buffer)-1] = 0;
	key_t iresult = CreateKeyBinding(0); // initialize with SHIFT+ALT+CTRL excluded
	UINT8* ptr = (UINT8*)&iresult;
	const STR sDelims = "|+";
	for ( STR key = strtok(buffer, sDelims); key != NULL; key = strtok(NULL, sDelims) )
	{
		Trim(key);
		int ichr = StringToEnum(key, gKeyTable);
		if (ichr > 0 && ichr <= 0xFF)
		{
			AddInclusion(iresult, ichr);
			RemoveExclusion(iresult, ichr);
		}
	}
	return iresult;
}

BOOLEAN GetStringForKey(key_t key, char* value, int maxlen)
{
	if (!key.incl)
		return 0;

	value[0] = 0;
	BOOLEAN ok = 0;
	UINT8* ptr = (UINT8*)&key.incl;
	const int len = sizeof(int) / sizeof(UINT8);
	for (int i=0; i<len && ptr[i]; ++i)
	{
		if (i != 0)
			strcat_s(value, maxlen, "+");
		strcat_s(value, maxlen, EnumToString(ptr[i], gKeyTable));
	}
	return ok;
}
