// Windows platform specifica

#define WIN32_LEAN_AND_MEAN
#ifndef UNICODE
#define UNICODE
#endif
#define _WIN32_WINNT 0x0600

#include <windows.h>
#define _CRT_RAND_S
#include <stdlib.h>
#include <assert.h>
#include <string>
#include <stdexcept>
#include "platform_windows.h"

#ifndef WC_ERR_INVALID_CHARS
#define WC_ERR_INVALID_CHARS      0x00000080  // error for invalid chars
#endif

using namespace std;

static string utf8_string(wstring wstr) {
    string result;

    if (wstr.length()) {
        int size = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS,
                wstr.c_str(), -1, NULL, 0, NULL, NULL);
        assert(size);
        if (size) {
            char *buf = new char[size];
            WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, wstr.c_str(),
                    -1, buf, size, NULL, NULL);
            result = buf;
            delete[] buf;
        } else
            throw out_of_range("input wstring is not valid"
                    " while converting UTF-16 to UTF-8.");
    }

    return result;
}

static wstring utf16_string(string str) {
    wstring result;

    if (str.length()) {
        int size = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
                str.c_str(), -1, NULL, 0);
        assert(size);
        if (size) {
            wchar_t * buf = new wchar_t[size];
            MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, str.c_str(), -1,
                    buf, size);
            result = buf;
            delete[] buf;
        } else
            throw out_of_range("input string is not valid"
                    " while converting UTF-8 to UTF-16.");
    }

    return result;
}

static bool readRegistryString(
        HKEY hKey, LPCTSTR lpSubKey, LPCTSTR lpValueName, LPTSTR lpResult,
        DWORD dwSize, LPCTSTR lpDefault
    )
{
    assert(lpResult);

	HKEY theKey;
	DWORD type;
	DWORD bytesCopied = dwSize;
	HRESULT result;

	result = RegOpenKeyEx(hKey, lpSubKey, 0, KEY_READ, &theKey);
	if (result != ERROR_SUCCESS) {
		if (lpDefault) {
			wcsncpy_s(lpResult, dwSize, lpDefault, _TRUNCATE);
			return true;
		}
		else
			return false;
	}

	result = RegQueryValueEx(theKey, lpValueName, NULL, &type,
            (LPBYTE) lpResult, &bytesCopied);
    if (result != ERROR_SUCCESS || (type != REG_EXPAND_SZ && type != REG_SZ)) {
		if (lpDefault) {
			wcsncpy_s(lpResult, dwSize, lpDefault, _TRUNCATE);
			RegCloseKey(theKey);
			return true;
		}
		else {
			RegCloseKey(theKey);
			return false;
		}
	}

	RegCloseKey(theKey);
	return true;
}

static const DWORD PATH_BUF_SIZE = 32768;

static inline string managementPath(const char *file_path, const char *file_name)
{
    string path;
	static TCHAR tPath[PATH_BUF_SIZE];

    DWORD length = ExpandEnvironmentStringsW(utf16_string(file_path).c_str(),
            tPath, PATH_BUF_SIZE);
	assert(length);
    if (length == 0)
        throw bad_alloc(); // BUG: there are other errors possible beside out of memory

	CreateDirectory(tPath, NULL);
	DWORD error = GetLastError();
	assert(error == 0 || error == ERROR_ALREADY_EXISTS);

	path = utf8_string(tPath);
	path += "\\";
	path += file_name;

	return path;
}

extern "C" {

void *dlopen(const char *filename, int flag) {
	static TCHAR path[PATH_BUF_SIZE];

    assert(filename);
	assert(flag == RTLD_LAZY); // only lazy binding is implemented

    bool result = readRegistryString(HKEY_LOCAL_MACHINE,
            TEXT("SOFTWARE\\GNU\\GnuPG"), TEXT("Install Directory"), path,
            PATH_BUF_SIZE, NULL);
	assert(result);
	if (!result)
		return NULL;

    SetDllDirectory(TEXT(""));
    BOOL _result = SetDllDirectory(path);
    assert(_result != 0);
    if (_result == 0)
        return NULL;

	HMODULE module = LoadLibrary(utf16_string(filename).c_str());
    SetDllDirectory(NULL);
	if (module == NULL)
		return NULL;
	else
		return (void *) module;
}

int dlclose(void *handle) {
	if (FreeLibrary((HMODULE) handle))
		return 0;
	else
		return 1;
}

void *dlsym(void *handle, const char *symbol) {
	return (void *) (intptr_t) GetProcAddress((HMODULE) handle, symbol);
}

const char *windoze_local_db(void) {
	static string path;
	if (path.length() == 0)
        path = managementPath("%LOCALAPPDATA%\\pEp", "management.db");
    return path.c_str();
}

const char *windoze_system_db(void) {
	static string path;
	if (path.length() == 0)
		path = managementPath("%ALLUSERSPROFILE%\\pEp", "system.db");
    return path.c_str();
}

const char *gpg_conf(void)
{
    static string path;
    if (path.length() == 0)
        path = managementPath("%APPDATA%\\gnupg", "gpg.conf");
    return path.c_str();
}

long random(void)
{
    unsigned int r;
    errno_t e;

    assert(sizeof(unsigned int) == sizeof(long)); // this is Windoze

    do {
        e = rand_s(&r);
    } while (e);

    return (long) (r & ((1<<31)-1));
}

} // "C"
