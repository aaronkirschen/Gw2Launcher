// version_proxy.cpp - version.dll proxy that hooks GW2's single-instance mutex
//
// Built automatically during dotnet build via mingw (see Gw2Launcher.csproj).
// Gw2Launcher extracts this DLL next to Gw2-64.exe at launch time and
// configures WINEDLLOVERRIDES so Wine loads it instead of its builtin.
//
// How it works:
//   GW2 imports version.dll (almost all Windows apps do). Windows DLL search order
//   loads ours first (same directory). We forward all real version.dll calls to the
//   system copy, and in DllMain we hook CreateMutexA/W to suppress GW2's
//   single-instance check.

#include <windows.h>
#include <stdio.h>
#include <string.h>

// ============================================================================
// Real version.dll forwarding
// ============================================================================

static HMODULE g_realVersionDll = NULL;

// Function pointer types for all version.dll exports
#define DECL_FP(name) static decltype(&name) Real_##name = NULL

// We can't use decltype for these since MinGW might not declare all of them,
// so use explicit typedefs
typedef BOOL  (WINAPI *GetFileVersionInfoA_t)(LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *GetFileVersionInfoW_t)(LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *GetFileVersionInfoSizeA_t)(LPCSTR, LPDWORD);
typedef DWORD (WINAPI *GetFileVersionInfoSizeW_t)(LPCWSTR, LPDWORD);
typedef BOOL  (WINAPI *GetFileVersionInfoExA_t)(DWORD, LPCSTR, DWORD, DWORD, LPVOID);
typedef BOOL  (WINAPI *GetFileVersionInfoExW_t)(DWORD, LPCWSTR, DWORD, DWORD, LPVOID);
typedef DWORD (WINAPI *GetFileVersionInfoSizeExA_t)(DWORD, LPCSTR, LPDWORD);
typedef DWORD (WINAPI *GetFileVersionInfoSizeExW_t)(DWORD, LPCWSTR, LPDWORD);
typedef DWORD (WINAPI *VerFindFileA_t)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT, LPSTR, PUINT);
typedef DWORD (WINAPI *VerFindFileW_t)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT, LPWSTR, PUINT);
typedef DWORD (WINAPI *VerInstallFileA_t)(DWORD, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPCSTR, LPSTR, PUINT);
typedef DWORD (WINAPI *VerInstallFileW_t)(DWORD, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPCWSTR, LPWSTR, PUINT);
typedef DWORD (WINAPI *VerLanguageNameA_t)(DWORD, LPSTR, DWORD);
typedef DWORD (WINAPI *VerLanguageNameW_t)(DWORD, LPWSTR, DWORD);
typedef BOOL  (WINAPI *VerQueryValueA_t)(LPCVOID, LPCSTR, LPVOID*, PUINT);
typedef BOOL  (WINAPI *VerQueryValueW_t)(LPCVOID, LPCWSTR, LPVOID*, PUINT);

static GetFileVersionInfoA_t       Real_GetFileVersionInfoA = NULL;
static GetFileVersionInfoW_t       Real_GetFileVersionInfoW = NULL;
static GetFileVersionInfoSizeA_t   Real_GetFileVersionInfoSizeA = NULL;
static GetFileVersionInfoSizeW_t   Real_GetFileVersionInfoSizeW = NULL;
static GetFileVersionInfoExA_t     Real_GetFileVersionInfoExA = NULL;
static GetFileVersionInfoExW_t     Real_GetFileVersionInfoExW = NULL;
static GetFileVersionInfoSizeExA_t Real_GetFileVersionInfoSizeExA = NULL;
static GetFileVersionInfoSizeExW_t Real_GetFileVersionInfoSizeExW = NULL;
static VerFindFileA_t              Real_VerFindFileA = NULL;
static VerFindFileW_t              Real_VerFindFileW = NULL;
static VerInstallFileA_t           Real_VerInstallFileA = NULL;
static VerInstallFileW_t           Real_VerInstallFileW = NULL;
static VerLanguageNameA_t          Real_VerLanguageNameA = NULL;
static VerLanguageNameW_t          Real_VerLanguageNameW = NULL;
static VerQueryValueA_t            Real_VerQueryValueA = NULL;
static VerQueryValueW_t            Real_VerQueryValueW = NULL;

static bool LoadRealVersionDll() {
    // Load the real version.dll from the system directory
    char sysDir[MAX_PATH];
    GetSystemDirectoryA(sysDir, MAX_PATH);
    char path[MAX_PATH];
    snprintf(path, MAX_PATH, "%s\\version.dll", sysDir);

    g_realVersionDll = LoadLibraryA(path);
    if (!g_realVersionDll) return false;

    #define LOAD(name) Real_##name = (name##_t)GetProcAddress(g_realVersionDll, #name)
    LOAD(GetFileVersionInfoA);
    LOAD(GetFileVersionInfoW);
    LOAD(GetFileVersionInfoSizeA);
    LOAD(GetFileVersionInfoSizeW);
    LOAD(GetFileVersionInfoExA);
    LOAD(GetFileVersionInfoExW);
    LOAD(GetFileVersionInfoSizeExA);
    LOAD(GetFileVersionInfoSizeExW);
    LOAD(VerFindFileA);
    LOAD(VerFindFileW);
    LOAD(VerInstallFileA);
    LOAD(VerInstallFileW);
    LOAD(VerLanguageNameA);
    LOAD(VerLanguageNameW);
    LOAD(VerQueryValueA);
    LOAD(VerQueryValueW);
    #undef LOAD

    return true;
}

// Forwarding exports
extern "C" {

__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoA(LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    return Real_GetFileVersionInfoA ? Real_GetFileVersionInfoA(a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoW(LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    return Real_GetFileVersionInfoW ? Real_GetFileVersionInfoW(a, b, c, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeA(LPCSTR a, LPDWORD b) {
    return Real_GetFileVersionInfoSizeA ? Real_GetFileVersionInfoSizeA(a, b) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeW(LPCWSTR a, LPDWORD b) {
    return Real_GetFileVersionInfoSizeW ? Real_GetFileVersionInfoSizeW(a, b) : 0;
}
__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExA(DWORD f, LPCSTR a, DWORD b, DWORD c, LPVOID d) {
    return Real_GetFileVersionInfoExA ? Real_GetFileVersionInfoExA(f, a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Proxy_GetFileVersionInfoExW(DWORD f, LPCWSTR a, DWORD b, DWORD c, LPVOID d) {
    return Real_GetFileVersionInfoExW ? Real_GetFileVersionInfoExW(f, a, b, c, d) : FALSE;
}
__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExA(DWORD f, LPCSTR a, LPDWORD b) {
    return Real_GetFileVersionInfoSizeExA ? Real_GetFileVersionInfoSizeExA(f, a, b) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_GetFileVersionInfoSizeExW(DWORD f, LPCWSTR a, LPDWORD b) {
    return Real_GetFileVersionInfoSizeExW ? Real_GetFileVersionInfoSizeExW(f, a, b) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerFindFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPSTR e, PUINT f, LPSTR g, PUINT h) {
    return Real_VerFindFileA ? Real_VerFindFileA(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerFindFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPWSTR e, PUINT f, LPWSTR g, PUINT h) {
    return Real_VerFindFileW ? Real_VerFindFileW(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerInstallFileA(DWORD a, LPCSTR b, LPCSTR c, LPCSTR d, LPCSTR e, LPCSTR f, LPSTR g, PUINT h) {
    return Real_VerInstallFileA ? Real_VerInstallFileA(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerInstallFileW(DWORD a, LPCWSTR b, LPCWSTR c, LPCWSTR d, LPCWSTR e, LPCWSTR f, LPWSTR g, PUINT h) {
    return Real_VerInstallFileW ? Real_VerInstallFileW(a, b, c, d, e, f, g, h) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerLanguageNameA(DWORD a, LPSTR b, DWORD c) {
    return Real_VerLanguageNameA ? Real_VerLanguageNameA(a, b, c) : 0;
}
__declspec(dllexport) DWORD WINAPI Proxy_VerLanguageNameW(DWORD a, LPWSTR b, DWORD c) {
    return Real_VerLanguageNameW ? Real_VerLanguageNameW(a, b, c) : 0;
}
__declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueA(LPCVOID a, LPCSTR b, LPVOID* c, PUINT d) {
    return Real_VerQueryValueA ? Real_VerQueryValueA(a, b, c, d) : FALSE;
}
__declspec(dllexport) BOOL WINAPI Proxy_VerQueryValueW(LPCVOID a, LPCWSTR b, LPVOID* c, PUINT d) {
    return Real_VerQueryValueW ? Real_VerQueryValueW(a, b, c, d) : FALSE;
}

} // extern "C"

// ============================================================================
// Mutex hook - the actual point of this DLL
// ============================================================================

static bool IsGW2Mutex(const char* name) {
    if (!name) return false;
    return strstr(name, "AN-Mutex-Window-Guild Wars 2") != NULL;
}

static bool IsGW2MutexW(const WCHAR* name) {
    if (!name) return false;
    return wcsstr(name, L"AN-Mutex-Window-Guild Wars 2") != NULL;
}

// IAT patching
static bool PatchIAT(HMODULE module, const char* targetDll, const char* funcName, void* hookFunc, void** origFunc) {
    if (!module) return false;

    BYTE* base = (BYTE*)module;
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

    IMAGE_DATA_DIRECTORY* importDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (!importDir->VirtualAddress) return false;

    IMAGE_IMPORT_DESCRIPTOR* imports = (IMAGE_IMPORT_DESCRIPTOR*)(base + importDir->VirtualAddress);

    for (; imports->Name; imports++) {
        const char* dllName = (const char*)(base + imports->Name);
        if (_stricmp(dllName, targetDll) != 0) continue;

        IMAGE_THUNK_DATA* origThunk = (IMAGE_THUNK_DATA*)(base + imports->OriginalFirstThunk);
        IMAGE_THUNK_DATA* iatThunk = (IMAGE_THUNK_DATA*)(base + imports->FirstThunk);

        for (; origThunk->u1.AddressOfData; origThunk++, iatThunk++) {
            if (origThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) continue;

            IMAGE_IMPORT_BY_NAME* imp = (IMAGE_IMPORT_BY_NAME*)(base + origThunk->u1.AddressOfData);
            if (strcmp(imp->Name, funcName) != 0) continue;

            if (origFunc) *origFunc = (void*)iatThunk->u1.Function;

            DWORD oldProtect;
            VirtualProtect(&iatThunk->u1.Function, sizeof(void*), PAGE_READWRITE, &oldProtect);
            iatThunk->u1.Function = (ULONG_PTR)hookFunc;
            VirtualProtect(&iatThunk->u1.Function, sizeof(void*), oldProtect, &oldProtect);
            return true;
        }
    }
    return false;
}

typedef HANDLE (WINAPI *CreateMutexA_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCSTR);
typedef HANDLE (WINAPI *CreateMutexW_t)(LPSECURITY_ATTRIBUTES, BOOL, LPCWSTR);
typedef HANDLE (WINAPI *CreateMutexExA_t)(LPSECURITY_ATTRIBUTES, LPCSTR, DWORD, DWORD);
typedef HANDLE (WINAPI *CreateMutexExW_t)(LPSECURITY_ATTRIBUTES, LPCWSTR, DWORD, DWORD);

static CreateMutexA_t   Orig_CreateMutexA   = NULL;
static CreateMutexW_t   Orig_CreateMutexW   = NULL;
static CreateMutexExA_t Orig_CreateMutexExA = NULL;
static CreateMutexExW_t Orig_CreateMutexExW = NULL;

// Instead of creating the named mutex and hiding the error, we create an
// UNNAMED mutex. GW2 gets a valid handle (won't crash), but no named mutex
// ever appears in the kernel namespace. GW2Launcher won't see it either.

static HANDLE WINAPI Hook_CreateMutexA(LPSECURITY_ATTRIBUTES attrs, BOOL owner, LPCSTR name) {
    if (IsGW2Mutex(name))
        return Orig_CreateMutexA(attrs, owner, NULL);  // unnamed
    return Orig_CreateMutexA(attrs, owner, name);
}

static HANDLE WINAPI Hook_CreateMutexW(LPSECURITY_ATTRIBUTES attrs, BOOL owner, LPCWSTR name) {
    if (IsGW2MutexW(name))
        return Orig_CreateMutexW(attrs, owner, NULL);
    return Orig_CreateMutexW(attrs, owner, name);
}

static HANDLE WINAPI Hook_CreateMutexExA(LPSECURITY_ATTRIBUTES attrs, LPCSTR name, DWORD flags, DWORD access) {
    if (IsGW2Mutex(name))
        return Orig_CreateMutexExA(attrs, NULL, flags, access);
    return Orig_CreateMutexExA(attrs, name, flags, access);
}

static HANDLE WINAPI Hook_CreateMutexExW(LPSECURITY_ATTRIBUTES attrs, LPCWSTR name, DWORD flags, DWORD access) {
    if (IsGW2MutexW(name))
        return Orig_CreateMutexExW(attrs, NULL, flags, access);
    return Orig_CreateMutexExW(attrs, name, flags, access);
}

static void InstallMutexHooks() {
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    if (!kernel32) return;

    Orig_CreateMutexA   = (CreateMutexA_t)GetProcAddress(kernel32, "CreateMutexA");
    Orig_CreateMutexW   = (CreateMutexW_t)GetProcAddress(kernel32, "CreateMutexW");
    Orig_CreateMutexExA = (CreateMutexExA_t)GetProcAddress(kernel32, "CreateMutexExA");
    Orig_CreateMutexExW = (CreateMutexExW_t)GetProcAddress(kernel32, "CreateMutexExW");

    HMODULE exe = GetModuleHandleA(NULL);
    const char* dlls[] = { "kernel32.dll", "KERNELBASE.dll",
                           "api-ms-win-core-synch-l1-1-0.dll",
                           "api-ms-win-core-synch-l1-2-0.dll", NULL };

    for (int i = 0; dlls[i]; i++) {
        PatchIAT(exe, dlls[i], "CreateMutexA",   (void*)Hook_CreateMutexA,   (void**)&Orig_CreateMutexA);
        PatchIAT(exe, dlls[i], "CreateMutexW",   (void*)Hook_CreateMutexW,   (void**)&Orig_CreateMutexW);
        PatchIAT(exe, dlls[i], "CreateMutexExA", (void*)Hook_CreateMutexExA, (void**)&Orig_CreateMutexExA);
        PatchIAT(exe, dlls[i], "CreateMutexExW", (void*)Hook_CreateMutexExW, (void**)&Orig_CreateMutexExW);
    }
}

// ============================================================================
// Entry point
// ============================================================================

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hinstDLL);
        LoadRealVersionDll();
        InstallMutexHooks();
    } else if (fdwReason == DLL_PROCESS_DETACH) {
        if (g_realVersionDll) FreeLibrary(g_realVersionDll);
    }
    return TRUE;
}
