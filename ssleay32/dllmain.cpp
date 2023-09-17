// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#pragma comment(lib, "libssl")
#include "openssl\ssl.h"

#ifdef _DEBUG
#pragma comment(lib, "libMinHook-x86-v141-mdd")
#else
#pragma comment(lib, "libMinHook-x86-v141-md")
#endif
#include "MinHook.h"

__declspec(dllexport) void my_SSL_CTX_free(SSL_CTX *ctx) {
#pragma comment(linker, "/EXPORT:SSL_CTX_free=" __FUNCDNAME__ ",@8")
    SSL_CTX_free(ctx);
}

__declspec(dllexport) SSL_CTX *my_SSL_CTX_new(SSL_METHOD *method) {
#pragma comment(linker, "/EXPORT:SSL_CTX_new=" __FUNCDNAME__ ",@12")
    return SSL_CTX_new(method);
}

__declspec(dllexport) void my_SSL_CTX_set_quiet_shutdown(SSL_CTX *ctx, int mode) {
#pragma comment(linker, "/EXPORT:SSL_CTX_set_quiet_shutdown=" __FUNCDNAME__ ",@145")
    SSL_CTX_set_quiet_shutdown(ctx, mode);
}

__declspec(dllexport) int my_SSL_connect(SSL *ssl) {
#pragma comment(linker, "/EXPORT:SSL_connect=" __FUNCDNAME__ ",@43")
    return SSL_connect(ssl);
}

__declspec(dllexport) void my_SSL_free(SSL *ssl) {
#pragma comment(linker, "/EXPORT:SSL_free=" __FUNCDNAME__ ",@48")
    SSL_free(ssl);
}

__declspec(dllexport) int my_SSL_get_error(const SSL *ssl, int ret) {
#pragma comment(linker, "/EXPORT:SSL_get_error=" __FUNCDNAME__ ",@58")
    return SSL_get_error(ssl, ret);
}

__declspec(dllexport) int my_SSL_library_init() {
#pragma comment(linker, "/EXPORT:SSL_library_init=" __FUNCDNAME__ ",@183")
    return SSL_library_init();
}

__declspec(dllexport) SSL *my_SSL_new(SSL_CTX *ctx) {
#pragma comment(linker, "/EXPORT:SSL_new=" __FUNCDNAME__ ",@75")
    return SSL_new(ctx);
}

__declspec(dllexport) int my_SSL_pending(const SSL* ssl) {
#pragma comment(linker, "/EXPORT:SSL_pending=" __FUNCDNAME__ ",@77")
    return SSL_pending(ssl);
}

__declspec(dllexport) int my_SSL_read(SSL* ssl, void* buf, int num) {
#pragma comment(linker, "/EXPORT:SSL_read=" __FUNCDNAME__ ",@78")
    return SSL_read(ssl, buf, num);
}

__declspec(dllexport) void my_SSL_set_bio(SSL* ssl, BIO *rbio, BIO *wbio) {
#pragma comment(linker, "/EXPORT:SSL_set_bio=" __FUNCDNAME__ ",@83")
    SSL_set_bio(ssl, rbio, wbio);
}

__declspec(dllexport) int my_SSL_shutdown(SSL* ssl) {
#pragma comment(linker, "/EXPORT:SSL_shutdown=" __FUNCDNAME__ ",@96")
    return SSL_shutdown(ssl);
}

__declspec(dllexport) int my_SSL_write(SSL* ssl, const void* buf, int num) {
#pragma comment(linker, "/EXPORT:SSL_write=" __FUNCDNAME__ ",@108")
    return SSL_write(ssl, buf, num);
}

__declspec(dllexport) SSL_METHOD *my_SSLv23_client_method(SSL* ssl) {
#pragma comment(linker, "/EXPORT:SSLv23_client_method=" __FUNCDNAME__ ",@110")
    return (SSL_METHOD *) SSLv23_client_method();
}



// Disable the GameGuard launcher
int Splash_InitGG() {
    return 0;
}
// Force GG liveness checks to be OK
int CheckNPGameMon() {
    return 1877;
}
int SendUserIDToNPGameMonW(wchar_t*) {
    return 1;
}

// Fix encodings
unsigned int WrapMultiByteToWideChar(LPWSTR dest, LPCSTR src, unsigned int destLen) {
    unsigned int result = MultiByteToWideChar(932, 0, src, -1, dest, destLen);
    if (result >= destLen)
        result = destLen - 1;
    if (result > 0)
        dest[result] = 0;
    return result;
}

unsigned int WrapWideCharToMultiByte(LPSTR dest, LPCWSTR src, unsigned int destLen) {
    unsigned int result = WideCharToMultiByte(932, 0, src, -1, dest, destLen, NULL, NULL);
    if (result >= destLen)
        result = destLen - 1;
    if (result > 0)
        dest[result] = 0;
    return result;
}

// Fix the ChrMotionSE crash
struct cCsvRead {
    wchar_t** data;
    int maxColumns, maxRows;

    wchar_t* getStr(unsigned int column, unsigned int row) {
        if (column < maxColumns && row < maxRows)
            return data[row * maxColumns + column];
        return nullptr;
    }
};

int (__fastcall *orig_cCsvRead_LoadCSV2)(cCsvRead *, void *, LPCWSTR);
int __fastcall cCsvRead_LoadCSV2(cCsvRead* self, void*, LPCWSTR path) {
    int rows = orig_cCsvRead_LoadCSV2(self, NULL, path);

	void *(*allocptr)(size_t) = ((void *(*) (size_t)) 0x7A75C6);
	void (*freeptr)(void*) = ((void (*) (void*)) 0x7A7AFB);

    //wchar_t buf[1024];
    //wsprintf(buf, L"Loaded CSV %s with %d rows", path, rows);
    //MessageBox(NULL, buf, NULL, MB_OK);

    // Fix broken ChrMotionSE tables
    if (!wcsncmp(path, L"data\\table\\ChrMotionSE", 22)) {
        for (int row = 2; row < rows; row++) {
            if (self->getStr(0, row) && self->getStr(0, row)[0] == 'x') {
                // This row is disabled

                wchar_t* pMotionID = self->getStr(1, row);
                if (pMotionID && pMotionID[0] == 0) {
                    // Empty buffer - free it so we can replace it
                    freeptr(pMotionID);
                    pMotionID = nullptr;
                }

                if (!pMotionID) {
                    // No buffer, or one that we just freed - create one with a dummy motion ID
                    pMotionID = (wchar_t*)allocptr(12);
                    wcscpy(pMotionID, L"99999");
                    self->data[row * self->maxColumns + 1] = pMotionID;
                }
            }
        }
    }

    return rows;
}

// Use a custom server
const char* Cfg_GetHostname() {
    static char hostnameBuf[256];
    strcpy(hostnameBuf, "");

    FILE* f = fopen("server.txt", "r");
    if (f != NULL) {
        int len = fread(hostnameBuf, 1, 255, f);
        if (len < 0 || len > 255)
            len = 0;

        hostnameBuf[255] = 0; // failsafe

        // Trim spacing from the end
        while (len > 0 && isspace(hostnameBuf[len]))
            len--;

        hostnameBuf[len] = 0;
        fclose(f);
    }

    if (hostnameBuf[0] == 0) {
        MessageBox(NULL, L"Create a file called 'server.txt' in the Splash Golf directory, containing the IP address or hostname of the server.", L"SplashHack", MB_OK);
        return "127.0.0.1";
    }

    return hostnameBuf;
}


bool firstRun = true;

BOOL (WINAPI *orig_GetVersionExA)(LPOSVERSIONINFOEXA);

BOOL WINAPI my_GetVersionExA(LPOSVERSIONINFOEXA lpVersionInformation) {
    if (firstRun) {
        const wchar_t* str = (const wchar_t*)0x7FD95C;
        if (!wcsncmp(str, L"SplashGolfJP", 12)) {
            firstRun = false;
            //MessageBox(NULL, L"Applying hooks", NULL, MB_OK);

            // These hooks will get applied after the game has been unpacked
            MH_CreateHook((LPVOID)0x418F00, Splash_InitGG, NULL);
            MH_CreateHook((LPVOID)0x7A0180, CheckNPGameMon, NULL);
            MH_CreateHook((LPVOID)0x7A01A0, SendUserIDToNPGameMonW, NULL);
            MH_CreateHook((LPVOID)0x418000, WrapMultiByteToWideChar, NULL);
            MH_CreateHook((LPVOID)0x418040, WrapWideCharToMultiByte, NULL);
            MH_CreateHook((LPVOID)0x564DF0, Cfg_GetHostname, NULL);
            MH_CreateHook((LPVOID)0x40E4B0, cCsvRead_LoadCSV2, (LPVOID *) &orig_cCsvRead_LoadCSV2);
            MH_EnableHook(MH_ALL_HOOKS);
        }
    }
    return orig_GetVersionExA(lpVersionInformation);
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        MH_Initialize();
		MH_CreateHook(GetVersionExA, my_GetVersionExA, (LPVOID *) &orig_GetVersionExA);
		MH_EnableHook(GetVersionExA);
        break;
        
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

