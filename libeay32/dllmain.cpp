// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

#pragma comment(lib, "libcrypto")
#include "openssl\ssl.h"

__declspec(dllexport) BIO* my_BIO_new_socket(int sock, int close_flag) {
#pragma comment(linker, "/EXPORT:BIO_new_socket=" __FUNCDNAME__ ",@84")
    return BIO_new_socket(sock, close_flag);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

