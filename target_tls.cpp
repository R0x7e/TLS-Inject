#include <iostream>
#include <windows.h>

void NTAPI MyTlsCallback(PVOID DllHandle, DWORD Reason, PVOID Reserved) {
    if (Reason == DLL_PROCESS_ATTACH) {
        printf("Original TLS Callback executed!\n");
    }
}

// For GCC/MinGW
#ifdef __GNUC__
PIMAGE_TLS_CALLBACK pTlsCallback __attribute__((section(".CRT$XLB"))) = MyTlsCallback;
#else
#pragma section(".CRT$XLB", read)
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK pTlsCallback = MyTlsCallback;
#endif

int main() {
    std::cout << "Target Main function executed (With TLS)!" << std::endl;
    return 0;
}
